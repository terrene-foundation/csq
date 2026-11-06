//! Telegram owner-command authority, distinct from message-origin attestation.
//!
//! The daemon's validated intake may mint this closed command envelope. The
//! relay checks its MAC, immutable process bindings, fresh relay generation,
//! lifetime and replay high-water before creating an opaque token. This token
//! conveys provenance only: it grants neither Idle nor permission to write a
//! byte. The ordinary per-CLI table and Enter gates still apply.
//!
//! `new` and `reenable_local` generate a fresh random generation. Consequently
//! old envelopes fail their generation check after a restart or local re-enable;
//! replay high-water itself is in-memory, not a durable replay database.

use super::{state::SlashCmd, types::SessionIdentity};
use hmac::{Hmac, Mac};
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use std::fmt;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use zeroize::Zeroizing;

const DOMAIN: &[u8] = b"csq.relay.owner-telegram.command.v1\0";
const VERSION: u8 = 1;
/// Owner-decided command lifetime, checked against the authenticated issue time.
pub(crate) const MAX_COMMAND_LIFETIME_MS: u64 = 120_000;

/// The wire has no text, argv, environment, grant, enable or arbitrary command.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum OwnerCommand {
    Clear,
    Compact,
}

impl OwnerCommand {
    fn tag(self) -> u8 {
        match self {
            Self::Clear => 1,
            Self::Compact => 2,
        }
    }

    fn slash(self) -> SlashCmd {
        match self {
            Self::Clear => SlashCmd::Clear,
            Self::Compact => SlashCmd::Compact,
        }
    }
}

/// Every interpretation-relevant field is included in the fixed-width MAC.
/// `issued_at_ms` is the original Telegram command date, not a renewed mint time.
#[derive(Clone, Copy, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct OwnerCommandFields {
    pub(crate) version: u8,
    pub(crate) target_pid: u32,
    pub(crate) target_started_at: u64,
    pub(crate) relay_pid: u32,
    pub(crate) relay_started_at: u64,
    pub(crate) generation: [u8; 32],
    pub(crate) update_id: u64,
    pub(crate) issued_at_ms: u64,
    pub(crate) expires_at_ms: u64,
    pub(crate) command: OwnerCommand,
}

/// An untrusted claim. Deserialization cannot produce an authorized token.
#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct WireOwnerCommand {
    fields: OwnerCommandFields,
    mac: String,
}

impl fmt::Debug for WireOwnerCommand {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("WireOwnerCommand(<unverified>)")
    }
}

/// Closed diagnostic codes; neither key nor wire bytes occur in an error.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum OwnerAuthError {
    Invalid,
    Expired,
    Disabled,
    Replay,
    ClockUnavailable,
    GenerationUnavailable,
}

/// Private fields and no Deserialize/Clone implementation keep token creation
/// at `OwnerVerifier::verify` and delivery consumption at `authorize_delivery`.
pub(crate) struct AuthorizedOwnerCommand {
    fields: OwnerCommandFields,
    instance: Arc<AtomicBool>,
    deadline: Instant,
    clock: WallClock,
    time_high_water: Arc<Mutex<Option<u64>>>,
}

impl fmt::Debug for AuthorizedOwnerCommand {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("AuthorizedOwnerCommand(<provenance-only>)")
    }
}

impl AuthorizedOwnerCommand {
    /// Metadata only. A writer must consume `authorize_delivery` and still
    /// evaluate the state machine's table, audit and Enter preconditions.
    pub(in crate::relay) fn command(&self) -> SlashCmd {
        self.fields.command.slash()
    }

    pub(in crate::relay) fn target(&self) -> SessionIdentity {
        SessionIdentity {
            pid: self.fields.target_pid,
            started_at: self.fields.target_started_at,
        }
    }

    pub(in crate::relay) fn relay(&self) -> SessionIdentity {
        SessionIdentity {
            pid: self.fields.relay_pid,
            started_at: self.fields.relay_started_at,
        }
    }

    pub(in crate::relay) const fn deadline(&self) -> Instant {
        self.deadline
    }
}

type WallClock = Arc<dyn Fn() -> Option<u64> + Send + Sync>;

fn wall_clock_ms() -> Option<u64> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .ok()?
        .as_millis()
        .try_into()
        .ok()
}

fn observe_time(high_water: &Mutex<Option<u64>>, now: Option<u64>) -> Result<u64, OwnerAuthError> {
    let now = now.ok_or(OwnerAuthError::ClockUnavailable)?;
    let mut last = high_water
        .lock()
        .map_err(|_| OwnerAuthError::ClockUnavailable)?;
    if last.is_some_and(|last| now < last) {
        return Err(OwnerAuthError::ClockUnavailable);
    }
    *last = Some(now);
    Ok(now)
}

/// Consumed provenance with live revocation. It owns no verifier borrow, so an
/// operator can disable the verifier between command bytes and submission.
pub(crate) struct DeliveryAuthority {
    token: AuthorizedOwnerCommand,
    failure: Mutex<Option<OwnerAuthError>>,
}

impl fmt::Debug for DeliveryAuthority {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("DeliveryAuthority(<revocable>)")
    }
}

impl DeliveryAuthority {
    pub(in crate::relay) fn command(&self) -> SlashCmd {
        self.token.command()
    }
    pub(in crate::relay) const fn deadline(&self) -> Instant {
        self.token.deadline()
    }
    pub(in crate::relay) fn target(&self) -> SessionIdentity {
        self.token.target()
    }
    pub(in crate::relay) fn relay(&self) -> SessionIdentity {
        self.token.relay()
    }

    /// Re-read wall time even when monotonic time stopped during suspend. Any
    /// observed loss is terminal for this handle; it cannot recover on retry.
    pub(in crate::relay) fn check(&self) -> Result<(), OwnerAuthError> {
        let mut failure = self
            .failure
            .lock()
            .map_err(|_| OwnerAuthError::ClockUnavailable)?;
        if let Some(error) = *failure {
            return Err(error);
        }
        let result = (|| {
            if self.token.instance.load(Ordering::Acquire) {
                return Err(OwnerAuthError::Disabled);
            }
            let now = observe_time(&self.token.time_high_water, (self.token.clock)())?;
            if now < self.token.fields.issued_at_ms {
                return Err(OwnerAuthError::ClockUnavailable);
            }
            if now >= self.token.fields.expires_at_ms || Instant::now() >= self.token.deadline {
                return Err(OwnerAuthError::Expired);
            }
            Ok(())
        })();
        if let Err(error) = result {
            *failure = Some(error);
        }
        result
    }
}

/// Owned by one relay control loop. Key custody is supplied by the trusted
/// daemon/launch integration, never by a request or an environment override.
pub(crate) struct OwnerVerifier {
    key: Zeroizing<[u8; 32]>,
    target: SessionIdentity,
    relay: SessionIdentity,
    generation: [u8; 32],
    instance: Arc<AtomicBool>,
    enabled: bool,
    update_high_water: Option<u64>,
    time_high_water: Arc<Mutex<Option<u64>>>,
    clock: WallClock,
}

impl OwnerVerifier {
    /// Take the already-protected key by ownership; constructor validation and
    /// generation failures drop the same zeroizing wrapper.
    pub(crate) fn new(
        key: Zeroizing<[u8; 32]>,
        target: SessionIdentity,
        relay: SessionIdentity,
    ) -> Result<Self, OwnerAuthError> {
        if !valid_identity(target) || !valid_identity(relay) || target.pid == relay.pid {
            return Err(OwnerAuthError::Invalid);
        }
        Ok(Self {
            key,
            target,
            relay,
            generation: fresh_generation(None)?,
            instance: Arc::new(AtomicBool::new(false)),
            enabled: true,
            update_high_water: None,
            time_high_water: Arc::new(Mutex::new(None)),
            clock: Arc::new(wall_clock_ms),
        })
    }

    pub(crate) fn generation(&self) -> [u8; 32] {
        self.generation
    }

    pub(crate) fn target(&self) -> SessionIdentity {
        self.target
    }

    pub(crate) fn relay(&self) -> SessionIdentity {
        self.relay
    }

    pub(crate) fn verify(
        &mut self,
        wire: WireOwnerCommand,
        now_ms: Option<u64>,
    ) -> Result<AuthorizedOwnerCommand, OwnerAuthError> {
        self.check_enabled()?;
        let now = self.read_time(now_ms)?;
        if wire.mac.len() != 64
            || !wire
                .mac
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
        {
            return Err(OwnerAuthError::Invalid);
        }
        let supplied = hex::decode(&wire.mac).map_err(|_| OwnerAuthError::Invalid)?;
        command_mac(&self.key, &wire.fields)?
            .verify_slice(&supplied)
            .map_err(|_| OwnerAuthError::Invalid)?;
        self.check_fields(&wire.fields, now)?;
        if self
            .update_high_water
            .is_some_and(|last| wire.fields.update_id <= last)
        {
            return Err(OwnerAuthError::Replay);
        }
        let deadline = Instant::now()
            .checked_add(Duration::from_millis(wire.fields.expires_at_ms - now))
            .ok_or(OwnerAuthError::ClockUnavailable)?;
        // Only a fully authenticated, live claim can advance the replay cursor.
        self.update_high_water = Some(wire.fields.update_id);
        Ok(AuthorizedOwnerCommand {
            fields: wire.fields,
            instance: Arc::clone(&self.instance),
            deadline,
            clock: Arc::clone(&self.clock),
            time_high_water: Arc::clone(&self.time_high_water),
        })
    }

    pub(crate) fn revalidate(
        &mut self,
        token: &AuthorizedOwnerCommand,
        now_ms: Option<u64>,
    ) -> Result<(), OwnerAuthError> {
        self.check_enabled()?;
        let now = self.read_time(now_ms)?;
        if !Arc::ptr_eq(&token.instance, &self.instance) {
            return Err(OwnerAuthError::Invalid);
        }
        self.check_fields(&token.fields, now)
    }

    /// Consumes provenance without renewing its verification-time deadline.
    /// The returned authority still grants neither Idle nor an Enter bypass.
    pub(crate) fn authorize_delivery(
        &mut self,
        token: AuthorizedOwnerCommand,
        now_ms: Option<u64>,
    ) -> Result<DeliveryAuthority, OwnerAuthError> {
        self.revalidate(&token, now_ms)?;
        Ok(DeliveryAuthority {
            token,
            failure: Mutex::new(None),
        })
    }

    pub(crate) fn disable(&mut self) {
        self.enabled = false;
        self.instance.store(true, Ordering::Release);
    }

    /// Only trusted local integration may call this; no control wire operation
    /// reaches it. Failure leaves the verifier disabled and old tokens revoked.
    #[cfg_attr(
        not(test),
        expect(dead_code, reason = "local enable integration follows shard 1")
    )]
    pub(crate) fn reenable_local(
        &mut self,
        key: Zeroizing<[u8; 32]>,
    ) -> Result<(), OwnerAuthError> {
        self.disable();
        let generation = fresh_generation(Some(self.generation))?;
        self.key = key;
        self.generation = generation;
        self.instance = Arc::new(AtomicBool::new(false));
        self.enabled = true;
        Ok(())
    }

    fn check_enabled(&self) -> Result<(), OwnerAuthError> {
        if self.enabled {
            Ok(())
        } else {
            Err(OwnerAuthError::Disabled)
        }
    }

    fn read_time(&mut self, now_ms: Option<u64>) -> Result<u64, OwnerAuthError> {
        observe_time(&self.time_high_water, now_ms)
    }

    #[cfg(test)]
    pub(in crate::relay) fn set_clock_for_test(&mut self, clock: WallClock) {
        assert!(
            self.update_high_water.is_none(),
            "clock fixture must precede verification"
        );
        self.clock = clock;
    }

    fn check_fields(&self, f: &OwnerCommandFields, now: u64) -> Result<(), OwnerAuthError> {
        if f.version != VERSION
            || f.target_pid != self.target.pid
            || f.target_started_at != self.target.started_at
            || f.relay_pid != self.relay.pid
            || f.relay_started_at != self.relay.started_at
            || f.generation != self.generation
            || f.update_id == 0
        {
            return Err(OwnerAuthError::Invalid);
        }
        if f.issued_at_ms > now
            || f.expires_at_ms <= f.issued_at_ms
            || f.expires_at_ms - f.issued_at_ms > MAX_COMMAND_LIFETIME_MS
        {
            return Err(OwnerAuthError::Invalid);
        }
        if now >= f.expires_at_ms {
            return Err(OwnerAuthError::Expired);
        }
        Ok(())
    }
}

impl Drop for OwnerVerifier {
    fn drop(&mut self) {
        self.disable();
    }
}

fn valid_identity(id: SessionIdentity) -> bool {
    id.pid > 0 && id.pid <= i32::MAX as u32 && id.started_at > 0
}

fn fresh_generation(previous: Option<[u8; 32]>) -> Result<[u8; 32], OwnerAuthError> {
    let mut generation = [0u8; 32];
    getrandom::getrandom(&mut generation).map_err(|_| OwnerAuthError::GenerationUnavailable)?;
    if generation == [0u8; 32] || previous == Some(generation) {
        return Err(OwnerAuthError::GenerationUnavailable);
    }
    Ok(generation)
}

/// Only csq-core's trusted daemon intake may mint. The numeric user/chat pin,
/// fresh-unedited-update validation and named-session resolution precede this
/// call in that integration; a message-origin MAC is not a command envelope.
#[cfg_attr(
    not(test),
    expect(dead_code, reason = "daemon command mint integration follows shard 1")
)]
pub(crate) fn mint(
    fields: OwnerCommandFields,
    key: &[u8; 32],
) -> Result<WireOwnerCommand, OwnerAuthError> {
    let mac = hex::encode(command_mac(key, &fields)?.finalize().into_bytes());
    Ok(WireOwnerCommand { fields, mac })
}

fn command_mac(key: &[u8; 32], f: &OwnerCommandFields) -> Result<Hmac<Sha256>, OwnerAuthError> {
    let mut mac = Hmac::<Sha256>::new_from_slice(key).map_err(|_| OwnerAuthError::Invalid)?;
    mac.update(DOMAIN);
    mac.update(&[f.version]);
    mac.update(&f.target_pid.to_be_bytes());
    mac.update(&f.target_started_at.to_be_bytes());
    mac.update(&f.relay_pid.to_be_bytes());
    mac.update(&f.relay_started_at.to_be_bytes());
    mac.update(&f.generation);
    mac.update(&f.update_id.to_be_bytes());
    mac.update(&f.issued_at_ms.to_be_bytes());
    mac.update(&f.expires_at_ms.to_be_bytes());
    mac.update(&[f.command.tag()]);
    Ok(mac)
}

#[cfg(test)]
mod tests {
    use super::*;

    const KEY: [u8; 32] = [0x5a; 32];
    // All fixture time is injected; no wall-clock access or calendar expiry.
    const NOW: u64 = 4_102_444_800_000;

    fn verifier() -> OwnerVerifier {
        OwnerVerifier {
            key: Zeroizing::new(KEY),
            target: SessionIdentity {
                pid: 11,
                started_at: 22,
            },
            relay: SessionIdentity {
                pid: 33,
                started_at: 44,
            },
            generation: [0x77; 32],
            instance: Arc::new(AtomicBool::new(false)),
            enabled: true,
            update_high_water: None,
            time_high_water: Arc::new(Mutex::new(None)),
            clock: Arc::new(|| Some(NOW)),
        }
    }

    fn fields(v: &OwnerVerifier) -> OwnerCommandFields {
        OwnerCommandFields {
            version: 1,
            target_pid: v.target().pid,
            target_started_at: v.target().started_at,
            relay_pid: v.relay().pid,
            relay_started_at: v.relay().started_at,
            generation: v.generation(),
            update_id: 7,
            issued_at_ms: NOW,
            expires_at_ms: NOW + MAX_COMMAND_LIFETIME_MS,
            command: OwnerCommand::Clear,
        }
    }

    fn verified(v: &mut OwnerVerifier) -> AuthorizedOwnerCommand {
        v.verify(mint(fields(v), &KEY).unwrap(), Some(NOW)).unwrap()
    }

    #[test]
    fn owner_command_launch_uses_fresh_generation_and_valid_process_bindings() {
        let target = SessionIdentity {
            pid: 11,
            started_at: 22,
        };
        let relay = SessionIdentity {
            pid: 33,
            started_at: 44,
        };
        let first = OwnerVerifier::new(Zeroizing::new(KEY), target, relay).unwrap();
        let second = OwnerVerifier::new(Zeroizing::new(KEY), target, relay).unwrap();
        assert_ne!(first.generation(), [0; 32]);
        assert_ne!(first.generation(), second.generation());
        for invalid in [
            SessionIdentity {
                pid: 0,
                started_at: 22,
            },
            SessionIdentity {
                pid: u32::MAX,
                started_at: 22,
            },
            SessionIdentity {
                pid: 11,
                started_at: 0,
            },
            relay,
        ] {
            assert!(matches!(
                OwnerVerifier::new(Zeroizing::new(KEY), invalid, relay),
                Err(OwnerAuthError::Invalid)
            ));
        }
    }

    #[test]
    fn owner_commands_round_trip_and_consume_a_verified_token() {
        for (command, slash) in [
            (OwnerCommand::Clear, SlashCmd::Clear),
            (OwnerCommand::Compact, SlashCmd::Compact),
        ] {
            let mut v = verifier();
            let f = OwnerCommandFields {
                command,
                ..fields(&v)
            };
            let raw = serde_json::to_vec(&mint(f, &KEY).unwrap()).unwrap();
            let wire = serde_json::from_slice(&raw).unwrap();
            let token = v.verify(wire, Some(NOW)).unwrap();
            assert_eq!(
                v.authorize_delivery(token, Some(NOW + 1))
                    .map(|a| a.command()),
                Ok(slash)
            );
        }
    }

    #[test]
    fn owner_command_mac_authenticates_every_interpreted_field() {
        let v = verifier();
        let original = fields(&v);
        let mut changed = Vec::new();
        macro_rules! alter {
            ($field:ident, $value:expr) => {{
                let mut f = original;
                f.$field = $value;
                changed.push(f);
            }};
        }
        alter!(version, 2);
        alter!(target_pid, 12);
        alter!(target_started_at, 23);
        alter!(relay_pid, 34);
        alter!(relay_started_at, 45);
        alter!(generation, [0x78; 32]);
        alter!(update_id, 8);
        alter!(issued_at_ms, NOW - 1);
        alter!(expires_at_ms, NOW + 1);
        alter!(command, OwnerCommand::Compact);
        for f in changed {
            let mut v = verifier();
            let mut wire = mint(original, &KEY).unwrap();
            wire.fields = f;
            assert_eq!(
                v.verify(wire, Some(NOW)).unwrap_err(),
                OwnerAuthError::Invalid
            );
        }
    }

    #[test]
    fn owner_command_rejects_wrong_keys_and_noncanonical_or_message_macs() {
        for mac in [
            String::new(),
            "00".repeat(31),
            "G".repeat(64),
            "AA".repeat(32),
        ] {
            let mut v = verifier();
            let wire = WireOwnerCommand {
                fields: fields(&v),
                mac,
            };
            assert_eq!(
                v.verify(wire, Some(NOW)).unwrap_err(),
                OwnerAuthError::Invalid
            );
        }
        let mut v = verifier();
        assert_eq!(
            v.verify(mint(fields(&v), &[0x5b; 32]).unwrap(), Some(NOW))
                .unwrap_err(),
            OwnerAuthError::Invalid
        );
        let mut v = verifier();
        let f = fields(&v);
        let mut old = Hmac::<Sha256>::new_from_slice(&KEY).unwrap();
        old.update(b"csq.bridge.owner-attestation.v1");
        old.update(&f.target_pid.to_be_bytes());
        old.update(&f.target_started_at.to_be_bytes());
        old.update(&f.update_id.to_be_bytes());
        use sha2::Digest;
        old.update(&Sha256::digest(b"/clear"));
        let wire = WireOwnerCommand {
            fields: f,
            mac: hex::encode(old.finalize().into_bytes()),
        };
        assert_eq!(
            v.verify(wire, Some(NOW)).unwrap_err(),
            OwnerAuthError::Invalid
        );
    }

    #[test]
    fn owner_command_rejects_authenticated_wrong_bindings_and_bad_lifetimes() {
        let v = verifier();
        let original = fields(&v);
        let mut changed = Vec::new();
        macro_rules! alter {
            ($field:ident, $value:expr) => {{
                let mut f = original;
                f.$field = $value;
                changed.push(f);
            }};
        }
        alter!(version, 2);
        alter!(target_pid, 12);
        alter!(target_started_at, 23);
        alter!(relay_pid, 34);
        alter!(relay_started_at, 45);
        alter!(generation, [0x78; 32]);
        alter!(update_id, 0);
        alter!(issued_at_ms, NOW + 1);
        alter!(expires_at_ms, NOW);
        alter!(expires_at_ms, NOW + MAX_COMMAND_LIFETIME_MS + 1);
        for f in changed {
            let mut v = verifier();
            assert_eq!(
                v.verify(mint(f, &KEY).unwrap(), Some(NOW)).unwrap_err(),
                OwnerAuthError::Invalid
            );
        }
        let mut v = verifier();
        assert_eq!(
            v.verify(
                mint(fields(&v), &KEY).unwrap(),
                Some(NOW + MAX_COMMAND_LIFETIME_MS)
            )
            .unwrap_err(),
            OwnerAuthError::Expired
        );
    }

    #[test]
    fn owner_command_replay_high_water_advances_only_after_full_validation() {
        let mut v = verifier();
        let original = fields(&v);
        let hostile = OwnerCommandFields {
            update_id: u64::MAX,
            ..original
        };
        assert_eq!(
            v.verify(mint(hostile, &[0x5b; 32]).unwrap(), Some(NOW))
                .unwrap_err(),
            OwnerAuthError::Invalid
        );
        let _token = verified(&mut v);
        assert_eq!(
            v.verify(mint(original, &KEY).unwrap(), Some(NOW))
                .unwrap_err(),
            OwnerAuthError::Replay
        );
        let older = OwnerCommandFields {
            update_id: 6,
            ..original
        };
        assert_eq!(
            v.verify(mint(older, &KEY).unwrap(), Some(NOW)).unwrap_err(),
            OwnerAuthError::Replay
        );
        let newer = OwnerCommandFields {
            update_id: 8,
            ..original
        };
        assert!(v.verify(mint(newer, &KEY).unwrap(), Some(NOW)).is_ok());
    }

    #[test]
    fn owner_command_delivery_rechecks_expiry_disable_and_verifier_instance() {
        let mut v = verifier();
        let token = verified(&mut v);
        assert_eq!(
            v.authorize_delivery(token, Some(NOW + MAX_COMMAND_LIFETIME_MS))
                .map(|a| a.command()),
            Err(OwnerAuthError::Expired)
        );
        let mut v = verifier();
        let token = verified(&mut v);
        v.disable();
        assert_eq!(
            v.authorize_delivery(token, Some(NOW)).map(|a| a.command()),
            Err(OwnerAuthError::Disabled)
        );
        assert_eq!(
            v.verify(mint(fields(&v), &KEY).unwrap(), Some(NOW))
                .unwrap_err(),
            OwnerAuthError::Disabled
        );
        let mut first = verifier();
        let token = verified(&mut first);
        let mut second = verifier();
        assert_eq!(
            second
                .authorize_delivery(token, Some(NOW))
                .map(|a| a.command()),
            Err(OwnerAuthError::Invalid)
        );
    }

    #[test]
    fn owner_command_clock_unknown_or_rollback_never_resurrects_authority() {
        let mut v = verifier();
        assert_eq!(
            v.verify(mint(fields(&v), &KEY).unwrap(), None).unwrap_err(),
            OwnerAuthError::ClockUnavailable
        );
        let token = verified(&mut v);
        v.revalidate(&token, Some(NOW + 50)).unwrap();
        assert_eq!(
            v.revalidate(&token, Some(NOW + 49)),
            Err(OwnerAuthError::ClockUnavailable)
        );
        assert_eq!(
            v.revalidate(&token, None),
            Err(OwnerAuthError::ClockUnavailable)
        );
        assert_eq!(
            v.revalidate(&token, Some(NOW + MAX_COMMAND_LIFETIME_MS)),
            Err(OwnerAuthError::Expired)
        );
        assert_eq!(
            v.authorize_delivery(token, Some(NOW + 1))
                .map(|a| a.command()),
            Err(OwnerAuthError::ClockUnavailable)
        );
    }

    #[test]
    fn owner_command_local_reenable_rotates_generation_and_revokes_queued_tokens() {
        let mut v = verifier();
        let old_fields = fields(&v);
        let token = verified(&mut v);
        v.reenable_local(Zeroizing::new(KEY)).unwrap();
        assert_ne!(v.generation(), old_fields.generation);
        assert_eq!(
            v.authorize_delivery(token, Some(NOW)).map(|a| a.command()),
            Err(OwnerAuthError::Invalid)
        );
        assert_eq!(
            v.verify(mint(old_fields, &KEY).unwrap(), Some(NOW))
                .unwrap_err(),
            OwnerAuthError::Invalid
        );
        assert_eq!(
            v.verify(mint(fields(&v), &KEY).unwrap(), Some(NOW))
                .unwrap_err(),
            OwnerAuthError::Replay
        );
        let next = OwnerCommandFields {
            update_id: 8,
            ..fields(&v)
        };
        assert!(v.verify(mint(next, &KEY).unwrap(), Some(NOW)).is_ok());
    }

    #[test]
    fn owner_delivery_authority_disable_reenable_and_drop_revoke_existing_handles() {
        let mut v = verifier();
        let token = verified(&mut v);
        let deadline = token.deadline();
        assert_eq!(token.target(), v.target());
        assert_eq!(token.relay(), v.relay());
        let delivery = v.authorize_delivery(token, Some(NOW)).unwrap();
        assert_eq!(
            delivery.deadline(),
            deadline,
            "R1_H2: authorization must not renew verification-time deadline"
        );
        assert_eq!(delivery.target(), v.target());
        assert_eq!(delivery.relay(), v.relay());
        assert_eq!(delivery.check(), Ok(()));
        v.disable();
        assert_eq!(
            delivery.check(),
            Err(OwnerAuthError::Disabled),
            "R1_H2: disable between body and CR must revoke the held authority"
        );
        v.reenable_local(Zeroizing::new(KEY)).unwrap();
        assert_eq!(
            delivery.check(),
            Err(OwnerAuthError::Disabled),
            "R1_H2: fresh generation cannot resurrect an old handle"
        );
        let next = OwnerCommandFields {
            update_id: 8,
            ..fields(&v)
        };
        let token = v.verify(mint(next, &KEY).unwrap(), Some(NOW)).unwrap();
        let replacement = v.authorize_delivery(token, Some(NOW)).unwrap();
        assert_eq!(replacement.check(), Ok(()));
        drop(v);
        assert_eq!(
            replacement.check(),
            Err(OwnerAuthError::Disabled),
            "R1_H2: verifier drop must revoke outstanding authority"
        );
    }

    #[test]
    fn owner_delivery_authority_checks_wall_expiry_rollback_and_unknown_on_every_call() {
        use std::sync::atomic::AtomicU64;
        for (changed, expected) in [
            (NOW + MAX_COMMAND_LIFETIME_MS, OwnerAuthError::Expired),
            (NOW - 1, OwnerAuthError::ClockUnavailable),
            (0, OwnerAuthError::ClockUnavailable),
        ] {
            let mut v = verifier();
            let now = Arc::new(AtomicU64::new(NOW));
            let reader = Arc::clone(&now);
            v.set_clock_for_test(Arc::new(move || match reader.load(Ordering::Acquire) {
                0 => None,
                value => Some(value),
            }));
            let token = verified(&mut v);
            let delivery = v.authorize_delivery(token, Some(NOW)).unwrap();
            assert_eq!(delivery.check(), Ok(()));
            assert!(Instant::now() < delivery.deadline());
            now.store(changed, Ordering::Release);
            assert_eq!(
                delivery.check(),
                Err(expected),
                "R1_LI: wall loss must revoke even while monotonic deadline is live"
            );
            now.store(NOW, Ordering::Release);
            assert_eq!(
                delivery.check(),
                Err(expected),
                "R1_H2: observed owner-authority loss must be terminal"
            );
        }
    }

    #[test]
    fn owner_delivery_authority_preserves_deadline_across_authorization_delay() {
        let mut v = verifier();
        let token = verified(&mut v);
        let deadline = token.deadline();
        let delivery = v.authorize_delivery(token, Some(NOW + 1000)).unwrap();
        assert_eq!(
            delivery.deadline(),
            deadline,
            "R1_H2: audit delay must not remint the owner lifetime"
        );
    }

    #[test]
    fn owner_command_wire_has_no_enable_text_or_unknown_field_escape() {
        let v = verifier();
        let raw = serde_json::to_value(mint(fields(&v), &KEY).unwrap()).unwrap();
        for command in ["enable", "/clear", "clear now", "text"] {
            let mut bad = raw.clone();
            bad["fields"]["command"] = command.into();
            assert!(serde_json::from_value::<WireOwnerCommand>(bad).is_err());
        }
        for name in ["origin", "role", "text", "enable", "argv", "key"] {
            let mut bad = raw.clone();
            bad[name] = true.into();
            assert!(serde_json::from_value::<WireOwnerCommand>(bad).is_err());
            let mut bad = raw.clone();
            bad["fields"][name] = true.into();
            assert!(serde_json::from_value::<WireOwnerCommand>(bad).is_err());
        }
    }

    #[test]
    fn owner_command_debug_excludes_keys_and_bearer_macs() {
        let mut v = verifier();
        let wire = mint(fields(&v), &KEY).unwrap();
        let mac = wire.mac.clone();
        assert!(!format!("{wire:?}").contains(&mac));
        let token = verified(&mut v);
        assert!(!format!("{token:?}").contains(&mac));
    }
}
