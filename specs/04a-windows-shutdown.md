# 04a Windows Shutdown and Upgrade Guard

Spec version: 1.0.9 | Governs: Windows daemon and desktop shutdown, credential-write admission,
installed-image stop proof
## Scope

This contract covers Windows shutdown through `csq daemon stop`, desktop Quit, `csq-upgrade-guard`,
and the per-user NSIS installation admission protocol. A successful stop census describes the
processes it observed. Installation admission additionally requires the retained installer lease
described below.

## Credential work and generation ownership

`update::upgrade_guard::drain::TaskCustody` owns the actual subsystem and admitted work handles. A
`TaskObservation` is an observer: dropping or timing it out never cancels the underlying task. A
stable wake relay notifies both task observers and the custody drain. Join failures retain only
fixed cause tokens, without panic payloads or raw credential-bearing error chains.

A Windows desktop supervisor generation owns its current session custody outside the supervisor
loop. Normal return and loop panic both drain that registry before `Completion::record_joined`. A
failed completion is distinct from an unfinished join. Restart cannot use an old generation's
completion as proof for a new generation. `QuitBridge` owns its cancellation-aware event listener
and joins the listener thread before completion is published.

The daemon closes IPC admission on shutdown. Router handlers belong to `HandlerWork`, independently
of transport connections. A stalled named-pipe connection has a two-second graceful transport
deadline; expiry drops the transport while its admitted router handler remains owned and joined.
Credential-writing handler work has no transport deadline.

## Observer budgets

`derived_shutdown_budget` adds the exported credential-lock, Node-child wait, post-commit lock,
publication allowance and durable-record-lock budgets. `derived_shutdown_deadline` converts that
duration to one absolute observer deadline. The installed-image guard adds a five-second
exit-observation margin to the same duration through `shutdown_observer_budget`. Each role starts
its observation window at its first signal; a later arrival in that role does not reset it.
Sequential daemon, desktop and CLI phases do not consume one another's window. Ordinary daemon stop
reports the full policy budget even when preflight has consumed part of the retained-handle wait.
Overflow or invalid limits refuse the operation.

This is an availability policy, not a bound on credential persistence or a promise that every
shutdown completes in that interval. Filesystem work, keychain operations, private pipe draining and
scheduling can outlast it. Expiry refuses the observer's operation; it never authorizes killing a
process, cancelling admitted work, detaching custody, or declaring completion.

## Desktop Quit and sign-in

The Windows desktop intercepts exit requests until credential-write admission, the selected
supervisor generation and the quit listener have completed their required joins. Closing a window
retains the ordinary hide behavior and does not become a Quit request.

`desktop::credential_writes` re-exports the canonical `desktop::login_custody` gate; it owns no
separate admission state. That gate serializes closing admission with acquiring write permits and
registered child custody. A permit follows the actual worker through mint, persistence and
publication, including renderer cancellation. A drain requires both admitted work and registered
children to finish. Reopening after refusal retains existing custody; a stale drain cannot reopen a
newer close or the identity owned by a live update lease.

Claude, Codex and native vendor sign-in subprocesses can persist credentials before returning an
exit status. They expose no reliable pre-commit boundary. Their complete worker therefore retains
custody across browser interaction and persistence. An already registered sign-in makes Quit refuse
immediately, before cancelling the supervisor or beginning a write drain. Unreadable sign-in state also refuses, logs fixed
`credential_write_gate_poisoned`, and shows a credential-state-unavailable title without a finish/retry promise. The window stays shown
and the tray remains usable. The known-active sign-in refusal title branch logs `desktop_signin_active`, identifies the provider/account, and asks the user to finish or close the browser and retry.
The supervisor has not been cancelled at this admission-refusal boundary. The refused intent retires, so another Quit after
the child finishes can proceed normally. Dropping the last sign-in permit notifies presentation
cleanup outside the registry lock.

Gemini's browser callback wait is separately registered for cancellation. Closing admission cancels
an interaction that has not acquired its mint permit. Acquisition and cancellation eligibility
change under the same gate mutex. Once admitted, token exchange and persistence finish without Quit
cancellation. Worker cleanup, including releasing its account login lock, remains counted until the
worker ends. Reopening admission cannot revive a cancelled earlier browser interaction.

A supervisor or listener observation deadline retires the exit intent and retains visible refusal
while the exact generation and admitted work join. The UI identifies daemon unavailability and
waiting for recovery; it does not advertise an immediate retry or a no-op cancellation. While a user
exit intent is still pending, Cancel Quit clears only that intent and retains all work custody. A
refused intent has nothing left to cancel; a fresh Quit or upgrade can retry after recovery
completes. A later join never silently converts the refused request into exit. Recovery cannot
reopen admission or restart the daemon before the exact generation joins. Registered-sign-in refusal
clears when its final registration ends; a writer-drain deadline stays visibly refused until an
explicit retry. Early recovery rejects the pending installation callback before reopening or
restoring the running title and tray.

## Bound and legacy stop channels

Bound stop events carry PID and process birth time, use the login-session namespace and owner-only
object security, and refuse pre-created objects. Senders retain the process object and verify event
ownership before signalling. The daemon stop event is distinct from desktop application Quit.

A verified exited or non-csq PID-file target yields `StalePidFile`. A live target with an
unavailable stop channel yields typed `ShutdownUnavailable`; unverified endpoint facts yield typed
`ShutdownUnverified` or the actual kernel error. Successful signalling is not reported as failed
solely because closing its query handle subsequently fails.

For an older daemon that only exposes the per-user legacy event, the stop path first retains the
PID-file target's process handle, birth time, same-user ownership, session and exact selected
installed image. Ordinary daemon stop requires real daemon argv and a sole live same-user daemon
census before the legacy signal. A non-daemon PID-file target is stale; an ambiguous or unreadable
census refuses without a signal. Only then may it signal the owner-checked legacy event and wait for
that retained handle to exit within the shared observation budget. A non-csq target grants no signal
authority. A missing or unverified endpoint or an unobserved exit refuses the upgrade with the
specific cause. No fallback terminates a process.

The legacy event may belong to another same-user csq daemon: upgrades treat all such daemon hosts as
stop targets. The signal requests a graceful quit, and a same-user non-csq event squatter gains no
additional authority from receiving it. Event presence alone never substitutes for verifying the
PID-file target and its retained process identity.

## Installed-image stop proof

The helper accepts one to sixteen explicit existing installed image paths; callers include every
installed executable, including renamed desktop images. Basenames only filter candidates negatively.
Exact native image and owner verification establish target identity; argv classification establishes
role. An exited-before-open process is absent from that snapshot. Other open or identity failures
refuse, with their cause named. PID zero is not opened.

Before the first signal, discovery checks every live target's graceful-stop channel. An unsignalable
CLI or another unsupported live target refuses with zero quit signals. No role is force-stopped. A
supported legacy daemon requires the verified PID-file target described above. Complete snapshot
enumeration retains the known-different-basename negative filter even when a legacy event is
present: an inaccessible protected SYSTEM image with a known unrelated name supplies no csq identity
evidence. Unknown, non-Unicode, same-family and explicit installed-image names still require strict
native verification. Legacy event presence alone never authorizes a signal.

Every selected target remains bound to its retained handle and birth time. Success requires that
every retained target was counted exited before the current pass's final snapshot and that the
snapshot contains no new live target. An exit first observed after a snapshot requires another
census. Deadline expiry, incomplete enumeration or unverifiable identity refuses. A later refusal
distinguishes an already verified stopped daemon from a requested stop that may still be draining,
and names `csq daemon start` for recovery. The backend retains the caller's actual installed-image
set for subsequent request verification. The basename filter does not establish identity for a
renamed executable omitted from that set.

## Windows restart and update installation

All desktop targets revoke raw updater check, download/install and process restart/exit IPC.
`UpdateBanner` uses only `desktop::commands::update_custody::{install_update_with_custody,
restart_with_custody}`. Both validate the requesting main window and acquire the canonical
`login_custody::UpdateLease`. Installation retains the enterprise/community channel refusal.
The renderer supplies intent and a progress channel, never an installer path, URL, approval token
or generation identity.

The backend waits for admitted writers and registered children before update effects. On Windows,
it checks the configured updater and verifies downloaded bytes, then transfers that existing lease
into `desktop::windows_upgrade::request_install`. The Windows owner must not close ordinary Quit
admission a second time: ordinary Quit uses `close_for_quit_tag`, while installation retains the
original lease identity through the selected supervisor generation and quit-listener joins.

Only the Windows owner constructs `ApprovedInstall`. The actual blocking installation worker owns
the lease and authorizes canonical exit immediately before invoking the one-shot callback. Both
Windows and canonical custody exit proofs must permit the handoff. Returning or unwinding revokes
exit approval; a returning installer, including unexpected success, cannot certify replacement.
Unknown completion keeps admission closed with the canonical sticky unverified outcome. A known
no-install result may release the lease; pre-install refusal may reopen only after required exact
generation/listener recovery. Dropping a renderer observer never cancels admitted Rust work.

Refusal, cancellation and observer expiry discard the pending callback; a late recovery cannot
install it. Installation does not restart the supervisor during the owned operation. Per-operation
updater setup suppresses premature application cleanup so a failed launch retains the recovery UI.
The normal successful Windows updater handoff exits inside the installer call.

Windows signature failures use the fixed `update_signature_invalid` tag and provide no Retry;
other builder, check, download and installer outcomes retain fixed diagnostics without raw error
payloads. Progress uses a caller-specific channel and the canonical waiting/started/progress/finished
contract. Stale or detached observers cannot update a later UI operation, and invalid byte counts do
not produce determinate progress. Non-Windows installation and manual restart retain the same
canonical custody IPC and lease checks; they do not restore raw plugin authority.

## Installer admission and lease lifetime

Windows desktop bundle builds produce NSIS only, installing for `currentUser` with an unelevated
token. MSI bundle publication is omitted for v2.21.2; the existing WiX-to-NSIS migration dispatch
retains the same pre-uninstall refusal gate. Elevated or foreign-principal operation refuses.

A token-native profile lookup selects `.csq\installer-admission-v2\namespace.secret` beneath the user's profile; environment variables do
not select it. Both profile and `.csq` require current-user, SYSTEM or Administrators ownership and a present non-NULL DACL; effective foreign
ALLOWs for DELETE, DELETE_CHILD, ADD_SUBDIRECTORY, FILE_WRITE_DATA, FILE_WRITE_ATTRIBUTES, WRITE_DAC or WRITE_OWNER, including generic mappings, refuse. Inherit-only and CREATOR OWNER
grants do not grant effective foreign access. The dedicated directory and secret still require protected user-SID-only security. First publication
writes exactly 16 random bytes to a private CREATE_NEW temporary file, flushes it, then publishes without replacement, retrying bounded sharing contention. A concurrent loser removes only its own temporary file and securely rereads the winner before checking the creation deadline; a stray
temporary file does not block publication. Every read rechecks owner, protected DACL, integrity label, regular/nonreparse identity, link count and exact size. Unsafe paths, directory security or secret facts refuse with fixed `namespace_*` tags. Pins start at the profile
directory, not its ancestors; sharing contention has a distinct transient diagnostic.
Admission requires NTFS; other filesystems return typed `namespace_filesystem_unsupported` refusal.
The retained parent and child use 128-bit file IDs and 64-bit volume serials. Each namespace directory
and the temporary secret must have a kernel-reported parent ID and leaf matching its retained parent;
zero, sentinel or nonrepresentable parent IDs refuse. Secret containment is checked before writing,
and its sole-link check remains required. Unsupported identity queries refuse.
Both `.csq` and `installer-admission-v2` open or create relative to retained parents, without pathname fallback.
Retained-directory reparses and native child-operation errors 1920/1921 return the typed
`namespace_directory_reparsed` cause. These checks do not fence every create/rename race or guarantee
continued access after mutation. Refused publication removes its owned temporary file through its
handle, leaving no temporary file; cleanup failure adds `namespace_secret_cleanup` context while
preserving the typed refusal. A final secret published before the directory change is kept.
The installer explains both existing links and changed safety folders, and gives a plain unsupported-drive refusal.

Existing unsafe or incomplete final state is not repaired, overwritten or deleted. Exit and uninstall retain the secret; no rotation may orphan live transaction names.

Object names contain domain-separated HMAC-SHA256 values, never raw secret bytes: the message is `csq-v2|<kind>|<SID>`, with distinct lease,
capability and pipe labels, truncated to 16 digest bytes in lowercase hex. Lease and PID/birth capability objects use the session Local
namespace. The pipe has its distinct derived name and same-principal/session verification, but pipe names are machine-wide: a foreign
account in another session can observe and replay a name after the legitimate endpoint closes. Local object names can also be replayed where
visible. Foreign or ambiguous ownership refuses, causing availability denial; HMAC derivation does not guarantee non-deniable availability.

`csq-installer-admission` acquires the owner-only lease before draining targets. Participating startup in that session refuses any
owner-checked existing lease object, including unlocked, signalled or abandoned states; only absence admits, and ownership/read errors
refuse. New installer admission refuses an existing object rather than acquiring an abandoned lease. A Local lease does not fence a csq
started in another session of the same user after the holder's last recheck. That late start can overlap installation; the protocol supplies
no cross-session admission fence.
Owner Jack Hong accepted these two stated limits on 2026-10-22 (receipt `OWNER-ACCEPTANCE-A-B.md`), conditional on native probes finding no broader impact.
Credential exposure, fail-open beyond the stated gap, or profile-owner refusal for standard accounts returns to the owner; native qualification remains required.
Revisit with the cross-session rendezvous issue; calendar backstop: the next release cut after v2.21.2.

Before readiness, the helper duplicates a READ_CONTROL-only, noninheritable lease reference into the
retained installer process, verified by PID, birth and SID. That reference survives controller or
helper failure and remains through copy and rollback handling. The helper watches installer lifetime
and closes its own references on installer exit. Startup in that session admits only after every reference closes,
including probes. Terminating both helper and installer, including during copying, leaves no
orphaned transaction lease after remaining probe references close. Helper-only termination while the
installer lives retains the fence.

Application entry checks the lease before self-test and retains a distinct PID/birth capability for
its lifetime. Supervision checks each loop and before PID-file acquisition; admission refusal warns,
waits through cancellable backoff and retries instead of permanently ending supervision. Desktop
generation restart checks before changing generation state. Before any graceful request, the helper
preflights each target's installation capability and bound stop endpoint, and rechecks capability at
signal time. A shutdown-only legacy endpoint is insufficient. Live legacy, foreign-user or
unverifiable targets refuse before signals. Admitted credential work retains actual joins; observer
expiry never permits force-kill or replacement success.

Root and image strings are untrusted hints. Existing components reject reparses; the nearest
existing directory and selected executables must belong to the actual user. Planned images remain
beneath that root. Initial targets remain retained and later hints are unioned, preserving renamed
targets after registry removal. Fresh censuses inspect each actual image without changing the
retained installed-image selection. Vanished or already-signalled processes are absent. Before old
uninstall, any live process with the main binary basename refuses, including CLI roles and other
installation paths, because legacy uninstallers can terminate by name. Root revalidation and
cooperative probes do not serialize every legacy start or create an OS-enforced path-mutation fence.

## NSIS helper custody, replacement and launch

The installer as delivered is the trust root. It carries no Authenticode signature. In-app updater
minisign verifies the package bytes, including the compiled helper hash, before the plugin
materializes a temporary installer and launches by path. Verification of memory does not eliminate
the plugin's later materialize-to-launch replacement interval. Manual delivery retains trust in the
supplied installer.

Before helper execution, NSIS checks staged bytes against the compiled hash. Its owner-checked stage
chain is pinned only from the token profile down through LOCALAPPDATA and fixed descendants,
rejecting redirected or reparse components. Unsupported non-drive-root profile volumes refuse rather
than skipping profile ownership checks; pin sharing contention uses `staging_sharing_violation`.
Each child is checked before creating the next. The stage leaf
contains only the helper executable; extra entries refuse. CREATE_NEW extraction skips an existing
leaf and then independently verifies it. A truncated or wrong-hash regular helper inside the pinned
owned directory is removed, extracted once more with CREATE_NEW and rehashed; a second failure
refuses. Both installer and uninstaller embed their helper, and stale SHA stages are cleaned without
recursive traversal or deleting the current stage.

The verified helper leaf is held for read with no write/delete sharing. Helper-staging ancestry
directories request FILE_TRAVERSE|SYNCHRONIZE in addition to security/attribute access and share
read/write without delete: they block rename/removal, not new sibling creation. The standalone
uninstaller's target-root DELETE-share exception remains separate so it can remove the installation
root. Handles are noninheritable and retained through controller execution or installer exit after
timeout. The MSVC helper static-import loader flag restricts dependent DLL search to System32. The
helper self-pins its executable ancestry and verifies installer birth/liveness. Direct launches
retain the raw volume-GUID path; only explicit intended stdio endpoints enter inherited-handle
lists.

`begin` binds the direct installer parent and acquires admission before old uninstall or copy.
`recheck` authenticates that retained installer and checks before both old-uninstaller executions,
preinstall, main executable extraction and renamed-image deletion. `uninstall-admit` either proves
the actual retained ancestor chain to reuse the parent transaction or acquires a standalone lease.
Parent reuse transfers no installer reference and closes no parent handle.

Readiness requires exit code zero and exact `CSQ_INSTALL_V1 READY 0xHHHHHHHH`, or standalone
`CSQ_INSTALL_V1 UNINSTALL_READY 0xHHHHHHHH`. The eight uppercase hex digits identify the actual
installer-local lease handle. NSIS validates framing, nonzero/non-pseudo value, local handle
validity, noninheritability and absence of protection from close. Before admission, the same
SHA-pinned helper independently returns the expected native lease name through `lease-object-name`;
the READY reference must have native type Mutant and exactly that name. Parent reuse returns exactly
`CSQ_INSTALL_V1 UNINSTALL_REUSE_OK`, without a token. Malformed output, unexpected status, timeout
or refusal prevents launch and uses fixed diagnostics; argv and raw paths supply no handle or stop
authority.

The installer clears the copy error flag before the stock file/resource sequence and refuses on a
copy error while retaining the lease. Required settings/association writes have isolated error checks; GetSize supplies only an informational estimate.
Desktop-shortcut errors refuse before commit; after commit they report a nonfatal detail and continue. Only successful completion precedes `commit-release` with both
`--transaction-committed` and `--rollback-closed`. The authenticated helper must successfully
release the mutex and drop its own reference before returning exact `CSQ_INSTALL_V1 RELEASED` with
exit code zero. NSIS then closes its stored installer reference, requires CloseHandle success and
clears the stored value. Only after these steps does the common normal launch wrapper run,
preserving `/R`, raw `/ARGS` and interactive finish-page launch behavior. Launch requested is
distinct from observed application startup.

Failed, cancelled, rollback and no-launch paths launch nothing and retain any installer-local lease reference until installer exit. A
release exchange or CloseHandle failure refuses launch. No-launch completion shows a message only in interactive mode. Silent and passive
(`/P` without `/R`) no-launch completion records an owner-checked, flushed outcome log beside the SHA stage directories, returns success and
shows no modal box. Random suffixes retry name collisions; stale outcome logs are pruned with ownership/path checks. A record failure is
explicit. Commit flags record installer flow completion; replacement remains stock NSIS. Startup admission is cooperative within its
session; direct legacy installer/uninstaller bytes retain their own behavior.

Interruption during main payload copy can leave the installed csq binary truncated and unable to
start until the installer is rerun. Recovery is to rerun the installer to completion, which installs
the working new csq. Admission-fence release after process death permits that recovery; it does not
restore overwritten binary bytes. The installation path provides no backup/restore or atomic payload
replacement guarantee.

The admission gate runs synchronously in NSIS page/section callbacks; a long drain can leave the GUI
unresponsive until the observer completes. Silent refusal deliberately uses the documented default
response, never proceeds after refusal, and launches nothing. No installation output directory is
created before its gate.

## References
- [04 Daemon Architecture](04-csq-daemon-architecture.md): daemon hosts and subsystem responsibilities.
- [01 Credential Architecture](01-cc-credential-architecture.md): vendor credential persistence.
- [02 Handle-Dir Model](02-csq-handle-dir-model.md): account and terminal identity.

## Revisions
- 2026-10-24 — 1.0.9 — Require NTFS and full-width volume/file identity for namespace containment, extend parent checks to directories, and clarify installer refusals for existing links and unsupported drives.
- 2026-10-24 — 1.0.8 — Rooted namespace-directory creation in retained parent handles, rejected foreign reparse-setting grants, and clarified typed refusal propagation, temporary cleanup and preservation of a previously published secret.
- 2026-10-24 — 1.0.7 — Specify typed refusal when the retained namespace directory becomes a reparse point, with no pathname fallback or newly created secret/temp residue from the refused operation, and an installer explanation.
- 2026-10-24 — 1.0.6 — Reconciled installer continuation with canonical login/update custody and all-platform IPC revocation; corrected relative synchronous access, final secret publication, and native fixture preconditions. Native acceptance remains a separate execution boundary.
- 2026-10-22 — 1.0.5 — Validated parent owner/ACL grants; corrected estimate/shortcut and sign-in diagnostics; recorded conditional owner acceptance of the two stated cross-session limits.
- 2026-10-22 — 1.0.4 — Corrected dedicated secret publication, profile-down pins and passive outcomes; stated machine-wide pipe replay and same-user cross-session admission limits.
- 2026-10-22 — 1.0.3 — Corrected session-derived namespace security, replay refusal, helper repair and loader custody, copy-error and no-launch reporting, shipped NSIS-only wiring, and deadline recovery controls.

- 2026-10-22 — 1.0.2 — Added per-user NSIS admission, installer-owned lease references, helper custody, authenticated release before normal launch, and interrupted-copy recovery by installer rerun.
- 2026-10-22 — 1.0.1 — Added per-role observer windows, ordinary-stop sole-daemon legacy authority, immediate sign-in refusal, retired deadline exit intents and Rust-gated Windows update installation. These are source contracts; native Windows installation and UI behavior require their own execution evidence.
