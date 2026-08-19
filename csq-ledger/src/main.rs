//! csq-ledger server entrypoint (M10).
//!
//! Wires: config → append-only store → checkpoint signing key → optional
//! anchor target → axum server + anchor-cadence background task.

use std::sync::Arc;

use clap::Parser;
use tracing::{error, info, warn};

use csq_ledger::anchor::{self, AnchorTarget};
use csq_ledger::config::Config;
use csq_ledger::server::{
    build_authority_router, build_read_router, submit::build_checkpoint, AppState,
};
use csq_ledger::signing::{ServerSigningKey, AUTO_KEY_WARNING, SIGNING_KEY_PATH_ENV};
use csq_ledger::storage::LedgerStore;

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .init();

    if let Err(code) = run().await {
        std::process::exit(code);
    }
}

/// The fallible body. Returns `Err(exit_code)` on a fatal startup error.
async fn run() -> Result<(), i32> {
    let config = Config::parse();

    // ── Load or generate the checkpoint signing key (decision 2) ─────────────
    let env_override = std::env::var(SIGNING_KEY_PATH_ENV).ok();
    let signing_key =
        match ServerSigningKey::load_or_generate(&config.data_dir, env_override.as_deref()) {
            Ok(k) => k,
            Err(e) => {
                error!(error = %e, "failed to load or generate signing key");
                return Err(74);
            }
        };
    info!(
        key_id = signing_key.key_id(),
        "checkpoint signing key ready"
    );
    if signing_key.warn_active() {
        // Persistent first-boot WARN (also surfaced on GET /v1/health).
        warn!("[csq-ledger] {AUTO_KEY_WARNING}");
    }

    // ── Open append-only storage after authority-key load ───────────────────
    // Recovery pins durable anchor verdict/revocation artifacts to this key;
    // accepting an arbitrary self-signed file here could turn a local write
    // into an authority-approved denial.
    let store = match LedgerStore::open_with_authority(&config.data_dir, signing_key.key_id()) {
        Ok(s) => s,
        Err(e) => {
            error!(error = %e, "failed to open ledger storage");
            return Err(74); // EX_IOERR
        }
    };
    info!(tree_size = store.tree_size(), data_dir = %config.data_dir.display(), "ledger storage opened");

    // ── Resolve the optional anchor target (Strengthening 1) ─────────────────
    let anchor_target = match &config.anchor_to_sink {
        Some(name) => match anchor::resolve_sink(name) {
            Ok(sink) => {
                info!(
                    sink = name,
                    cadence_secs = config.anchor_cadence,
                    "anchor-to-sink configured"
                );
                Some(AnchorTarget {
                    sink,
                    cadence_secs: config.anchor_cadence,
                })
            }
            Err(e) => {
                error!(error = %e, "failed to resolve --anchor-to-sink");
                return Err(78); // EX_CONFIG
            }
        },
        None => None,
    };

    // Whether anchoring is on (the AnchorTarget is moved into AppState; the
    // cadence task gets its own resolved sink + cadence below).
    let anchor_for_task = match (&config.anchor_to_sink, &anchor_target) {
        (Some(name), Some(_)) => Some((name.clone(), config.anchor_cadence)),
        _ => None,
    };

    let state = Arc::new(AppState::new(store, signing_key, anchor_target));

    // ── Spawn the anchor-cadence background task ─────────────────────────────
    if let Some((sink_name, cadence_secs)) = anchor_for_task {
        let task_state = Arc::clone(&state);
        tokio::spawn(async move {
            run_anchor_cadence(task_state, sink_name, cadence_secs).await;
        });
    }

    // ── Bind + serve: two listeners, two routers (H3) ───────────────────────
    // The read/write listener carries submit + all read routes. The authority
    // listener carries ONLY revoke + verifier-bootstrap redemption, defaults
    // to loopback-only, and is bound independently so an operator can
    // firewall it more tightly than the read/write traffic. See
    // `server::mod` doc "Two listeners, two routers" + spec 17 §17.3.
    let addr = config.socket_addr();
    let listener = match tokio::net::TcpListener::bind(&addr).await {
        Ok(l) => l,
        Err(e) => {
            error!(error = %e, addr = %addr, "failed to bind read/write listener");
            return Err(74);
        }
    };
    info!(addr = %addr, "csq-ledger read/write listener");

    let authority_addr = config.authority_socket_addr();
    let authority_listener = match tokio::net::TcpListener::bind(&authority_addr).await {
        Ok(l) => l,
        Err(e) => {
            error!(error = %e, addr = %authority_addr, "failed to bind authority listener");
            return Err(74);
        }
    };
    info!(
        addr = %authority_addr,
        "csq-ledger authority listener (revoke, verifier-bootstraps; internal-only by default)"
    );

    let read_router = build_read_router(Arc::clone(&state));
    let authority_router = build_authority_router(state);

    let read_server = axum::serve(listener, read_router);
    let authority_server = axum::serve(authority_listener, authority_router);

    // Either listener exiting (only possible on an IO error — neither server
    // has a configured graceful-shutdown trigger) brings the whole process
    // down; a half-alive server (e.g. authority listener dead, read/write
    // listener still serving) is a worse operator experience than a clean
    // exit + restart.
    tokio::select! {
        res = read_server => {
            if let Err(e) = res {
                error!(error = %e, "read/write server error");
                return Err(70); // EX_SOFTWARE
            }
        }
        res = authority_server => {
            if let Err(e) = res {
                error!(error = %e, "authority server error");
                return Err(70); // EX_SOFTWARE
            }
        }
    }
    Ok(())
}

/// Background task: anchors the current checkpoint to the configured sink at
/// `cadence_secs` intervals, storing each receipt so `GET /v1/checkpoint`
/// surfaces `anchored_to`.
///
/// The task re-resolves the sink once (resolution is cheap + the impl is held
/// in `AppState.anchor`). It uses `AppState.anchor` if present; otherwise it
/// resolves from the name. We resolve from the name here so the task owns its
/// own `Arc<dyn LedgerSink>` independent of the request path.
async fn run_anchor_cadence(state: Arc<AppState>, sink_name: String, cadence_secs: u64) {
    let target = match anchor::resolve_sink(&sink_name) {
        Ok(sink) => AnchorTarget { sink, cadence_secs },
        Err(e) => {
            error!(error = %e, "anchor cadence task could not resolve sink; anchoring disabled");
            return;
        }
    };
    let period = std::time::Duration::from_secs(cadence_secs.max(1));
    let mut interval = tokio::time::interval(period);
    // Skip the immediate first tick's "fire at t=0" so the first anchor happens
    // after one full cadence (a fresh empty tree has nothing meaningful to
    // anchor at t=0). High-impact-op immediate anchoring is a future hook.
    interval.tick().await;
    loop {
        interval.tick().await;
        let checkpoint = build_checkpoint(&state);
        match anchor::anchor_checkpoint(&checkpoint, &target).await {
            Ok(receipt) => {
                if let Err(e) = state.store.record_anchor(receipt) {
                    warn!(error = %e, "failed to persist anchor receipt");
                } else {
                    info!(
                        sink = %sink_name,
                        tree_size = checkpoint.tree_size,
                        "checkpoint anchored to sink"
                    );
                }
            }
            Err(e) => {
                warn!(error = %e, sink = %sink_name, "checkpoint anchor attempt failed");
            }
        }
    }
}
