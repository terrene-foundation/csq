# csq-ledger — Foundation-owned transparency-log server (M10).
#
# Multi-stage build: a Rust builder compiles a static-ish release binary, then
# a distroless runtime carries only the binary. Published as
# ghcr.io/terrene-foundation/csq-ledger:<version> (workspace-owner decision 1).
#
# Build (from the workspace root, NOT from csq-ledger/):
#   docker build -f csq-ledger/Dockerfile -t ghcr.io/terrene-foundation/csq-ledger:latest .
#
# Run:
#   docker run -v /var/lib/csq-ledger:/data -p 8080:8080 \
#     ghcr.io/terrene-foundation/csq-ledger:latest

# ── Stage 1: builder ─────────────────────────────────────────────────────────
FROM rust:1.90-bookworm AS builder

WORKDIR /build

# Copy the whole workspace so the path-dependency on csq-core resolves. The
# build context MUST be the workspace root (see the build command above).
COPY . .

# Build only the csq-ledger binary in release mode. Default features (no
# anchor sink); operators who anchor rebuild with --features anchor-<sink>.
RUN cargo build --release -p csq-ledger --bin csq-ledger

# Pre-create /data owned by the distroless nonroot uid (65532). Docker seeds a
# fresh anonymous/named volume from the image's content + ownership at the
# mount path, so a plain `docker run -v vol:/data` (or `-v /host/path:/data`
# after the operator chowns the host dir) lands a writable directory for the
# nonroot user without a manual chown step.
RUN mkdir -p /data && chown 65532:65532 /data && chmod 700 /data

# ── Stage 2: distroless runtime ──────────────────────────────────────────────
# gcr.io/distroless/cc-debian12 carries glibc + libgcc (needed by the Rust
# binary) and nothing else — no shell, no package manager, minimal attack
# surface. `nonroot` runs as uid 65532.
FROM gcr.io/distroless/cc-debian12:nonroot

# Carry over the /data directory with its nonroot ownership so a fresh volume
# mount inherits writability for uid 65532.
COPY --from=builder --chown=65532:65532 /data /data

# The data directory is a mounted volume; the server creates subdirs on boot.
# Declaring it documents the mount point and ensures the layer exists.
VOLUME /data
ENV CSQ_LEDGER_DATA_DIR=/data
ENV CSQ_LEDGER_PORT=8080
ENV CSQ_LEDGER_BIND=0.0.0.0

EXPOSE 8080

COPY --from=builder /build/target/release/csq-ledger /usr/local/bin/csq-ledger

# Run as the distroless nonroot user (uid 65532). The mounted volume must be
# writable by this uid; see docs/audit-sinks/csq-ledger.md for the chown note.
USER nonroot:nonroot

ENTRYPOINT ["/usr/local/bin/csq-ledger"]
