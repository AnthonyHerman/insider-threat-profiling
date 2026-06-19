# =============================================================================
# Aegis server (aegisd) — self-contained container image
# =============================================================================
#
# A two-stage build that compiles the statically-linked `aegisd` against musl and
# ships ONLY that one binary in a `scratch` final stage. The result is the entire
# server: no base distro, no shared libraries, no package manager.
#
# Build (from the repo root):
#   docker build -t aegisd:0.1.0 .
# Run:
#   docker run --rm -p 8443:8443 -p 127.0.0.1:8080:8080 \
#     -v aegis-data:/var/lib/aegis \
#     aegisd:0.1.0 run --listen 0.0.0.0:8443 --http 0.0.0.0:8080 --data-dir /var/lib/aegis
#
# (Image flags mirror `aegisd run`; see crates/aegis-server/src/main.rs.)
# =============================================================================

# ---- Stage 1: build the static musl binary ---------------------------------
# The toolchain is pinned by rust-toolchain.toml (Rust 1.92, with the
# x86_64-unknown-linux-musl target). musl-tools provides `musl-gcc`, which the
# TLS stack (rustls + ring) needs to link statically — exactly as CI does
# (see .github/workflows/ci.yml and docs/BUILD.md).
FROM rust:1.92 AS build

# C toolchain that targets musl (for `ring`). Matches the CI "musl-tools" step.
RUN apt-get update \
    && apt-get install -y --no-install-recommends musl-tools \
    && rm -rf /var/lib/apt/lists/*

# Ensure the musl target is present (the pinned toolchain already lists it; this
# is a no-op safety net if the base image's default profile differs).
RUN rustup target add x86_64-unknown-linux-musl

WORKDIR /src
# Copy the whole workspace. (For better layer caching you could pre-fetch deps
# with a manifest-only copy + `cargo fetch`; kept simple and correct here.)
COPY . .

# Build ONLY the server binary, statically linked, with the locked dependency
# graph — identical to the CI "Build static aegisd" step. `release` already sets
# strip + LTO + panic=abort (see [profile.release] in Cargo.toml).
RUN CC_x86_64_unknown_linux_musl=musl-gcc \
    cargo build --release --locked \
        --bin aegisd \
        --target x86_64-unknown-linux-musl

# Fail the build early if the artifact is not actually self-contained, so a
# regression to dynamic linking can never silently ship in the scratch image.
RUN ldd target/x86_64-unknown-linux-musl/release/aegisd 2>&1 \
    | grep -qiE "not a dynamic executable|statically linked" \
    || (echo "FATAL: aegisd is not statically linked" && exit 1)

# ---- Stage 2: the entire runtime image is one file --------------------------
# `scratch` is empty: no shell, no libc, no CA bundle, nothing. We can do this
# because aegisd is a HARD self-contained design constraint — it links statically
# (musl) and embeds everything it needs:
#   * the datastore is an embedded `redb` file (no external database),
#   * the operator dashboard assets are compiled into the binary (no asset dir),
#   * its TLS leaf cert is self-signed and generated on first run into --data-dir,
#     and the protocol pins it (no system CA trust store required).
# So the only thing the container needs is the binary and a writable data volume;
# adding any other file would contradict the "single self-contained binary" claim.
FROM scratch

# Persisted state: embedded redb store + the self-signed TLS material whose
# SHA-256 fingerprint agents pin. Mount a volume here to survive restarts;
# "backup" is simply copying this directory (see docs/BUILD.md).
VOLUME ["/var/lib/aegis"]

# TLS ingest listener (agents connect here) and the operator HTTP API/dashboard.
EXPOSE 8443 8080

COPY --from=build /src/target/x86_64-unknown-linux-musl/release/aegisd /aegisd

ENTRYPOINT ["/aegisd"]
# Default to `run` with the data dir on the volume; override args at `docker run`.
CMD ["run", "--listen", "0.0.0.0:8443", "--http", "0.0.0.0:8080", "--data-dir", "/var/lib/aegis"]
