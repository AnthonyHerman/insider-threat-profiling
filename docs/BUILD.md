# Building & Deploying Aegis

## Prerequisites
- Rust (pinned in `rust-toolchain.toml`, 1.92).
- For the static server: the musl target (`rustup target add x86_64-unknown-linux-musl`)
  and a C toolchain for `ring` (CI installs `musl-tools`, which provides `musl-gcc`).

## Development build
```bash
cargo build --workspace
cargo test --workspace
cargo clippy --workspace --all-targets -- -D warnings
```

## The self-contained server (single static binary)
`aegisd` is designed to ship as one statically-linked binary with no external
database and no runtime asset directory (embedded `redb` store + embedded
dashboard assets).

```bash
cargo build --release --bin aegisd --target x86_64-unknown-linux-musl
ldd target/x86_64-unknown-linux-musl/release/aegisd   # => "statically linked"
```

> **musl + ring note.** Once the TLS stack (`rustls` + `ring`) is linked, the
> musl build needs a C compiler that targets musl. On CI we install `musl-tools`
> (`musl-gcc`). On a host without it, either install `musl-tools` or point cargo
> at clang:
> ```bash
> CC_x86_64_unknown_linux_musl=musl-gcc \
>   cargo build --release --bin aegisd --target x86_64-unknown-linux-musl
> ```

## Running locally
```bash
# List the plugins the kernel discovers (proves the plugin-native core)
cargo run --bin aegisctl -- plugins

# Run the server
cargo run --bin aegisd -- run --listen 0.0.0.0:8443 --http 127.0.0.1:8080

# Enroll + run an agent (enrollment token minted by aegisctl/server)
cargo run --bin aegis-agent -- enroll --server https://SERVER:8443 --token <TOKEN>
cargo run --bin aegis-agent -- run --server https://SERVER:8443

# A monitored shell that produces real behavioral telemetry
cargo run --bin aegis-agent -- shell
```

## Deploying the server to a Linux host
The server is one file. Copy it and run it; back up = copy the `redb` file.
```bash
scp target/x86_64-unknown-linux-musl/release/aegisd user@host:/usr/local/bin/aegisd
ssh user@host '/usr/local/bin/aegisd run --listen 0.0.0.0:8443 --http 127.0.0.1:8080 --data-dir /var/lib/aegis'
```

## Installing the tamper-resistant agent (requires root)
```bash
sudo aegis-agent install --server https://SERVER:8443
# Authenticated removal (root only):
sudo aegis-agent uninstall
```
See `THREAT_MODEL.md` for exactly what "tamper-resistant" guarantees and the
deliberate root escape hatch.
