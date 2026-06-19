# Packaging & Deployment

This directory documents how Aegis components are deployed. There is deliberately
**no traditional package** (`.deb`/`.rpm`) to maintain: the server is a single
self-contained binary, and the agent ships its own installer that generates the
systemd units at install time. This note explains both.

For build instructions (including the static musl `aegisd`) see
[`docs/BUILD.md`](../docs/BUILD.md). For *why* the tamper-resistance is shaped the
way it is — and its limits — see [`docs/THREAT_MODEL.md`](../docs/THREAT_MODEL.md).

---

## The server: one file

`aegisd` is a single, statically-linked binary with an embedded datastore and
embedded dashboard assets — no external database, no runtime asset directory.
"Packaging" the server is copying that file:

```bash
scp target/x86_64-unknown-linux-musl/release/aegisd user@host:/usr/local/bin/aegisd
ssh user@host '/usr/local/bin/aegisd run \
    --listen 0.0.0.0:8443 --http 127.0.0.1:8080 --data-dir /var/lib/aegis'
```

Back up = copy the `redb` file under `--data-dir`. A container image is provided
by the repo-root [`Dockerfile`](../Dockerfile) (scratch + the single binary).
A systemd unit for the server is left to the operator (the server has no special
self-protection requirement); the tamper machinery below is for the **agent**.

---

## The agent: a self-installing, tamper-resistant systemd service

The agent does not need an external packaging recipe to lay down units — it
**generates and installs them itself**. The privileged install/uninstall
lifecycle lives in
[`plugins/plugin-tamper/src/install.rs`](../plugins/plugin-tamper/src/install.rs)
(module `plugin_tamper::install`) and is driven by the `aegis-agent`
subcommands (see `crates/aegis-agent/src/main.rs`).

### Install (requires root)

```bash
sudo aegis-agent install --server https://SERVER:8443
# Optionally override the destination:
sudo aegis-agent install --install-path /usr/local/sbin/aegis-agent --server https://SERVER:8443
```

`install` prints the two unit files it is about to write, then performs the
privileged steps. The layout and ordering come straight from
`InstallSpec` / `install()`:

| Artifact | Default path | Mode | Owner |
|----------|--------------|------|-------|
| Agent binary | `/usr/local/sbin/aegis-agent` | `0755` | `root:root` |
| Primary unit | `/etc/systemd/system/aegis-agent.service` | `0644` | `root:root` |
| Guardian unit | `/etc/systemd/system/aegis-guardian.service` | `0644` | `root:root` |
| Baseline manifest | `/var/lib/aegis/manifest.json` | `0644` | `root:root` |
| Uninstall token | `/var/lib/aegis/uninstall.token` | `0600` | `root:root` |

Install order is chosen so the system is **never left unremovable**: the
immutable attribute is applied **last** (and uninstall clears it **first**):

1. Copy the running binary to `install_path` (symlink-safe: `O_NOFOLLOW` open +
   `fchown` the fd, never a re-resolved path; clears any prior immutable bit so a
   reinstall can overwrite).
2. Write both systemd unit files (rendered by `render_service_unit` /
   `render_guardian_unit`).
3. Write the SHA-256 baseline **manifest** over the binary + both units (this is
   the `manifest_path` the runtime tamper loop uses for content verification).
4. Write the **uninstall token/marker** (`0600`) — see note below; it is
   *intentionally not* made immutable.
5. `systemctl daemon-reload`, then `enable --now` both units.
6. Set the **immutable bit** (`chattr +i`) on the binary + both units + the
   manifest.

After install, `aegis-agent run` (the unit's `ExecStart`) auto-wires the tamper
plugin to exactly this layout when running as root — so the runtime
`protected_paths` / `manifest_path` match what the installer hashed and locked.
You normally do **not** set those fields in a `--config` TOML (see
[`configs/agent.example.toml`](../configs/agent.example.toml)).

### The generated units

The two units are a mutually-dependent watchdog **pair** so that killing one
triggers recovery of both. Their hardening (verbatim from `install.rs`):

`aegis-agent.service`
- `Restart=always`, `RestartSec=1` — a single `kill` is ineffective.
- `Requires=aegis-guardian.service` — bound to its guardian.
- `NoNewPrivileges=yes` — no privilege transition (defeats setuid/`LD_PRELOAD`
  escalation); the root uninstall path is unaffected.
- `KillMode=process`, `OOMScoreAdjust=-900` — resist casual signals / the OOM killer.
- `ExecStart=/usr/local/sbin/aegis-agent run --server <SERVER>`.

`aegis-guardian.service`
- `BindsTo=aegis-agent.service`, `After=aegis-agent.service`.
- `ExecStart=/usr/local/sbin/aegis-agent guard --service aegis-agent`.
- `Restart=always`, `RestartSec=1`, `User=root`.

The guardian's `guard` loop is belt-and-suspenders to systemd's own
`BindsTo`/`Restart`: every ~2s it runs `systemctl is-active aegis-agent` and, if
the service is not exactly `active`, logs the event (so a kill is observable) and
restarts it. The decision is the pure `should_restart()` helper.

### Enroll, then run

Install wires `--server` into the unit, but the agent still needs an enrolled
identity to forward telemetry over mutual TLS. Mint a one-time token on the
server and enroll (the secure path keeps the token off `argv`):

```bash
# On the server host:
aegisctl token create --label web-01      # prints the token + the cert pin

# On the endpoint — prefer the blob/stdin or a 0600 token file over --token:
aegis-agent enroll --server https://SERVER:8443 --enroll-blob -   # paste AEGIS-ENROLL blob
```

The enrolled identity is persisted under `<data_dir>/plugin-transport/`, where
the forwarder reads it.

---

## Authenticated, root-only uninstall (the escape hatch)

Removal is the **authenticated administrator escape hatch**. The single hard
precondition is **uid 0**:

```bash
sudo aegis-agent uninstall
```

`uninstall()` deliberately:

- **Requires root, and root alone.** Root holds the one privileged primitive
  (`CAP_LINUX_IMMUTABLE` + systemd control + file ownership) every protection
  layer is keyed on, so requiring root is both necessary and sufficient.
- **Does not require the token.** A missing/corrupt `uninstall.token` does *not*
  block removal — the token records *intent*/paths; root is *authority*. (When
  present, the token is read to target the exact paths recorded at install.)
  This is why the token is mode `0600` and never made immutable: root must always
  be able to consume it during teardown.
- **Reverses the install ordering safely.** It clears the immutable bits *first*
  (so the files become modifiable/removable), then `disable --now` both units,
  removes the binary + both units + manifest + token, and `daemon-reload`s.
  Each step is best-effort/idempotent (an already-gone file or unloaded unit is
  success), so a partial install is still fully removable.

This is by design **not** a rootkit: it uses only supported OS mechanisms
(root-owned files, the immutable attribute, a systemd watchdog pair), hides
nothing, and is fully reversible by the administrator. See
[`docs/THREAT_MODEL.md`](../docs/THREAT_MODEL.md) for the complete reasoning,
the posture self-check, and the alert-only fallbacks when the strong posture
(root + systemd + host PID namespace) is unavailable.
