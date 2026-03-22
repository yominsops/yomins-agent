# Development TODO

This document covers what remains to be built — on the agent side and on the server side — to reach a production-ready state.

---

## Agent — remaining work

The agent binary is functional for local testing but several items are needed before a production release.

### Must-have before production

**Release pipeline**

- ~~CI workflow (GitHub Actions or equivalent) that runs `go test ./...` on every push.~~ **Done** (`.github/workflows/ci.yml`)
- ~~Cross-compilation targets: `linux/amd64` and `linux/arm64` as static binaries (`CGO_ENABLED=0`).~~ **Done** (`release.yml`)
- ~~Automated GitHub release with checksums (`sha256sum`).~~ **Done** (`release.yml` — SHA256 checksums generated and signed with Sigstore keyless signing)
- ~~Docker image build and push to a container registry (e.g. `ghcr.io/yominsops/agent`).~~ **Done** (`release.yml` — multi-platform via `docker buildx`)

**TLS enforcement**

The agent already uses HTTPS for all push calls. Operators who explicitly need plain HTTP (e.g. local testing) can pass `--allow-http`.

### Nice-to-have

~~**iowait CPU metric**~~

~~The spec lists iowait as optional. gopsutil exposes per-CPU time breakdowns via `cpu.TimesWithContext`. Adding a `cpu_iowait_percent` Gauge requires computing the delta between two samples, similar to how total CPU percent is derived.~~ **Done** — `cpu_iowait_percent` (Gauge) is emitted from the second collection onward; the first call is skipped (no delta yet). Always 0 on macOS/BSD where the kernel does not expose iowait.

~~**Network error/drop counters**~~

~~gopsutil's `net.IOCountersStat` exposes `Errin`, `Errout`, `Dropin`, `Dropout`. These are straightforward additions to the `NetworkCollector`.~~ **Done** — `network_errors_in_total`, `network_errors_out_total`, `network_drops_in_total`, `network_drops_out_total` (all Counter) are now emitted per interface.

~~**Configurable filesystem filter**~~

~~Currently all physical partitions are collected. A future `--exclude-mountpoints` flag (accepting a comma-separated list or regex) would allow operators to exclude noisy or irrelevant mounts.~~ **Done** — `--exclude-mountpoints` flag (env: `YOMINS_EXCLUDE_MOUNTPOINTS`) accepts a comma-separated list of mountpoints to skip.

~~**Configurable network interface filter**~~

~~Similar to filesystems, a `--exclude-interfaces` flag to skip specific interfaces by name (e.g. virtual bridges, VPN tunnels).~~ **Done** — `--exclude-interfaces` flag (env: `YOMINS_EXCLUDE_INTERFACES`) accepts a comma-separated list of interface names to skip; loopback (`lo`) is always excluded regardless.

**Structured log format option**

Add a `--log-format json` flag for log aggregation pipelines. The `slog.JSONHandler` is already in the standard library; it is a two-line change.

**arm64 Docker image**

~~The Dockerfile currently builds for the host architecture only. A multi-platform image (`--platform linux/amd64,linux/arm64`) requires a `docker buildx` pipeline, typically set up in CI.~~ **Done** — `release.yml` uses `docker buildx` to build and push a multi-platform image.

~~**Graceful shutdown with final push**~~

~~When the agent receives `SIGTERM` it currently exits after the context is cancelled. A short grace-period push of the final snapshot (including self-metrics) would give operators one last data point before the agent stops.~~ **Done** — on `SIGTERM`/`SIGINT` the agent performs one final collection and push (10 s budget, fits within systemd's `TimeoutStopSec=15s`) before exiting.

**Health check endpoint (optional)**

A minimal HTTP server on localhost (e.g. `:9101/healthz`) that returns 200 when the last push succeeded within 2× the interval. This enables Kubernetes liveness probes and systemd watchdog integration without exposing metrics externally.

~~**Self-upgrade mechanism**~~

~~The agent should be able to upgrade itself to the latest released version without requiring operator intervention. On startup (or via a dedicated flag/signal), the agent checks the GitHub Releases API for a newer version, downloads the binary for the current platform, verifies the SHA256 checksum, atomically replaces itself on disk, and restarts via systemd (or prompts the operator to restart). This is especially useful for long-running deployments managed by systemd where manual upgrades are inconvenient.~~ **Done** — implemented via a two-phase approach: the unprivileged agent stages the new binary (download + SHA256 verification), exits, and a root-owned `ExecStartPre=+` systemd script applies it atomically. Automatic rollback if the new binary fails to commit its first successful push. Configurable via `--disable-auto-upgrade` and `--auto-upgrade-interval`.

------

## Summary of open items

| Area | Item | Priority |
|------|------|----------|
| Agent | CI pipeline + cross-compilation | ~~High~~ done |
| Agent | One-command install script | ~~High~~ done |
| Agent | Docker image + arm64 multi-platform | ~~High~~ done |
| Agent | GitHub release with checksums | ~~High~~ done |
| Agent | ~~Signed release artifacts~~ | ~~Medium~~ done |
| Agent | ~~Self-upgrade mechanism~~ | ~~Medium~~ done |
| Agent | ~~iowait and network error metrics~~ | ~~Low~~ done |
| Agent | ~~Configurable filesystem/interface filters~~ | ~~Low~~ done |
| Agent | ~~Graceful shutdown with final push~~ | ~~Low~~ done |
| Agent | Health check endpoint | Low |

---

## Security recommendations

These items are not blocking but are worth considering for hardened deployments:

- **Config-level HTTPS enforcement**: Currently only `install.sh` rejects plain `http://` server URLs; the binary itself accepts any scheme. Adding a check in `config.Validate()` would make the binary self-defending. Plain HTTP can still be allowed explicitly via `--allow-http`, so operators who need it (e.g. local testing) are not blocked.
- **Build-tag-gate `--insecure-skip-verify`**: This flag disables TLS certificate verification entirely. Restricting it to debug builds prevents it from being accidentally enabled in production. Operators on private networks with internal CAs may still need it; in that case, document it clearly.
