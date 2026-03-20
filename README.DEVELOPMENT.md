# Development Guide

This document covers what remains to be built — on the agent side and on the server side — to reach a production-ready state.

---

## Agent — remaining work

The agent binary is functional for local testing but several items are needed before a production release.

### Must-have before production

**Release pipeline**

- CI workflow (GitHub Actions or equivalent) that runs `go test ./...` on every push.
- Cross-compilation targets: `linux/amd64` and `linux/arm64` as static binaries (`CGO_ENABLED=0`).
- Automated GitHub release with checksums (`sha256sum`) and a signed manifest.
- Docker image build and push to a container registry (e.g. `ghcr.io/yominsops/agent`).

**TLS enforcement**

The agent already uses HTTPS for all push calls. Before release:
- Remove or gate `--insecure-skip-verify` so it is only compiled in for debug builds or explicitly rejected in production environments.
- Validate that `--server` starts with `https://` in `config.Validate()` and reject plain `http://` unless the insecure flag is explicitly set.

### Nice-to-have

**iowait CPU metric**

The spec lists iowait as optional. gopsutil exposes per-CPU time breakdowns via `cpu.TimesWithContext`. Adding a `cpu_iowait_percent` Gauge requires computing the delta between two samples, similar to how total CPU percent is derived.

**Network error/drop counters**

gopsutil's `net.IOCountersStat` exposes `Errin`, `Errout`, `Dropin`, `Dropout`. These are straightforward additions to the `NetworkCollector`.

**Configurable filesystem filter**

Currently all physical partitions are collected. A future `--exclude-mountpoints` flag (accepting a comma-separated list or regex) would allow operators to exclude noisy or irrelevant mounts.

**Configurable network interface filter**

Similar to filesystems, a `--exclude-interfaces` flag to skip specific interfaces by name (e.g. virtual bridges, VPN tunnels).

**Structured log format option**

Add a `--log-format json` flag for log aggregation pipelines. The `slog.JSONHandler` is already in the standard library; it is a two-line change.

**arm64 Docker image**

The Dockerfile currently builds for the host architecture only. A multi-platform image (`--platform linux/amd64,linux/arm64`) requires a `docker buildx` pipeline, typically set up in CI.

**Graceful shutdown with final push**

When the agent receives `SIGTERM` it currently exits after the context is cancelled. A short grace-period push of the final snapshot (including self-metrics) would give operators one last data point before the agent stops.

**Health check endpoint (optional)**

A minimal HTTP server on localhost (e.g. `:9101/healthz`) that returns 200 when the last push succeeded within 2× the interval. This enables Kubernetes liveness probes and systemd watchdog integration without exposing metrics externally.

------

## Summary of open items

| Area | Item | Priority |
|------|------|----------|
| Agent | CI pipeline + cross-compilation | High |
| Agent | One-command install script | ~~High~~ done |
| Agent | Enforce HTTPS in config validation | High |
| Agent | Signed release artifacts | Medium |
| Agent | iowait and network error metrics | Low |
| Agent | Configurable filesystem/interface filters | Low |
| Agent | Graceful shutdown with final push | Low |
| Agent | Health check endpoint | Low |
