# YominsOps Metrics Agent

A lightweight Go agent that collects host-level system metrics and pushes them to the YominsOps monitoring stack. The agent requires no inbound ports and no SSH access — it pushes outbound over HTTPS.

## How it works

```
[Your Server]                          [YominsOps]
  yomins-agent
    → collects CPU, RAM, disk,
      network, system metrics
    → pushes every 60s over HTTPS  →   Ingestion endpoint
      with Bearer token auth           validates token
                                       enriches with project labels
                                       writes to Prometheus storage
```

The agent identifies itself with a project-scoped token. The server resolves the token to a project, appends authoritative labels (`project_id`, `customer_id`), and stores the data. **The agent never controls project identity** — that is always enforced server-side.

## Metrics collected

### CPU
| Metric | Type | Description |
|--------|------|-------------|
| `cpu_usage_percent` | Gauge | Total CPU usage, 0–100 |

### Memory
| Metric | Type | Description |
|--------|------|-------------|
| `memory_total_bytes` | Gauge | Total physical memory |
| `memory_available_bytes` | Gauge | Available memory |
| `memory_used_bytes` | Gauge | Used memory |
| `memory_used_percent` | Gauge | Memory usage, 0–100 |
| `swap_total_bytes` | Gauge | Total swap |
| `swap_used_bytes` | Gauge | Used swap |
| `swap_free_bytes` | Gauge | Free swap |
| `swap_used_percent` | Gauge | Swap usage, 0–100 |

### Disk (per filesystem, labels: `mountpoint`, `fstype`, `device`)
| Metric | Type | Description |
|--------|------|-------------|
| `disk_total_bytes` | Gauge | Total filesystem size |
| `disk_used_bytes` | Gauge | Used space |
| `disk_free_bytes` | Gauge | Free space |
| `disk_used_percent` | Gauge | Usage, 0–100 |
| `disk_inodes_total` | Gauge | Total inodes |
| `disk_inodes_used` | Gauge | Used inodes |
| `disk_inodes_free` | Gauge | Free inodes |
| `disk_inodes_used_percent` | Gauge | Inode usage, 0–100 |

### Network (per interface, label: `interface`; loopback excluded)
| Metric | Type | Description |
|--------|------|-------------|
| `network_bytes_sent_total` | Counter | Bytes sent since boot |
| `network_bytes_recv_total` | Counter | Bytes received since boot |
| `network_packets_sent_total` | Counter | Packets sent since boot |
| `network_packets_recv_total` | Counter | Packets received since boot |

### System
| Metric | Type | Description |
|--------|------|-------------|
| `system_uptime_seconds` | Gauge | System uptime in seconds |
| `system_load_average` | Gauge | Load average (label `period`: `1m`, `5m`, `15m`) |

### Agent self-metrics
| Metric | Type | Description |
|--------|------|-------------|
| `agent_push_success_total` | Counter | Successful push operations |
| `agent_push_error_total` | Counter | Failed push operations |
| `agent_last_push_success_timestamp` | Gauge | Unix timestamp of last successful push |
| `agent_collection_duration_seconds` | Gauge | Last collection pass duration |
| `agent_push_duration_seconds` | Gauge | Last push attempt duration |
| `agent_uptime_seconds` | Gauge | Agent process uptime |
| `agent_build_info` | Gauge | Always 1; labels carry `version`, `commit`, `build_date`, `go_version`, `os`, `arch` |
| `agent_collector_error_total` | Counter | Errors per collector (label: `collector`) |

All metrics carry agent-level labels: `agent_id`, `hostname`, `agent_version`, `source="yomins_agent"`.

## Configuration

Configuration is accepted via CLI flags or environment variables. CLI flags take precedence over environment variables.

| Flag | Environment variable | Default | Description |
|------|---------------------|---------|-------------|
| `--server` | `YOMINS_SERVER` | *(required)* | Ingestion endpoint URL |
| `--token` | `YOMINS_TOKEN` | *(required)* | Project-scoped auth token |
| `--interval` | `YOMINS_INTERVAL` | `60s` | Push interval (e.g. `30s`, `2m`) |
| `--log-level` | `YOMINS_LOG_LEVEL` | `info` | Log level: `debug`, `info`, `warn`, `error` |
| `--hostname-override` | `YOMINS_HOSTNAME_OVERRIDE` | *(auto-detected)* | Override reported hostname |
| `--disable-filesystems` | `YOMINS_DISABLE_FILESYSTEMS` | `false` | Disable disk metrics |
| `--disable-network` | `YOMINS_DISABLE_NETWORK` | `false` | Disable network metrics |
| `--state-dir` | `YOMINS_STATE_DIR` | `/var/lib/yomins-agent` | Persistent state directory |
| `--disable-auto-upgrade` | `YOMINS_DISABLE_AUTO_UPGRADE` | `false` | Disable automatic self-upgrade |
| `--auto-upgrade-interval` | `YOMINS_AUTO_UPGRADE_INTERVAL` | `24h` | How often to check for a newer version |
| `--insecure-skip-verify` | — | `false` | Skip TLS verification (**dev only**) |

## Security model

- All communication is HTTPS only; plaintext HTTP is never used in production.
- The agent authenticates using a `Bearer` token in the `Authorization` header.
- Tokens are project-scoped and revocable server-side.
- The agent never requires open inbound ports, reverse proxies, or TLS termination.
- Project identity labels (`project_id`, `customer_id`) are assigned server-side based on the token; the agent cannot influence them.

## Agent identity

On first start the agent generates a UUID (`agent_id`) and persists it to `$state-dir/agent_id`. Subsequent restarts reuse the same ID, enabling consistent time-series identity in Prometheus. In read-only or ephemeral environments (e.g. Docker without a persistent volume) a warning is logged and an in-memory ID is used — the agent always starts successfully.

## Delivery

- Push model: the agent sends metrics every `--interval` seconds.
- Format: Prometheus text exposition format v0.0.4.
- Retries: exponential backoff starting at 1 s, capped at 60 s, with a total budget of 90% of the collection interval (prevents retry bleed into the next tick).
- Permanent errors (HTTP 4xx except 429) are not retried.
- Push failures are logged and counted in `agent_push_error_total` but do not crash the agent.

## Docker

```bash
docker run -d \
  --name yomins-agent \
  --restart unless-stopped \
  --pid=host \
  -v /proc:/host/proc:ro \
  -v /sys:/host/sys:ro \
  -v /:/rootfs:ro \
  -v yomins-agent-state:/var/lib/yomins-agent \
  -e YOMINS_SERVER=https://ingest.yominsops.com \
  -e YOMINS_TOKEN=<PROJECT_TOKEN> \
  ghcr.io/yominsops/yomins-agent:latest
```

The named volume `yomins-agent-state` persists the `agent_id` across container restarts.

## Development: serving install.sh locally

`Dockerfile.serve` builds a minimal nginx image that serves `install.sh` over HTTP. It is used in the local dev docker-compose as the `install-server` service (port 8080):

```bash
curl http://localhost:8080/install.sh
```

No HTTPS or certificates are needed — a reverse proxy handles TLS termination in production.

## Self-upgrade

The agent upgrades itself automatically. On startup and every `--auto-upgrade-interval` (default: 24 h) it checks the GitHub Releases API. When a newer version is found:

1. The binary and its SHA-256 checksum are downloaded and the hash is verified.
2. The new binary is staged in the agent's state directory (`/var/lib/yomins-agent/upgrade/`).
3. The agent exits cleanly; systemd restarts it.
4. On the next start a privileged pre-start script (`apply-upgrade.sh`) atomically replaces `/usr/local/bin/yomins-agent` before the agent process launches.

**Automatic rollback:** if the new binary crashes before successfully pushing metrics for the first time, `apply-upgrade.sh` detects the uncommitted upgrade on the following restart and restores the backup automatically.

To disable auto-upgrade set `YOMINS_DISABLE_AUTO_UPGRADE=true` in `/etc/yomins-agent/env`.

**Enabling auto-upgrade on an existing install** — re-run the install script without arguments. It detects the existing config and upgrades the binary, service file, and helper scripts in place:

```bash
curl -fsSL https://get.yominsops.com/agent | sudo bash
```

Dev builds (`version = "dev"`) never trigger an upgrade check.

## Project layout

```
cmd/yomins-agent/       — binary entry point
internal/
  config/               — CLI flag + env-var parsing
  version/              — build-time version info
  identity/             — agent_id persistence
  metrics/              — MetricPoint types and Prometheus text encoding
  collector/            — Collector interface, Registry, and per-subsystem collectors
  transport/            — Transport interface and HTTP push implementation
  agent/                — orchestration loop (collect → encode → push)
  upgrade/              — self-upgrade: version check, download, staging, rollback
systemd/                — systemd service unit and apply-upgrade.sh helper script
Dockerfile
Makefile
```

## Releases

Releases are published automatically via GitHub Actions when a semver tag is pushed:

```bash
git tag v1.2.3 && git push origin v1.2.3
```

Each release includes:
- Static binaries for `linux/amd64` and `linux/arm64`
- Per-binary SHA-256 checksum sidecars (`*.sha256`) used by the self-upgrade mechanism
- A unified `checksums.txt` and its Sigstore bundle (`checksums.txt.bundle`) for manual verification
- The systemd service unit file and the `apply-upgrade.sh` helper script
- Docker image pushed to `ghcr.io/yominsops/yomins-agent`

CI runs on every push and pull request to `main` (tests + lint). Releases are only created on tag pushes.

### Verifying a release

Signatures use [Sigstore](https://www.sigstore.dev/) keyless signing — no key to trust or rotate. The signing identity is the GitHub Actions workflow itself.

Install [cosign](https://github.com/sigstore/cosign), then:

```bash
VERSION=v1.2.3

# Download the checksums file and its bundle
curl -fsSL "https://github.com/yominsops/yomins-agent/releases/download/${VERSION}/checksums.txt" -o checksums.txt
curl -fsSL "https://github.com/yominsops/yomins-agent/releases/download/${VERSION}/checksums.txt.bundle" -o checksums.txt.bundle

# Verify the signature
cosign verify-blob \
  --bundle checksums.txt.bundle \
  --certificate-identity "https://github.com/yominsops/yomins-agent/.github/workflows/release.yml@refs/tags/${VERSION}" \
  --certificate-oidc-issuer "https://token.actions.githubusercontent.com" \
  checksums.txt

# Verify the binary hash
sha256sum --check --ignore-missing checksums.txt
```

A passing `cosign verify-blob` confirms the checksum file was produced by the official release workflow for that exact tag. The binary hash check then confirms the downloaded binary matches.

## Building from source

```bash
git clone https://github.com/yominsops/yomins-agent.git
cd yomins-agent
make build          # produces ./yomins-agent
make test           # unit tests
make test-integration  # real OS tests (Linux recommended)
```

Requires Go 1.24 or later.
