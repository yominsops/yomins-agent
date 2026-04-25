# Yomins Metrics Agent

A lightweight Go agent that collects host-level system metrics and security events, then pushes them to the Yomins monitoring stack. The agent requires no inbound ports and no SSH access — it pushes outbound over HTTPS.

## How it works

```
[Your Server]                          [Yomins]
  yomins-agent
    → collects CPU, RAM, disk,
      network, system, and server
      identity metrics
    → collects auth, process,
      network, and system events
    → pushes every 60s over HTTPS  →   Ingestion endpoint
      with Bearer token auth           validates token
                                       enriches with project labels
                                       writes to storage
```

The agent runs two independent pipelines:

- **Metrics pipeline** — collects numeric measurements on a configurable interval (default: 60 s) and pushes them as Prometheus text format.
- **Event pipeline** — detects discrete security-relevant changes (logins, new processes, new listening ports, OOM kills) and buffers them as structured JSON events. Buffered events are flushed to the server's `/events` endpoint in batches on a configurable interval (default: 10 s), independently of the metrics push interval.

The agent identifies itself with a project-scoped token. The server resolves the token to a project, appends authoritative labels (`project_id`, `customer_id`), and stores the data. **The agent never controls project identity** — that is always enforced server-side.

## Metrics collected

### CPU
| Metric | Type | Description |
|--------|------|-------------|
| `cpu_usage_percent` | Gauge | Total CPU usage, 0–100 |
| `cpu_seconds_total` | Counter | Total CPU time spent in each mode since boot (label: `mode`; aggregate across all CPUs) |
| `cpu_iowait_percent` | Gauge | CPU time spent waiting for I/O, 0–100 (absent on first collection; always 0 on macOS/BSD) |

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
| `network_errors_in_total` | Counter | Inbound errors since boot |
| `network_errors_out_total` | Counter | Outbound errors since boot |
| `network_drops_in_total` | Counter | Inbound packets dropped since boot |
| `network_drops_out_total` | Counter | Outbound packets dropped since boot |

### System
| Metric | Type | Description |
|--------|------|-------------|
| `system_uptime_seconds` | Gauge | System uptime in seconds |
| `system_load_average` | Gauge | Load average (label `period`: `1m`, `5m`, `15m`) |

### Server identity (software & hardware)

Static/semi-static metadata collected once per push cycle. Each metric is omitted independently if its data source is unavailable — a missing tool never prevents other metrics from being collected.

#### Software

| Metric | Type | Description |
|--------|------|-------------|
| `system_info` | Gauge | Always 1; labels: `distribution`, `distribution_version`, `kernel_version`, `virtualization` |
| `system_last_kernel_update_timestamp` | Gauge | Unix timestamp of the last kernel package update; omitted if not detectable |
| `system_last_software_update_timestamp` | Gauge | Unix timestamp of the last software package update; omitted if not detectable |
| `kernelcare_info` | Gauge | Always 1, label `version`; emitted only when KernelCare is installed and detection is not disabled |

#### Hardware

| Metric | Type | Description |
|--------|------|-------------|
| `cpu_info` | Gauge | Always 1; labels: `model`, `cores` (physical), `threads` (logical) |
| `memory_hardware_info` | Gauge | Always 1; label: `total_mb` — total installed RAM |
| `memory_module_info` | Gauge | Always 1 per populated DIMM; labels: `index`, `size_mb`, `type`, `speed_mhz`, `manufacturer`, `locator` — requires `dmidecode` |
| `disk_hardware_info` | Gauge | Always 1 per physical disk; labels: `device`, `model`, `size_gb`, `type` (`ssd`/`hdd`/`nvme`), `transport` |
| `network_hardware_info` | Gauge | Always 1 per physical NIC; labels: `interface`, `speed_mbps`, `state`, `duplex` |
| `hardware_info` | Gauge | Always 1; labels: `vendor`, `product` — server manufacturer and model name |

#### Data sources and tool requirements (Linux)

| Metric | Source | Extra tool required |
|--------|--------|---------------------|
| `system_info` — distribution | `/etc/os-release` | — |
| `system_info` — kernel version | `/proc/version` via gopsutil | — |
| `system_info` — virtualization | `systemd-detect-virt --vm`, fallback `/sys/class/dmi/id/sys_vendor` | `systemd-detect-virt` (optional; falls back to sysfs) |
| `system_last_*_update_timestamp` | `/var/log/dpkg.log{,.1}` on Debian/Ubuntu | — |
| `system_last_*_update_timestamp` | `rpm -qa --last` on RHEL/CentOS/AlmaLinux | `rpm` (must be installed) |
| `kernelcare_info` | `kcarectl --version` | `kcarectl` (KernelCare agent; omitted if not installed) |
| `cpu_info` | `/proc/cpuinfo` via gopsutil | — |
| `memory_hardware_info` — total | `/proc/meminfo` | — |
| `memory_module_info` — per DIMM | `dmidecode --type 17` | **`dmidecode`** (must be installed; usually requires root) |
| `disk_hardware_info` | `/sys/block/*/size`, `queue/rotational`, `device/model` | — |
| `network_hardware_info` | `/sys/class/net/*/speed`, `operstate`, `duplex` | — |
| `hardware_info` | `/sys/class/dmi/id/sys_vendor`, `product_name` | — |

> **`dmidecode` note:** Install with `apt install dmidecode` or `yum install dmidecode`. The agent must run as root (or with `CAP_SYS_RAWIO`) for dmidecode to access DMI tables. When unavailable, `memory_hardware_info` (total RAM) is still emitted from `/proc/meminfo`; only the per-DIMM `memory_module_info` metrics are skipped.

### Backup

Metrics from the [yomins-backup](yomins-backup) report file (`/var/lib/yomins/backup/last_run.json`). If the file does not exist the collector emits nothing — this is expected on hosts where `yomins-backup` is not installed.

| Metric | Type | Description |
|--------|------|-------------|
| `yomins_backup_last_status` | Gauge | Status of the last backup run (1 = success, 0 = error) |
| `yomins_backup_last_duration_seconds` | Gauge | Duration of the last backup run in seconds |
| `yomins_backup_last_success_timestamp` | Gauge | Unix timestamp of the last successful backup; omitted if the last run failed |
| `yomins_backup_files_total` | Gauge | Total files processed in the last backup; omitted if the last run failed |
| `yomins_backup_bytes_total` | Gauge | Total bytes processed in the last backup; omitted if the last run failed |

### Agent self-metrics
| Metric | Type | Description |
|--------|------|-------------|
| `agent_push_success_total` | Counter | Successful push operations |
| `agent_push_error_total` | Counter | Failed push operations |
| `agent_last_push_success_timestamp` | Gauge | Unix timestamp of last successful push |
| `agent_collection_duration_seconds` | Gauge | Last collection pass duration |
| `agent_push_duration_seconds` | Gauge | Last push attempt duration |
| `agent_uptime_seconds` | Gauge | Agent process uptime |
| `agent_info` | Gauge | Always 1; labels carry `agent_version`; the final series also includes global/server labels such as `agent_id`, `hostname`, `project_id`, `customer_id` |
| `agent_build_info` | Gauge | Always 1; labels carry `version`, `commit`, `build_date`, `go_version`, `os`, `arch` |
| `agent_collector_error_total` | Counter | Errors per collector (label: `collector`) |

All metrics carry agent-level labels: `agent_id`, `hostname`, `source="yomins_agent"`.

## Security events collected

The event pipeline is Linux-only. All collectors degrade gracefully — a missing file or restricted permission produces a single warning and the collector exits cleanly without blocking the metrics pipeline.

### Event schema

Every event shares a common envelope:

```json
{
  "id": "uuid-v4",
  "timestamp": "2026-04-24T16:10:00Z",
  "type": "auth.login_success",
  "category": "access_event",
  "severity": "info",
  "host": { "hostname": "srv-01", "ip": "10.0.0.10" },
  "agent": { "name": "yomins-agent", "version": "1.0.0" },
  "actor": { "user": "alice", "uid": 1000 },
  "context": { "tty": "pts/0", "remote_ip": "192.168.1.5" },
  "tags": ["auth", "login"]
}
```

Domain-specific payloads (`process`, `network`) are added for relevant event types.

### Severities and categories

| Category | Events |
|---|---|
| `access_event` | All auth events |
| `threat_activity` | `process.suspicious`, `network.scan_detected` |
| `system_check` | Process lifecycle, listening ports, system events |

| Severity | Events |
|---|---|
| `info` | login_success, logout, process.start/stop, network.connection_open |
| `warning` | login_failed, sudo, process.high_cpu/memory, system.reboot/oom_killer |
| `critical` | process.suspicious, network.scan_detected |

### auth.*

| Event | Trigger | Data source |
|---|---|---|
| `auth.login_success` | User logs in via SSH or console | `/var/log/wtmp` (binary utmp) |
| `auth.logout` | SSH or console session ends | `/var/log/wtmp` |
| `auth.login_failed` | Failed authentication attempt | `/var/log/auth.log`, `/var/log/secure`, or systemd journal |
| `auth.sudo` | `sudo` command executed | `/var/log/auth.log`, `/var/log/secure`, or systemd journal |

The wtmp cursor is persisted to `<state-dir>/wtmp_cursor` so events missed during agent downtime are replayed on restart.

For `auth.login_failed` and `auth.sudo` the agent uses the first available source in this order:
1. `--auth-log-path` (default: `/var/log/auth.log`) — used on Debian/Ubuntu with rsyslog/syslog-ng
2. `/var/log/secure` — automatic fallback on RHEL/CentOS/AlmaLinux when `auth.log` is absent
3. systemd journal via `journalctl` — automatic fallback on systems without a syslog file (modern Debian/Ubuntu without rsyslog); requires the service user to be in the `systemd-journal` group (configured automatically by the service unit)

### process.*

| Event | Trigger |
|---|---|
| `process.start` | New process appears after agent startup |
| `process.stop` | A tracked process (one that emitted `process.start`) exits |
| `process.high_cpu` | CPU usage spikes to >3× rolling average **and** >5% absolute |
| `process.high_memory` | Memory usage spikes to >3× rolling average **and** >10% absolute |
| `process.suspicious` | New process cmdline matches a suspicious pattern |

Anomaly detection uses a 5-reading rolling window per process. Repeat alerts are suppressed for 60 s (configurable). Processes present at agent startup form a silent baseline — only post-startup processes generate events.

Default suspicious patterns (configurable via `--suspicious-patterns`):
- `curl ... | sh` / `wget ... | sh`
- `nc -e ...` (netcat with exec)
- `base64 -d ... | sh`
- `/dev/tcp/` (bash TCP redirect)
- `xmrig`, `minerd`, `cpuminer` (crypto miners)
- `bash -i >& /dev/tcp/...` (reverse shell)

### network.*

| Event | Trigger | Data source |
|---|---|---|
| `network.connection_open` | New port appears in LISTEN state | `/proc/net/tcp`, `/proc/net/tcp6` |
| `network.scan_detected` | Total connection count doubles **and** increases by ≥50 | `/proc/net/tcp`, `/proc/net/tcp6` |

Ports in LISTEN state at agent startup are the baseline. Only new ports emit events.

### system.*

| Event | Trigger | Data source |
|---|---|---|
| `system.reboot` | Boot timestamp is newer than the last persisted boot time | gopsutil `BootTime()` + `<state-dir>/last_boot_time` |
| `system.oom_killer` | Kernel OOM killer kills a process | `/dev/kmsg` (requires `CAP_SYSLOG` or root) |

### Docker requirements for event collection

Run the container with these flags to enable host-level event visibility:

```bash
docker run -d \
  --name yomins-agent \
  --pid=host \
  --net=host \
  -v /var/log/wtmp:/var/log/wtmp:ro \
  -v /var/log/auth.log:/var/log/auth.log:ro \
  -v /dev/kmsg:/dev/kmsg:ro \
  ...
```

| Collector | Required flag/mount | Without it |
|---|---|---|
| Auth (login/logout) | `-v /var/log/wtmp:/var/log/wtmp:ro` | Single warning, collector disabled |
| Auth (failed/sudo) | `-v /var/log/auth.log:/var/log/auth.log:ro` | Single warning, collector disabled |
| Process (host PIDs) | `--pid=host` | Container-scoped PIDs only (no error) |
| Network (host sockets) | `--net=host` | Container network namespace only (no error) |
| OOM killer | `-v /dev/kmsg:/dev/kmsg:ro` + `CAP_SYSLOG` | Single warning, collector disabled |
| Reboot detection | None | Works from any namespace |

## Dry-run mode

Use `--dry-run` to collect metrics and print them to stdout without sending anything to the server. No `--server` or `--token` is required. This is useful for verifying what the agent collects on a given host.

```bash
yomins-agent --dry-run                 # collect every 60s (default interval)
yomins-agent --dry-run --interval 5s   # faster, for a quick spot-check
```

Output is grouped by metric prefix and printed on each tick:

```
dry-run mode: collecting every 60s, printing to stdout (Ctrl-C to stop)

=== [2026-03-26 14:30:01] Tick #1 — hostname: myserver ===

[cpu]
  cpu_iowait_percent                                                                1.20
  cpu_usage_percent                                                                42.30

[disk]
  disk_free_bytes{device=/dev/sda1,fstype=ext4,mountpoint=/}              42949672960
  disk_used_bytes{device=/dev/sda1,fstype=ext4,mountpoint=/}              10737418240
  disk_used_percent{device=/dev/sda1,fstype=ext4,mountpoint=/}                  61.40

[memory]
  memory_available_bytes                                                   3421345678
  memory_total_bytes                                                       8589934592
  memory_used_percent                                                           61.40
...
---
```

All other flags (`--disable-filesystems`, `--exclude-mountpoints`, `--hostname-override`, etc.) work normally alongside `--dry-run`. Event collection also runs in dry-run mode — each event is logged as a JSON line to stderr via the standard logger.

## Configuration

Configuration is accepted via CLI flags or environment variables. CLI flags take precedence over environment variables.

| Flag | Environment variable | Default | Description |
|------|---------------------|---------|-------------|
| `--server` | `YOMINS_SERVER` | *(required)* | Ingestion endpoint URL |
| `--token` | `YOMINS_TOKEN` | *(required)* | Project-scoped auth token |
| `--interval` | `YOMINS_INTERVAL` | `60s` | Push interval (e.g. `30s`, `2m`) |
| `--log-level` | `YOMINS_LOG_LEVEL` | `info` | Log level: `debug`, `info`, `warn`, `error` |
| `--hostname-override` | `YOMINS_HOSTNAME_OVERRIDE` | *(auto-detected)* | Override reported hostname |
| `--disable-filesystems` | `YOMINS_DISABLE_FILESYSTEMS` | `false` | Disable disk metrics entirely |
| `--disable-network` | `YOMINS_DISABLE_NETWORK` | `false` | Disable network metrics entirely |
| `--exclude-mountpoints` | `YOMINS_EXCLUDE_MOUNTPOINTS` | *(none)* | Comma-separated mountpoints to skip (e.g. `/proc,/sys,/dev/shm`) |
| `--exclude-interfaces` | `YOMINS_EXCLUDE_INTERFACES` | *(none)* | Comma-separated interfaces to skip (e.g. `docker0,virbr0`); loopback is always excluded |
| `--state-dir` | `YOMINS_STATE_DIR` | `/var/lib/yomins/agent` | Persistent state directory |
| `--disable-auto-upgrade` | `YOMINS_DISABLE_AUTO_UPGRADE` | `false` | Disable automatic self-upgrade |
| `--auto-upgrade-interval` | `YOMINS_AUTO_UPGRADE_INTERVAL` | `24h` | How often to check for a newer version |
| `--disable-kernelcare-info` | `YOMINS_DISABLE_KERNELCARE_INFO` | `false` | Disable KernelCare detection (skip `kernelcare_info` metric) |
| `--virtualization-override` | `YOMINS_VIRTUALIZATION_OVERRIDE` | *(auto-detected)* | Override the detected virtualization type (e.g. `kvm`, `none`) |
| `--disable-events` | `YOMINS_DISABLE_EVENTS` | `false` | Disable all security event collection |
| `--disable-auth-events` | `YOMINS_DISABLE_AUTH_EVENTS` | `false` | Disable auth event collection only |
| `--disable-process-events` | `YOMINS_DISABLE_PROCESS_EVENTS` | `false` | Disable process event collection only |
| `--disable-network-events` | `YOMINS_DISABLE_NETWORK_EVENTS` | `false` | Disable network event collection only |
| `--disable-system-events` | `YOMINS_DISABLE_SYSTEM_EVENTS` | `false` | Disable system event collection only |
| `--event-buffer-size` | `YOMINS_EVENT_BUFFER_SIZE` | `10000` | Maximum number of events held in memory before older events are dropped |
| `--wtmp-path` | `YOMINS_WTMP_PATH` | `/var/log/wtmp` | Path to the wtmp file used for login/logout event collection |
| `--auth-log-path` | `YOMINS_AUTH_LOG_PATH` | `/var/log/auth.log` | Path to the auth log file used for failed-login and sudo events; falls back to `/var/log/secure` then to systemd journal when the file does not exist |
| `--suspicious-patterns` | `YOMINS_SUSPICIOUS_PATTERNS` | *(built-in defaults)* | Comma-separated regex patterns for suspicious process detection; replaces the built-in list |
| `--event-flush-interval` | `YOMINS_EVENT_FLUSH_INTERVAL` | `10s` | How often to flush buffered events to the server |
| `--event-batch-size` | `YOMINS_EVENT_BATCH_SIZE` | `200` | Maximum number of events per HTTP request |
| `--insecure-skip-verify` | — | `false` | Skip TLS verification (**dev only**) |
| `--dry-run` | — | `false` | Print collected metrics to stdout instead of sending to the server; `--server` and `--token` are not required |

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
- On `SIGTERM`/`SIGINT` the agent performs one final collection and push (10 s budget) before exiting, ensuring no metric gap on planned restarts or upgrades.

## Docker

```bash
docker run -d \
  --name yomins-agent \
  --restart unless-stopped \
  --pid=host \
  -v /proc:/host/proc:ro \
  -v /sys:/host/sys:ro \
  -v /:/rootfs:ro \
  -v yomins-agent-state:/var/lib/yomins/agent \
  -e YOMINS_SERVER=https://ingest.yominsops.com \
  -e YOMINS_TOKEN=<PROJECT_TOKEN> \
  yominsops/yomins-agent:latest
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
2. The new binary is staged in the agent's state directory (`/var/lib/yomins/agent/upgrade/`).
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
