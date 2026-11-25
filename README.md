# Yomins Agent

A lightweight Go agent that collects host-level system metrics, security events and logs, then pushes them to the Yomins monitoring stack. The agent requires no inbound ports and no SSH access — it pushes outbound over HTTPS.

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

## Supported distributions

The service install (install.sh, systemd) is tested end to end on every pull request (`test/distro/`, CI job `distro`): the agent is installed in a container booted with systemd and has to report SSH logins with and without a terminal, failed logins (passwords and a rejected key), brute force, sudo, a new user, an edited `sshd_config`, an added key, cron job and sudoers drop-in, a new listening port, the security posture metrics, pending updates and the last update time.

| Family | Tested | Package manager | sshd and sudo messages |
|---|---|---|---|
| Debian | 12, 13 | apt | journal (no rsyslog by default) |
| Ubuntu | 22.04, 24.04, 25.10, 26.04 | apt | journal (also in `auth.log`) |
| AlmaLinux, Rocky Linux | 8, 9, 10 / 9 | dnf 4 | journal (also in `secure`) |
| Fedora | 43 | dnf 5 | journal |
| Amazon Linux | 2023 | dnf 4 | journal |
| openSUSE Leap | 15.6 | zypper | journal |

Oracle Linux, CentOS Stream and CloudLinux 8+ are RHEL rebuilds and take the same paths; CloudLinux 7 and CentOS 7 (yum, kernel 3.10) report pending updates without the security count and have no pressure (PSI) metrics. Run one locally with `test/distro/run.sh almalinux:9 almalinux yes` (needs Docker, Go, python3).

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

### Network (per interface, label: `interface`; only physical-style interfaces included by default)
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
| `system_last_*_update_timestamp` | `/var/log/dpkg.log{,.1}` on Debian/Ubuntu, or the times of `/var/lib/dpkg/info/*.list` once the log has rotated | — |
| `system_last_*_update_timestamp` | `rpm -qa --qf '%{INSTALLTIME}'` on RPM distributions (RHEL and rebuilds, Fedora, Amazon Linux, SUSE, CloudLinux); kernel = `kernel`, `kernel-core`, `kernel-default`, `kernel-uek` | `rpm` |
| `kernelcare_info` | `kcarectl --version` | `kcarectl` (KernelCare agent; omitted if not installed) |
| `cpu_info` | `/proc/cpuinfo` via gopsutil | — |
| `memory_hardware_info` — total | `/proc/meminfo` | — |
| `memory_module_info` — per DIMM | `dmidecode --type 17` | **`dmidecode`** (must be installed; usually requires root) |
| `disk_hardware_info` | `/sys/block/*/size`, `queue/rotational`, `device/model` | — |
| `network_hardware_info` | `/sys/class/net/*/speed`, `operstate`, `duplex` | — |
| `hardware_info` | `/sys/class/dmi/id/sys_vendor`, `product_name` | — |

> **`dmidecode` note:** Install with `apt install dmidecode` or `yum install dmidecode`. The agent must run as root (or with `CAP_SYS_RAWIO`) for dmidecode to access DMI tables. When unavailable, `memory_hardware_info` (total RAM) is still emitted from `/proc/meminfo`; only the per-DIMM `memory_module_info` metrics are skipped.

### Host health (Linux)

Read from `/proc` and `/sys` on every push, except where noted.

| Metric | Type | Description |
|--------|------|-------------|
| `disk_reads_completed_total`, `disk_writes_completed_total` | Counter | I/O operations per device (`device`: whole disks, md, dm) |
| `disk_read_bytes_total`, `disk_written_bytes_total` | Counter | Bytes read and written |
| `disk_read_time_seconds_total`, `disk_write_time_seconds_total` | Counter | Time spent on reads / writes (latency = rate of time / rate of ops) |
| `disk_io_time_seconds_total` | Counter | Time the device was busy; its rate is the utilisation |
| `disk_io_time_weighted_seconds_total`, `disk_io_now` | Counter, Gauge | Queue depth |
| `pressure_stalled_seconds_total`, `pressure_stalled_percent` | Counter, Gauge | PSI: time tasks waited for `resource` (cpu, memory, io), `kind` some/full |
| `memory_cached_bytes`, `memory_buffers_bytes`, `memory_dirty_bytes`, `memory_writeback_bytes`, `memory_shared_bytes`, `memory_slab_*_bytes`, `memory_committed_bytes`, `memory_commit_limit_bytes` | Gauge | Memory by kind |
| `memory_major_page_faults_total`, `memory_swap_in_pages_total`, `memory_swap_out_pages_total`, `memory_oom_kills_total` | Counter | Paging and OOM kills |
| `system_processes{state}` | Gauge | Processes by state: running, sleeping, blocked (I/O), zombie |
| `system_context_switches_total`, `system_interrupts_total`, `system_forks_total` | Counter | Scheduler activity |
| `system_open_files`, `system_open_files_limit` | Gauge | File handles vs `fs.file-max` |
| `network_conntrack_entries`, `network_conntrack_limit` | Gauge | Connection tracking table (full = dropped packets) |
| `tcp_retransmitted_segments_total`, `tcp_listen_overflows_total`, `tcp_listen_drops_total`, `tcp_established_resets_total`, `tcp_timeouts_total`, `tcp_syncookies_sent_total`, `udp_receive_buffer_errors_total`, … | Counter | TCP/UDP trouble counters |
| `tcp_connections{state}` | Gauge | TCP sockets by state |
| `filesystem_readonly{mountpoint,device,fstype}` | Gauge | 1 when remounted read-only (disk errors) |
| `time_synced`, `time_offset_seconds`, `time_estimated_error_seconds` | Gauge | Clock synchronisation |
| `systemd_units_failed`, `systemd_unit_failed{unit}`, `systemd_system_degraded` | Gauge | Failed units |
| `systemd_service_active{unit,state}`, `systemd_service_restarts_total{unit}` | Gauge, Counter | The usual services (web, PHP, databases, mail, Docker, SSH, cron) |
| `process_group_cpu_percent`, `process_group_memory_bytes`, `process_group_count` | Gauge | Top 10 process names by CPU and by memory (`process`) |
| `system_updates_pending{kind}`, `system_reboot_required` | Gauge | Every 6 h: pending updates (all / security) from the package manager's cache — apt, dnf 4/5, zypper, yum (no `security` on yum); reboot needed: `/run/reboot-required`, a newer kernel in `/boot`, `dnf needs-restarting -r`, `zypper needs-rebooting`. Omitted when the package manager does not answer |
| `system_updates_pending{kind="third_party"}`, `system_updates_held{kind}` | Gauge | apt only. `third_party`: updates from repositories outside Debian/Ubuntu (packages.sury.org, Docker CE…), which no `-security` label marks. `system_updates_held` (`all` / `security`): updates of packages held with `apt-mark hold`, which unattended-upgrades never installs and `kind=all`/`security` leave out (an `apt-get -s --ignore-hold` simulation) |
| `tls_certificate_expiry_timestamp_seconds{path,subject,issuer}` | Gauge | Hourly: certbot certificates and those nginx, Apache, Dovecot, Exim, Postfix are configured with |

### Hardware health (Linux)

On every push, from files any user can read. A virtual machine has little or none of it, and those metrics are absent.

| Metric | Description | Source |
|---|---|---|
| `raid_array_active`, `raid_array_disks`, `raid_array_degraded_disks`, `raid_array_failed_disks` (`device`, `level`) | Software RAID: serving I/O; disks it is built for; disks missing (above 0 = no full redundancy; not for raid0/linear); members marked faulty | `/sys/block/md*/md/` |
| `raid_array_sync_action{device,action}`, `raid_array_sync_ratio{device}` | 1 for the current action (`idle`, `resync`, `recover` = rebuild, `check`, `repair`, `reshape`, `frozen`); progress 0–1 while it runs | `sync_action`, `sync_completed` |
| `zfs_pool_state{pool,state}` | 1 for the pool's state: `online`, `degraded`, `faulted`, `offline`, `unavail`, `removed`, `suspended` | `/proc/spl/kstat/zfs/<pool>/state` |
| `memory_ecc_errors_total{controller,type}` | ECC memory errors, `corrected` (a module is failing) and `uncorrected` | EDAC, `/sys/devices/system/edac/mc/mc*/` |
| `hardware_temperature_celsius`, `hardware_temperature_critical_celsius` (`chip`, `device`, `sensor`) | Sensor temperatures (CPU packages and cores, board, NVMe, disks with `drivetemp`) and their critical point (`_crit`, else `_max`) | `/sys/class/hwmon/*/temp*_input` |
| `hardware_fan_rpm{chip,device,sensor}` | Fan speed | `/sys/class/hwmon/*/fan*_input` |
| `cpu_thermal_throttle_events_total` | Times CPU cores slowed down because they were too hot | `/sys/devices/system/cpu/cpu*/thermal_throttle/` |

#### Disk health (SMART)

Reading SMART needs root, which the agent does not have. `install.sh` (and the self-upgrade, from this version on) installs a separate root timer, `yomins-agent-smart.timer`: hourly, it runs `yomins-agent smart-scan`, which runs only `smartctl --scan-open` and `smartctl --json --all --nocheck=standby` (sleeping disks are not woken) and writes `/var/lib/yomins/agent/smart.json`. The service has no network, no config and no token, and only the capabilities `smartctl` needs (`CAP_SYS_RAWIO`, `CAP_SYS_ADMIN`, `CAP_DAC_OVERRIDE` to write the report, `CAP_MKNOD` for MegaRAID). It needs `smartmontools` (7.0+, for JSON); without it the agent reports `smart_smartctl_installed 0`. Disks behind a MegaRAID or other controller are read when `smartctl --scan-open` lists them.

| Metric | Description |
|---|---|
| `smart_smartctl_installed`, `smart_scan_ok`, `smart_scan_timestamp_seconds` | smartmontools present; last scan worked; when it ran. Readings older than 3 h are dropped |
| `smart_device_healthy` (`device`, `type`, `protocol`, `model`, `serial`) | The drive's own verdict: 0 = it expects to fail |
| `smart_device_standby` | The disk was asleep and left so |
| `smart_temperature_celsius`, `smart_power_on_hours` | |
| `smart_attribute{attribute}` | Raw counters: ATA `reallocated_sectors` (5), `reported_uncorrectable` (187), `command_timeouts` (188), `pending_sectors` (197), `offline_uncorrectable` (198), `udma_crc_errors` (199, cable), `failing_now` (attributes below their threshold); NVMe `nvme_critical_warning`, `nvme_percentage_used` (wear), `nvme_available_spare_percent`, `nvme_available_spare_threshold_percent`, `nvme_media_errors`, `nvme_error_log_entries`, `nvme_unsafe_shutdowns`; SCSI/SAS `scsi_grown_defects` |

#### Services to restart

After an update replaces a library or a binary, services started before keep running the old, deleted file until they restart, so the fix is not in effect yet. Finding them means reading other processes' `/proc/<pid>/maps`, which needs ptrace access the agent does not have. `install.sh` and the self-upgrade install a root timer, `yomins-agent-restart.timer`: hourly, it runs `yomins-agent restart-scan`, which reads only `/proc` and writes `/var/lib/yomins/agent/restart.json`. No network, no config, no token; capabilities `CAP_SYS_PTRACE`, `CAP_DAC_READ_SEARCH` and `CAP_DAC_OVERRIDE` (to write the report). A process counts when it maps a deleted file under `/usr`, `/lib`, `/lib64`, `/bin`, `/sbin` or `/opt`; it is attributed to its systemd service from its cgroup. Container processes are skipped (their files come from the image).

| Metric | Description |
|---|---|
| `restart_scan_ok`, `restart_scan_timestamp_seconds` | Last scan worked; when it ran. Readings older than 3 h are dropped |
| `system_services_restart_required` | Number of services running replaced code |
| `system_service_restart_required{unit}` | 1 for each such service (`nginx.service`) |
| `system_processes_restart_required_other` | Such processes outside a service: login sessions, user managers |

#### Software inventory

What runs on the server, for the server page and for matching against vulnerabilities. `install.sh` and the self-upgrade install a root timer, `yomins-agent-inventory.timer`: once a day it runs `yomins-agent inventory-scan`, which only reads and writes `/var/lib/yomins/agent/inventory.json`; the agent sends that report to `POST /v1/push/inventory` (gzip JSON) when it changes and at least daily. No network in the scan itself, no config, no token. Root is needed to read every user's site directory, other processes' executables and the Docker socket; programs asked for their version run as `nobody`, and only root-owned ones that only root can change. `yomins-agent inventory-scan --out -` prints the report.

| Part | What it reports |
|---|---|
| OS | `/etc/os-release`: id, version, codename |
| Packages | Every installed package with its version and source package: dpkg (read from `/var/lib/dpkg/status`) or rpm |
| Services | Programs running in a systemd service (and known ones outside one): name, version, the package they come from, unit, start time of the main process and the ports the service listens on (`/proc/net/{tcp,udp}*` matched to the processes' sockets; `docker-proxy`'s are the containers'). Version from the package, or from the program (`nginx -v`) when it was installed by hand |
| Stopped services | Known software whose unit is enabled but inactive (`stopped`) or failed (`failed`), from `systemctl`. Oneshot units and units that start an interpreter (python, node…) are left out |
| Containers | All containers, stopped ones too (Docker or Podman API, read only): state, health, start time, exit code and stop time of stopped ones, published ports, Compose project (`com.docker.compose.project`), image, the distribution inside, and the versions official images set in their environment (`PHP_VERSION`, `NGINX_VERSION`, …) |
| Programs outside packages | ELF executables in `/usr/local/{bin,sbin}` and `/opt/*/bin` that no package owns |
| Web applications | The core version of CMS and frameworks in the sites' directories (web server document roots, the usual hosting panel places, directories mounted into containers): WordPress, Joomla, Drupal, Magento, Bitrix, OpenCart, PrestaShop, Nextcloud, phpMyAdmin, Roundcube, MediaWiki, Moodle, TYPO3, DLE; Laravel, Symfony, Yii, CodeIgniter, CakePHP, Laminas, Slim from `composer.lock`. No plugins or extensions. Each with the site's domains: `server_name` / `ServerName` / `ServerAlias` of the virtual host whose root is the directory (or its `public/`) — also of a web server running in a container, its roots mapped to the host through the mounts; `set $var …` in the server block is followed (`root $base;`), and an app in a directory of a root (`example.com/blog`) takes the root's names — the hosting panel's directory name (Plesk, Hestia, DirectAdmin, ISPmanager), WordPress `WP_HOME` / `WP_SITEURL` |
| Updates | Packages with a newer version in the repositories, from the package manager's cached data (`apt-get -s dist-upgrade`, `dnf`/`yum check-update`): new version, origin, and whether it is a security update |
| Changelog CVEs | For each service and program from a Debian package on the host: the CVE ids its `changelog.Debian.gz` names (`fixed_cves`). Builds that backport fixes keep the upstream version (sury's PHP 7.4 and 5.6), so the backend uses this list instead of the version for those CVEs |

Each part is a detector (`internal/inventory`); one that fails is named in the report's `errors` and the others still report.

#### Maintenance jobs

On servers whose plan includes maintenance, `install.sh --maintenance` lets the maintenance automation do the work it is asked for in the portal: install updates, restart services, reboot. Nothing is pushed to the server and nothing listens on it:

1. The automation signs a job (a JWT, ES256) with its own key. The installer pins the public half in `/etc/yomins-agent/jobs.pub`.
2. The agent fetches its jobs from the ingest server (`GET /v1/push/jobs`) into `/var/lib/yomins/agent/jobs/inbox`. It never runs them itself.
3. `yomins-agent-jobs.path` starts `yomins-agent-jobs.service` (root), which runs `yomins-agent job-run`: for each job it checks the signature against the pinned key (the agent cannot write it), that the job is for this agent, unexpired and never run before, and only then runs `/usr/local/sbin/yopatch <verb> <args>`.
4. The result lands in `jobs/outbox`; the agent posts it back (`POST /v1/push/jobs/result`).

`yopatch` does one of `plan`, `security` (unattended-upgrade), `upgrade PKG…` (only packages matching `YOPATCH_ALLOW_PACKAGES` in `/etc/yopatch/yopatch.conf`), `fix PKG…` (for a vulnerability: upgrades the installed packages built from these source packages, never held ones, refused if apt would remove a package; reports the services left running old code and whether a reboot is due), `restart UNIT…` (only services the restart scan lists, never `YOPATCH_DENY_UNITS`), `reboot` (in a minute), and logs every call to `/var/log/yopatch.log`. `install.sh --remove-maintenance` takes it all away.

#### CloudLinux

Only on CloudLinux OS, from files (the agent cannot run `lvectl` or `cagefsctl`). Written against the CloudLinux documentation: `/proc/lve/list` is read by its header, so columns that differ between LVE versions are picked up by name.

| Metric | Description | Source |
|---|---|---|
| `cloudlinux_lve_enabled` | LVE limits are on | `LVE_ENABLE` in `/etc/sysconfig/lve` |
| `cloudlinux_lve_accounts` | Accounts with their own LVE | `/proc/lve/list` |
| `cloudlinux_lve_faults_total{limit}` | Times accounts hit a limit, all together: `ep` (entry processes — 508 errors), `mem`, `memphy`/`pmem` (memory — 503 errors), `nproc`, `io`, `iops` — the `f*` columns | `/proc/lve/list` |
| `cloudlinux_lve_accounts_at_limit{limit}` | Accounts that hit the limit since the previous push: how many sites suffer | `/proc/lve/list` |
| `cloudlinux_lve_entry_processes`, `cloudlinux_lve_processes` | Entry processes and processes of all accounts | `EP`, `NPROC` columns |
| `cloudlinux_cagefs_initialized`, `cloudlinux_cagefs_listed_users{list}` | The CageFS skeleton exists; accounts in `/etc/cagefs/users.disabled` (the exceptions in "Enable All" mode) and `users.enabled` (the only ones in "Disable All" mode) | `/usr/share/cagefs-skeleton`, `/etc/cagefs/` |

KernelCare is `kernelcare_info`; `lvestats`, `db_governor`, `imunify360`, `alt-php*` and `ea-php*` are in `systemd_service_active`.

### Security posture (Linux)

Every 5 minutes. A metric is left out where its subject does not exist on the host (no SELinux on Debian, no ufw on RHEL), so `0` always means "there and off".

| Metric | Description | Source |
|---|---|---|
| `security_selinux_mode{mode}` | 1 for the current mode: `enforcing`, `permissive`, `disabled` | `/sys/fs/selinux/enforce`, `/etc/selinux/config` |
| `security_apparmor_enabled`, `security_apparmor_profiles{mode}` | AppArmor on; loaded profiles by `enforce` / `complain` | `/sys/module/apparmor`, `/sys/kernel/security/apparmor/profiles` |
| `security_firewall_active{tool}`, `security_firewall_enabled` | Each firewall found (`firewalld`, `ufw`, `nftables`, `iptables`, `iptables-persistent`, `csf`), and whether any is on | systemd units; `ENABLED=` in `/etc/ufw/ufw.conf`; lfd for CSF |
| `security_auditd_active` | The audit daemon runs | `auditd.service` |
| `security_auto_updates_enabled{method}` | Security updates install by themselves: `unattended-upgrades` (APT::Periodic::Unattended-Upgrade), `dnf-automatic` (an enabled timer that applies updates) | apt.conf.d, dnf automatic.conf |
| `security_kernel_livepatches` | Kernel live patches loaded (kpatch, Canonical Livepatch, kGraft; KernelCare is `kernelcare_info`) | `/sys/kernel/livepatch` |
| `security_ssh_option{option,value}` | Effective `permitrootlogin`, `passwordauthentication`, `kbdinteractiveauthentication`, `pubkeyauthentication`, `permitemptypasswords`, `x11forwarding` outside Match blocks — first value wins, `Include` read in place, OpenSSH's default when unset | `/etc/ssh/sshd_config` and its includes |
| `security_accounts{kind}` | `uid0_extra`: accounts besides root with UID 0; `empty_password`: accounts with an empty password field | `/etc/passwd`, `/etc/shadow` |
| `security_privileged_users{group}` | Members of `sudo`, `wheel`, `admin` (listed and by primary group) | `/etc/group`, `/etc/passwd` |
| `security_ld_preload` | 1 when `/etc/ld.so.preload` names libraries — a common rootkit trick | |
| `security_kernel_tainted` | The kernel's taint flags (non-zero after an out-of-tree or unsigned module, a crash) | `/proc/sys/kernel/tainted` |

### Integrations (Linux)

Each integration finds its service and reports `agent_integration_status{integration,instance,status}` (`ok`, `unconfigured` — the service runs but exposes no statistics, `error`). `YOMINS_DISABLE_INTEGRATIONS=true` turns them off.

| Integration | Metrics | What it needs |
|---|---|---|
| nginx | `nginx_connections_active`, `nginx_connections{state}`, `nginx_connections_accepted_total`, `nginx_connections_handled_total`, `nginx_requests_total` | `stub_status` at `127.0.0.1:8099/nginx_status` (recommended), `127.0.0.1/nginx_status`, `/stub_status`, or `YOMINS_NGINX_STATUS_URL` |
| PHP-FPM | `phpfpm_processes{pool,state}`, `phpfpm_listen_queue`, `phpfpm_max_children_reached_total`, `phpfpm_slow_requests_total`, `phpfpm_accepted_connections_total`, … | `pm.status_path` in the pool; the agent reads it over the pool's socket (FastCGI), so it must be allowed to connect (e.g. member of the socket's group) |
| MySQL / MariaDB | `mysql_up`, `mysql_threads_connected`, `mysql_threads_running`, `mysql_queries_total`, `mysql_commands_total{command}`, `mysql_slow_queries_total`, `mysql_innodb_buffer_pool_*`, `mysql_innodb_row_lock_waits_total`, `mysql_replica_*`, `mysql_database_size_bytes{database}`, … | An account for the agent's OS user over the socket: `CREATE USER 'yomins-agent'@'localhost' IDENTIFIED VIA unix_socket; GRANT SLAVE MONITOR ON *.* TO 'yomins-agent'@'localhost';` (MySQL: `REPLICATION CLIENT`) — it reads no data; database sizes come from the data directory. Or `YOMINS_MYSQL_DSN` |
| Mail queue | `mail_queue_messages{mta,queue}` | Exim or Postfix spool (read with `CAP_DAC_READ_SEARCH`) |
| Local Prometheus | the endpoint's own series, labelled `scrape_target`; `scrape_up` | `YOMINS_SCRAPE_URLS` |
| Access logs (with logs on) | `http_requests_total{vhost,status_class}`, `http_request_duration_seconds` (histogram), `http_response_bytes_total`, and `log_lines_total{log_source,level}` for every log | nginx/apache access logs with a status (and a request time for the histogram) |

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
  "confidence": "high",
  "host": { "hostname": "srv-01", "ip": "10.0.0.10" },
  "agent": { "name": "yomins-agent", "version": "1.0.0" },
  "actor": { "user": "alice", "uid": 1000 },
  "context": { "tty": "pts/0", "remote_ip": "192.168.1.5" },
  "tags": ["auth", "login"]
}
```

`confidence` is present only on threat-activity events (`high`, `medium`, or `low`). It is omitted on audit/info events.

Domain-specific payloads (`process`, `network`) are added for relevant event types.

### Severities and categories

| Category | Events |
|---|---|
| `access_event` | All auth events (`login_success`, `login_failed`, `logout`, `sudo`) |
| `threat_activity` | `auth.bruteforce_detected`, `auth.login_new_ip`, `process.suspicious`, `process.exec_tmp`, `process.reverse_shell`, `network.scan_detected`, `network.suspicious_port`, `system.user_created`, `system.user_deleted`, `system.config_modified`, `system.persistence_changed` |
| `system_check` | Process lifecycle, listening ports, system events, `system.hardware_error` |

| Severity | Events |
|---|---|
| `info` | login_success, logout, process.start/stop, network.connection_open |
| `warning` | login_failed, sudo, process.high_cpu/memory, process.exec_tmp, auth.login_new_ip, network.suspicious_port, system.reboot/oom_killer, system.user_deleted, system.hardware_error (disk I/O, ata, nvme, corrected ECC) |
| `critical` | auth.bruteforce_detected, process.suspicious, process.reverse_shell, network.scan_detected, system.user_created, system.config_modified, system.persistence_changed (authorized_keys, ld.so.preload; others `warning`), system.hardware_error (RAID member failed, filesystem errors, uncorrected ECC, MCE) |

### Counts for alerting

The agent also counts the events it detects and pushes the counts with the metrics as `security_events_total{type}` (every type starts at 0), so alert rules can fire on them: e.g. `increase(security_events_total{type="process.reverse_shell"}[10m]) > 0`.

### auth.*

| Event | Trigger | Data source |
|---|---|---|
| `auth.login_success` | User logs in via SSH (with or without a terminal: `ssh host cmd`, scp, Ansible) or on the console | sshd's `Accepted …` message; console logins from `/var/log/wtmp` |
| `auth.logout` | SSH or console session ends | sshd's `Disconnected from user …` message (with or without PAM); console sessions from `/var/log/wtmp` |
| `auth.login_failed` | Failed authentication attempt (IPv4 and IPv6): each wrong password, a connection of a user that does not exist, and a connection that gave up authenticating as an existing user — on a server that accepts keys only, the only trace a key-guessing client leaves. Each counted once | sshd's messages |
| `auth.sudo` | `sudo` command executed | sudo's messages |
| `auth.bruteforce_detected` | ≥ `--bruteforce-threshold` failed logins from the same IP+user within `--bruteforce-window` | derived from `auth.login_failed` |
| `auth.login_new_ip` | Successful login from an IP not seen before for that user | derived from `auth.login_success`; state persisted in `<state-dir>/auth_last_ip.json` |

The wtmp cursor is persisted to `<state-dir>/wtmp_cursor` so events missed during agent downtime are replayed on restart.

sshd's and sudo's messages are read from:
1. the systemd journal, when the agent can read it (the service unit adds the `systemd-journal` group). Every systemd distribution keeps them there, with or without rsyslog, so this is the default everywhere. It follows sshd under both its names: `sshd`, and `sshd-session`/`sshd-auth` since OpenSSH 9.8 (Debian 13, Ubuntu 25.04+, Fedora 41+, RHEL 9.6+/10 and rebuilds);
2. otherwise the file: `--auth-log-path` (default `/var/log/auth.log`, Debian/Ubuntu), else `/var/log/secure` (RHEL family) — e.g. in a container with the file mounted. A configured `--auth-log-path` is always read as a file.

While sshd's messages are read, wtmp reports only console sessions, so an SSH login is reported once. Debian 13 records logins with wtmpdb (an SQLite database) and no longer writes `/var/log/wtmp`; SSH logins are reported from sshd's messages there too.

### process.*

| Event | Trigger |
|---|---|
| `process.start` | New process appears after agent startup |
| `process.stop` | A tracked process (one that emitted `process.start`) exits |
| `process.high_cpu` | CPU usage spikes to >3× rolling average **and** >5% absolute |
| `process.high_memory` | Memory usage spikes to >3× rolling average **and** >10% absolute |
| `process.suspicious` | New process cmdline matches a suspicious pattern (curl/wget pipe to shell, base64 decode pipe, crypto miners) |
| `process.exec_tmp` | New process binary or cmdline token originates from `/tmp`, `/var/tmp`, or `/dev/shm` |
| `process.reverse_shell` | New process cmdline matches a reverse-shell pattern (`nc -e`, `/dev/tcp/`, `bash -i >&`) |

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
| `network.suspicious_port` | Same trigger as `connection_open`; emitted as a `threat_activity/warning` signal alongside the audit event | `/proc/net/tcp`, `/proc/net/tcp6` |
| `network.scan_detected` | Total connection count doubles **and** increases by ≥50 | `/proc/net/tcp`, `/proc/net/tcp6` |

Ports in LISTEN state at agent startup are the baseline. Only new ports emit events.

### system.*

| Event | Trigger | Data source |
|---|---|---|
| `system.reboot` | Boot timestamp is newer than the last persisted boot time | gopsutil `BootTime()` + `<state-dir>/last_boot_time` |
| `system.oom_killer` | Kernel OOM killer kills a process | `/dev/kmsg` (requires `CAP_SYSLOG` or root) |
| `system.hardware_error` | The kernel logs failing hardware. `tags` carry the kind and device, `context.service` the device, `context.reason` the kernel's message. Kinds: `disk_io` (I/O error, medium error), `ata` (failed command), `nvme` (timeout, controller down), `raid_disk_failed` (md kicked a member out), `filesystem_error` (ext4, XFS, Btrfs), `filesystem_readonly` (ext4 remounted read-only), `memory_ecc` (EDAC CE / UE), `mce` (machine check). At most one per kind and device an hour; the next says how many were held back | `/dev/kmsg` |
| `system.user_created` | A username not present in the snapshot appears in `/etc/passwd` | `/etc/passwd` polled every 30 s; state in `<state-dir>/passwd_snapshot.json` |
| `system.user_deleted` | A username present in the snapshot disappears from `/etc/passwd` | `/etc/passwd` polled every 30 s |
| `system.config_modified` | SHA-256 hash of a monitored file changes, or a drop-in is added, changed or removed | `/etc/passwd`, `/etc/shadow`, `/etc/group`, `/etc/sudoers`, `/etc/ssh/sshd_config`; drop-ins `/etc/sudoers.d/*`, `/etc/ssh/sshd_config.d/*`, `/etc/pam.d/*`, `/etc/security/access.conf` — polled every 30 s |
| `system.persistence_changed` | A file that keeps an intruder in is added, changed or removed. `context.reason` is the path; `tags` carry the kind (`authorized_keys`, `ld_preload`, `cron`, `systemd_unit`, `rc_local`, `shell_profile`) and `added` / `modified` / `removed`; for authorized_keys the actor is the account it lets in | `/root/.ssh/authorized_keys`, `/home/*/.ssh/authorized_keys`; `/etc/ld.so.preload`; `/etc/crontab`, `/etc/cron.{d,hourly,daily,weekly,monthly}/*`, `/var/spool/cron/*` (RHEL), `/var/spool/cron/crontabs/*` (Debian); `/etc/systemd/system/*.{service,timer,socket,path}` and drop-ins; `/etc/rc.local`, `/etc/rc.d/rc.local`; `/etc/profile`, `/etc/profile.d/*`, `/etc/bash.bashrc`, `/etc/bashrc`, `/etc/environment` — polled every 30 s, up to 5000 files |

The drop-ins and persistence files start from what is on the host when the agent (or a version that adds a group) first sees them, and changes made while the agent was stopped are reported when it starts. A change made within 10 minutes of a package database write (dpkg, rpm) — package upgrades rewrite pam.d, cron.daily and profile.d — is still reported, with severity `info`, low confidence and the tag `package_manager`. State is in `<state-dir>/persistence_state.json`.

> **Permissions note:** the service unit grants `CAP_DAC_READ_SEARCH`, which lets the agent read these files whatever their mode — `/etc/shadow` is `000` on the RHEL family, `/etc/ssh/sshd_config` `600`. Without it (an older unit, a container) unreadable files are skipped.

### Docker requirements for event collection

Run the container with these flags to enable host-level event visibility:

```bash
docker run -d \
  --name yomins-agent \
  --pid=host \
  --net=host \
  -v /var/log/wtmp:/var/log/wtmp:ro \
  -v /var/log/auth.log:/var/log/auth.log:ro \
  --device /dev/kmsg:/dev/kmsg:r \
  -v /etc/passwd:/etc/passwd:ro \
  -v /etc/shadow:/etc/shadow:ro \
  -v /etc/group:/etc/group:ro \
  -v /etc/sudoers:/etc/sudoers:ro \
  -v /etc/ssh/sshd_config:/etc/ssh/sshd_config:ro \
  ...
```

| Collector | Required flag/mount | Without it |
|---|---|---|
| Auth (console login/logout) | `-v /var/log/wtmp:/var/log/wtmp:ro` | Single warning, console sessions not reported |
| Auth (SSH logins, failed logins, sudo) | `-v /var/log/auth.log:/var/log/auth.log:ro` (RHEL: `/var/log/secure`). The image has no `journalctl`: on hosts without rsyslog (Debian 12+, Fedora, Amazon Linux 2023) install rsyslog or the agent as a service | Single warning, collector disabled |
| Process (host PIDs) | `--pid=host` | Container-scoped PIDs only (no error) |
| Network (host sockets) | `--net=host` | Container network namespace only (no error) |
| OOM killer | `--device /dev/kmsg:/dev/kmsg:r` + `CAP_SYSLOG` | Single warning, collector disabled |
| Reboot detection | None | Works from any namespace |
| User created/deleted | `-v /etc/passwd:/etc/passwd:ro` | Monitors container's passwd (not host); no error |
| Config file monitoring | `-v /etc/passwd:…:ro`, `-v /etc/shadow:…:ro`, `-v /etc/group:…:ro`, `-v /etc/sudoers:…:ro`, `-v /etc/ssh/sshd_config:…:ro` | Monitors container's files; `/etc/sudoers` silently skipped if absent |

## Logs

Off by default. With `YOMINS_LOGS=auto` the agent finds the logs of the software on the host and ships them to the ingest server (`/v1/push/logs`), where they are stored per project and searched from the portal.

**What is collected.** Discovery looks for the usual files and uses each group only if it exists on the host:

| Source | Files | Parser |
|---|---|---|
| `syslog`, `auth`, `kernel`, `cron` | `/var/log/syslog`, `messages`, `auth.log`, `secure`, `kern.log`, `cron.log` | syslog |
| `audit` | `/var/log/audit/audit.log` (auditd: logins, privilege use, SELinux denials) | plain |
| `packages` | `dpkg.log`, `apt/history.log`, `dnf.log`, `dnf5.log`, `yum.log`, `zypp/history`, unattended-upgrades | plain |
| `firewall` | `/var/log/firewalld` | plain |
| `nginx` | `/var/log/nginx/*access*.log`, `*analytics*.log`, `*error*.log` | nginx access (combined, JSON, yomins `full`) / error |
| `apache` | `/var/log/apache2/*`, `/var/log/httpd/*` | combined / plain |
| `php-fpm` | `/var/log/php*-fpm.log`, `/var/log/php-fpm*/` | PHP |
| `mysql` | `/var/log/mysql/`, `/var/log/mariadb/`, `/var/lib/mysql/*.err`, slow logs | MySQL |
| `postgresql`, `redis`, `mongodb` | their `/var/log/<name>/` | auto / plain / JSON |
| `mail`, `exim`, `dovecot` | `mail.log`, `maillog`, `exim4/*log`, `dovecot*.log` | syslog / plain |
| `ftp`, `fail2ban`, `clamav` | `vsftpd.log`, `xferlog`, `fail2ban.log`, `clamav/` | plain |
| `docker` | `/var/lib/docker/containers/*/*-json.log`; lines carry `container` and `image` | Docker json-file |
| `app` | `/home/*/logs/`, `/var/www/*/logs/`, `/var/log/yomins/` | auto (JSON, syslog or plain) |
| `journal` | the systemd journal, only when no `/var/log/syslog` or `/var/log/messages` exists | journal |

Parsers set the line's own time, a level (`error`, `warn`, `info`, `debug`) and a few fields (status, path, vhost, program…).

**Software in containers.** When a container keeps its logs on the host through a mount (nginx with `./logs:/var/log/nginx`, MariaDB with `./db:/var/lib/mysql`), the agent finds the host side of the mount in Docker's configuration (`/var/lib/docker/containers/*/config.v2.json`, read at startup) and reads the files as above, with the right parser and a `container` field. These host paths join the default allow list; an explicit `YOMINS_LOG_ALLOW` is kept as it is.

**Other places.** Extra globs (`YOMINS_LOG_PATHS`, or "Extra log files" in the portal) may name what they hold: `nginx:/srv/site/logs/*.log` is read with the nginx parsers (`*error*` files as error logs), `php-fpm:`, `mysql:`, `apache:`, `syslog:`, `json:` likewise; another name (`myapp:/opt/app/*.log`) becomes the source with the auto parser, and a bare glob is source `custom`.

**Delivery.** Files are followed like `tail -F`: rotation and truncation are handled. A file's position is saved only after its lines were delivered (`<state-dir>/log_positions.json`), so the files themselves are the buffer: during an outage reading pauses, and nothing is lost on restart. What a file holds when the agent first sees it is not shipped. Batches are gzip-compressed NDJSON, retried until delivered.

**Secrets.** Before sending, the agent masks `password=`/`token=`/`api_key`-style pairs, `Authorization` headers, credentials in URLs and card numbers (Luhn-checked).

**Where it may read.** Only paths matching `YOMINS_LOG_ALLOW` (default: `/var/log/**`, `/home/*/logs/**`, `/home/*/log/**`, `/var/www/**/logs/**`, `/var/www/**/*.log`, `/srv/**/*.log`, `/opt/**/*.log`, Docker container logs, `/var/lib/mysql/*.err` and slow logs). Nothing outside it is read, whatever configuration asks for it.

**Permissions.** Many logs are `root:root 0600`. The service unit grants `CAP_DAC_READ_SEARCH` (read any file, never write) and mounts `/home` read-only. Self-upgrade replaces only the binary, so on hosts installed before logs existed re-run the installer once to get the new unit.

| Metric | Description |
|---|---|
| `agent_logs_lines_total{log_source}` | Lines delivered |
| `agent_logs_bytes_total` | Bytes delivered (before compression) |
| `agent_logs_dropped_total{reason}` | Lines dropped (`refused` by the server, `encode`) |
| `agent_logs_retries_total` | Failed delivery attempts |
| `agent_logs_last_delivery_timestamp` | Last delivered batch |
| `agent_logs_files_watched` | Files followed now |
| `agent_logs_files_denied` | Files found that the agent may not read — the service unit is older than v1.2.0: re-run the installer |
| `agent_logs_files_outside_allow` | Files matched by the configured globs that lie outside `YOMINS_LOG_ALLOW` — skipped; widen the allow list on the host |

## Remote configuration

Admins set the agent's configuration in the portal: a profile (e.g. "LAMP server") assigned to the project, with project- and server-level overrides. The agent fetches it every minute (`GET <server>/config`), saves it in `<state-dir>/remote_config.json`, and restarts to apply a new version (at most once per 2 minutes of uptime). At startup the saved configuration is applied over the environment, so it does not depend on the network.

It can set the push interval, disable collectors, switch logs and integrations on or off, add log paths, excludes and redaction patterns, the nginx status URL and scrape URLs, and switch the event collectors. Local lists are extended, not replaced.

`YOMINS_REMOTE_CONFIG` decides how far it is trusted: `full` (default), `limited` (nothing that chooses what is read — log paths, scrape and status URLs) or `off`. The log allow list (`YOMINS_LOG_ALLOW`) applies whatever the server says. `agent_config_info{version,config_source,mode}` reports what is applied.

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
| `--include-interfaces` | `YOMINS_INCLUDE_INTERFACES` | `eth*,ens*,enp*,eno*,wlan*,wlp*` | Comma-separated glob patterns of interfaces to report. When non-empty, only matching interfaces are included. Set to empty to switch to exclude mode. |
| `--exclude-interfaces` | `YOMINS_EXCLUDE_INTERFACES` | *(built-in: `lo,docker*,veth*,br-*,tun*,wg*`)* | Comma-separated glob patterns of interfaces to skip. Used only when `--include-interfaces` is empty; when in exclude mode, DOWN interfaces are also filtered automatically. |
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
| `--auth-log-path` | `YOMINS_AUTH_LOG_PATH` | `/var/log/auth.log` | Auth log file for SSH and sudo events. By default the systemd journal is read when it can be; this file (then `/var/log/secure`) is the fallback. Set explicitly, the file is read instead of the journal |
| `--suspicious-patterns` | `YOMINS_SUSPICIOUS_PATTERNS` | *(built-in defaults)* | Comma-separated regex patterns for suspicious process detection; replaces the built-in list |
| `--bruteforce-threshold` | `YOMINS_BRUTEFORCE_THRESHOLD` | `5` | Number of failed logins from the same IP+user within the window to trigger `auth.bruteforce_detected` |
| `--bruteforce-window` | `YOMINS_BRUTEFORCE_WINDOW` | `30s` | Sliding time window for counting brute-force attempts |
| `--bruteforce-suppression` | `YOMINS_BRUTEFORCE_SUPPRESSION` | `2m` | Cooldown after a bruteforce event fires before another can be emitted for the same IP+user |
| `--monitor-tmp-paths` | `YOMINS_MONITOR_TMP_PATHS` | `true` | Emit `process.exec_tmp` events for processes launched from `/tmp`, `/var/tmp`, or `/dev/shm` |
| `--monitor-config-files` | `YOMINS_MONITOR_CONFIG_FILES` | `true` | Emit `system.config_modified` when critical config files change |
| `--ignore-private-ip` | `YOMINS_IGNORE_PRIVATE_IP` | `true` | Ignore loopback, RFC-1918, IPv6 unique-local and link-local addresses when tracking `auth.login_new_ip` |
| `--event-flush-interval` | `YOMINS_EVENT_FLUSH_INTERVAL` | `10s` | How often to flush buffered events to the server |
| `--event-batch-size` | `YOMINS_EVENT_BATCH_SIZE` | `200` | Maximum number of events per HTTP request |
| `--logs` | `YOMINS_LOGS` | `off` | Log collection: `off` or `auto` (see [Logs](#logs)) |
| `--log-paths` | `YOMINS_LOG_PATHS` | *(none)* | Comma-separated extra log file globs; `source:/glob` picks the parser (see [Logs](#logs)), a bare glob is read with the auto parser as source `custom` |
| `--log-exclude` | `YOMINS_LOG_EXCLUDE` | *(none)* | Comma-separated globs of log files never to read |
| `--log-allow` | `YOMINS_LOG_ALLOW` | *(see [Logs](#logs))* | Comma-separated globs logs may be read from; `**` spans directories |
| `--remote-config` | `YOMINS_REMOTE_CONFIG` | `full` | Trust in the portal's configuration: `full`, `limited`, `off` (see [Remote configuration](#remote-configuration)) |
| `--disable-integrations` | `YOMINS_DISABLE_INTEGRATIONS` | `false` | Disable the service integrations |
| `--nginx-status-url` | `YOMINS_NGINX_STATUS_URL` | *(tried at local addresses)* | nginx `stub_status` URL |
| `--mysql-dsn` | `YOMINS_MYSQL_DSN` | *(local socket, agent's OS user)* | MySQL DSN (go-sql-driver format) |
| `--scrape-urls` | `YOMINS_SCRAPE_URLS` | *(none)* | Comma-separated local Prometheus endpoints to forward |
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
- 401/403 pause every push (metrics, events, logs) for the server's `Retry-After`, or for 1 min doubling up to 30 min, and are logged once with the server's reason. Events wait in the buffer meanwhile. A 403 with an HTML page and no `X-Yomins-Reason` comes from a proxy in front of the server (Cloudflare's WAF blocking a log line that looks like an attack): only that payload is dropped (logged at most once a minute per path, with the `Cf-Ray`), the rest keeps flowing.
- Bodies are gzip-compressed once the server announces support (`X-Yomins-Accept-Encoding`).
- Push failures are logged and counted in `agent_push_error_total` but do not crash the agent.
- On `SIGTERM`/`SIGINT` the agent performs one final collection and push (10 s budget) before exiting, ensuring no metric gap on planned restarts or upgrades.

## Docker

```bash
docker run -d \
  --name yomins-agent \
  --restart unless-stopped \
  --user root \
  --pid=host \
  --net=host \
  --cap-add CAP_SYSLOG \
  -v /proc:/host/proc:ro \
  -v /sys:/host/sys:ro \
  -v /:/rootfs:ro \
  -v /var/log/wtmp:/var/log/wtmp:ro \
  -v /var/log/auth.log:/var/log/auth.log:ro \
  --device /dev/kmsg:/dev/kmsg:r \
  -v /etc/passwd:/etc/passwd:ro \
  -v /etc/shadow:/etc/shadow:ro \
  -v /etc/group:/etc/group:ro \
  -v /etc/sudoers:/etc/sudoers:ro \
  -v /etc/ssh/sshd_config:/etc/ssh/sshd_config:ro \
  -v yomins-agent-state:/var/lib/yomins/agent \
  -e YOMINS_SERVER=https://ingest.yominsops.com/v1/push \
  -e YOMINS_TOKEN=<PROJECT_TOKEN> \
  yominsops/yomins-agent:latest
```

`--user root` is required for `CAP_SYSLOG` to take effect in the process's effective capability set — without it the kernel rejects `/dev/kmsg` opens even when the capability is added. Given that this container already uses `--pid=host`, `--net=host`, and mounts the host rootfs, the nonroot restriction provides no meaningful security boundary.

On Debian 13 `/var/log/wtmp` is no longer written: drop its mount. SSH events come from `/var/log/auth.log`, which Debian 12+ writes only with rsyslog installed.

The named volume `yomins-agent-state` persists the `agent_id` across container restarts.

### Updating the Docker agent

Pull the new image, then recreate the container:

```bash
docker pull yominsops/yomins-agent:latest
docker stop yomins-agent && docker rm yomins-agent
# re-run the docker run command above
```

The named volume `yomins-agent-state` is preserved by this sequence, so the agent keeps its existing `agent_id`.

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

**Service unit.** Since v1.2.3 the pre-start script also fetches the new version's service unit and itself from the release (as root, from GitHub — never from the state directory, which the agent can write). When the unit differs it is installed, the start fails on purpose and systemd starts the agent again under the new unit; that run applies the binary. Hosts whose helper is older than v1.2.3 (installed before it) re-run the installer once to get it.

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
  transport/            — HTTP transports:
                           transport.go     — metrics push (Prometheus text → ingest /v1/push/metrics)
                           events.go        — event flush (JSON batches → ingest /v1/push/events)
  agent/                — orchestration loop (collect → encode → push)
  upgrade/              — self-upgrade: version check, download, staging, rollback
  smart/                — `smart-scan`: smartctl → smart.json (run by the root timer)
  inventory/            — `inventory-scan`: software detectors → inventory.json (root timer); Sender pushes it
systemd/                — service unit, apply-upgrade.sh helper, root timers (SMART, restart, inventory), job runner
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
