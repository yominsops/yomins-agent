# Installation

## Prerequisites

- Linux, amd64 or arm64
- A project token obtained from the YominsOps dashboard
- `curl`, `sha256sum`, `systemctl` available on the target host

---

## Option 1 — One-command install (recommended)

The install script handles everything: downloads the correct binary for your architecture, verifies the checksum, creates a system user, writes the config, and starts the systemd service.

```bash
curl -fsSL https://get.yominsops.com/agent | sudo bash -s -- --token <YOUR_PROJECT_TOKEN>
```

**Upgrading an existing install** — the script detects `/etc/yomins-agent/env` and runs in upgrade mode automatically. No arguments needed; the token and config are read from the existing file:

```bash
curl -fsSL https://get.yominsops.com/agent | sudo bash
```

**Additional options:**

```bash
curl -fsSL https://get.yominsops.com/agent | sudo bash -s -- \
  --token  <YOUR_PROJECT_TOKEN> \
  --server https://ingest.yominsops.com \
  --interval 60s \
  --version v1.2.3 \
  --yes
```

| Option | Default | Description |
|--------|---------|-------------|
| `--token` | *(required for fresh installs)* | Project-scoped auth token |
| `--server` | `https://ingest.yominsops.com` | Ingestion endpoint URL |
| `--interval` | `60s` | Push interval (e.g. `30s`, `2m`) |
| `--version` | latest | Pin to a specific release |
| `--yes` | — | Skip confirmation prompt |
| `--uninstall` | — | Remove the agent from this system |

The script requires HTTPS for `--server` and will refuse plain `http://` URLs.

---

## After installing: logs and service statistics

The agent works without anything below; each step adds what it can read.

**Logs.** Off by default. Turn them on for the project in the portal (Admin → project → Agent: "Ship logs", or a profile), or on the host with `YOMINS_LOGS=auto` in `/etc/yomins-agent/env`. Duplicated logs can be left out with `YOMINS_LOG_EXCLUDE` (comma-separated globs), e.g. `/var/log/nginx/*.analytics.log`.

**Agents installed before v1.2.0** must re-run the installer once (`curl -fsSL https://get.yominsops.com/agent | sudo bash`): self-upgrade replaces only the binary, and reading logs needs the new service unit.

**nginx** — a local status page:

```nginx
# /etc/nginx/conf.d/yomins-status.conf
server {
    listen 127.0.0.1:8099;
    location = /nginx_status { stub_status; access_log off; allow 127.0.0.1; deny all; }
}
```

**PHP-FPM** — in every pool, `pm.status_path = /fpm-status`, and let the agent reach the pool's socket: `usermod -aG www-data yomins-agent` (the socket's group), then restart PHP-FPM and the agent.

**MySQL / MariaDB** — an account for the agent's OS user; it reads no data:

```sql
-- MariaDB
CREATE USER 'yomins-agent'@'localhost' IDENTIFIED VIA unix_socket;
GRANT SLAVE MONITOR ON *.* TO 'yomins-agent'@'localhost';
-- MySQL 8: CREATE USER 'yomins-agent'@'localhost' IDENTIFIED WITH auth_socket; GRANT REPLICATION CLIENT ON *.* TO 'yomins-agent'@'localhost';
```

For slow queries in the logs, enable the slow query log (`slow_query_log = 1`, `long_query_time = 1`).

**Mail queue** (Exim, Postfix) needs nothing.

`agent_integration_status{integration,status}` tells, per service, whether the agent reads it (`ok`), finds it without statistics (`unconfigured`) or fails (`error`).

---

## Option 2 — Manual systemd (bare-metal and VMs)

**1. Download the binary**

```bash
curl -fsSL https://github.com/yominsops/yomins-agent/releases/latest/download/yomins-agent-linux-amd64 \
  -o /usr/local/bin/yomins-agent
chmod +x /usr/local/bin/yomins-agent
```

**2. Create a dedicated system user**

```bash
useradd --system --no-create-home --shell /usr/sbin/nologin yomins-agent
```

**3. Write the environment file**

```bash
mkdir -p /etc/yomins-agent
cat > /etc/yomins-agent/env <<EOF
YOMINS_SERVER=https://ingest.yominsops.com
YOMINS_TOKEN=<YOUR_PROJECT_TOKEN>
EOF
chmod 600 /etc/yomins-agent/env
```

**4. Install and start the service**

```bash
curl -fsSL https://raw.githubusercontent.com/yominsops/yomins-agent/main/systemd/yomins-agent.service \
  -o /etc/systemd/system/yomins-agent.service
systemctl daemon-reload
systemctl enable --now yomins-agent
```

**5. Verify**

```bash
systemctl status yomins-agent
journalctl -u yomins-agent -f
```

You should see `push succeeded` log lines within 60 seconds.

---

## Option 3 — Docker

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
  -e YOMINS_TOKEN=<YOUR_PROJECT_TOKEN> \
  yominsops/yomins-agent:latest
```

The named volume `yomins-agent-state` preserves the agent's identity across restarts.

---

## Option 4 — Docker Compose

```yaml
services:
  yomins-agent:
    image: yominsops/yomins-agent:latest
    restart: unless-stopped
    pid: host
    volumes:
      - /proc:/host/proc:ro
      - /sys:/host/sys:ro
      - /:/rootfs:ro
      - yomins-agent-state:/var/lib/yomins/agent
    environment:
      YOMINS_SERVER: https://ingest.yominsops.com
      YOMINS_TOKEN: <YOUR_PROJECT_TOKEN>

volumes:
  yomins-agent-state:
```

---

## Uninstall

**Via the binary (recommended for systemd installs):**

```bash
sudo yomins-agent --uninstall
```

The binary stops the service, removes the service file, config, state, upgrade helper, and the binary itself, then deletes the `yomins-agent` system user.

**Via the install script (e.g. for scripted/CI teardown):**

```bash
curl -fsSL https://get.yominsops.com/agent | sudo bash -s -- --uninstall
# non-interactive:
curl -fsSL https://get.yominsops.com/agent | sudo bash -s -- --uninstall --yes
```

**Manual systemd removal:**
```bash
systemctl disable --now yomins-agent
rm /etc/systemd/system/yomins-agent.service
systemctl daemon-reload
rm /usr/local/bin/yomins-agent
rm -rf /etc/yomins-agent /usr/local/lib/yomins-agent /var/lib/yomins/agent
userdel yomins-agent
```

**Docker:**
```bash
docker rm -f yomins-agent
docker volume rm yomins-agent-state
```
