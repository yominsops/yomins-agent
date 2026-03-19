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
| `--token` | *(required)* | Project-scoped auth token |
| `--server` | `https://ingest.yominsops.com` | Ingestion endpoint URL |
| `--interval` | `60s` | Push interval (e.g. `30s`, `2m`) |
| `--version` | latest | Pin to a specific release |
| `--yes` | — | Skip confirmation prompt |

The script requires HTTPS for `--server` and will refuse plain `http://` URLs.

---

## Option 2 — Manual systemd (bare-metal and VMs)

**1. Download the binary**

```bash
curl -fsSL https://github.com/yominsops/agent/releases/latest/download/yomins-agent-linux-amd64 \
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
curl -fsSL https://raw.githubusercontent.com/yominsops/agent/main/systemd/yomins-agent.service \
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
  -v yomins-agent-state:/var/lib/yomins-agent \
  -e YOMINS_SERVER=https://ingest.yominsops.com \
  -e YOMINS_TOKEN=<YOUR_PROJECT_TOKEN> \
  ghcr.io/yominsops/agent:latest
```

The named volume `yomins-agent-state` preserves the agent's identity across restarts.

---

## Option 4 — Docker Compose

```yaml
services:
  yomins-agent:
    image: ghcr.io/yominsops/agent:latest
    restart: unless-stopped
    pid: host
    volumes:
      - /proc:/host/proc:ro
      - /sys:/host/sys:ro
      - /:/rootfs:ro
      - yomins-agent-state:/var/lib/yomins-agent
    environment:
      YOMINS_SERVER: https://ingest.yominsops.com
      YOMINS_TOKEN: <YOUR_PROJECT_TOKEN>

volumes:
  yomins-agent-state:
```

---

## Uninstall

**systemd:**
```bash
systemctl disable --now yomins-agent
rm /etc/systemd/system/yomins-agent.service
rm /usr/local/bin/yomins-agent
rm -rf /etc/yomins-agent /var/lib/yomins-agent
userdel yomins-agent
systemctl daemon-reload
```

**Docker:**
```bash
docker rm -f yomins-agent
docker volume rm yomins-agent-state
```
