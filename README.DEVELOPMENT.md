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

**One-command install script** ✓ implemented (`install.sh`)

`install.sh` at the repo root handles the full installation flow:
1. Detects host architecture (amd64 / arm64).
2. Resolves the latest release version or accepts `--version`.
3. Downloads the binary and verifies its SHA-256 checksum.
4. Creates the `yomins-agent` system user.
5. Writes `/etc/yomins-agent/env` from CLI arguments (backs up existing config).
6. Installs and starts the systemd unit.
7. Waits up to 10 seconds and confirms the service is active.

Example invocation:
```bash
curl -fsSL https://get.yominsops.com/agent | sudo bash -s -- --token <TOKEN>
```

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

---

## Server — what needs to be built

The server-side is entirely unimplemented. Below is the full specification.

### Overview

The server receives metric payloads from agents, validates and enriches them, and writes them into Prometheus-compatible storage. The architecture is intentionally simple: a single HTTP service with no stateful complexity beyond a token store.

```
yomins-agent  →  HTTPS POST /ingest  →  Ingestion Service  →  Prometheus remote_write
                  Bearer <token>            ↕
                                       Token Store (DB)
```

### Ingestion endpoint

**Method and path:** `POST /ingest` (or a versioned path like `/v1/push`)

**Authentication:**
- Extract `Authorization: Bearer <token>` from the request header.
- Reject with `401 Unauthorized` if the header is absent or malformed.
- Reject with `401 Unauthorized` if the token is not found or has `status != active`.
- Reject with `403 Forbidden` if `allowed_hostname` is set on the token and does not match the `hostname` label in the payload.

**Request validation:**
- Content-Type must be `text/plain; version=0.0.4` (Prometheus text format).
- Apply a request size limit (e.g. 4 MB) to prevent abuse.
- Parse the body with a Prometheus text parser (e.g. `github.com/prometheus/common/expfmt`).

**Label enrichment:**
After parsing, the service must rewrite the metric families to inject authoritative labels. Agent-provided labels for `project_id` or `customer_id` must be removed if present and replaced with values from the token record.

Labels added server-side:
```
project_id    = token.project_id
customer_id   = token.customer_id   (if set)
environment   = token.environment   (if set)
```

This enrichment must happen before any data is forwarded to storage.

**Response codes:**
| Code | Meaning |
|------|---------|
| `204 No Content` | Accepted and written |
| `400 Bad Request` | Unparseable body |
| `401 Unauthorized` | Missing or invalid token |
| `403 Forbidden` | Token valid but hostname not allowed |
| `413 Payload Too Large` | Body exceeds size limit |
| `429 Too Many Requests` | Rate limit exceeded |
| `500 Internal Server Error` | Storage write failed |

### Token data model

```sql
CREATE TABLE tokens (
    token         TEXT PRIMARY KEY,
    project_id    TEXT NOT NULL,
    customer_id   TEXT,
    environment   TEXT,
    status        TEXT NOT NULL DEFAULT 'active',  -- 'active' | 'revoked'
    description   TEXT,
    allowed_hostname TEXT,
    created_at    TIMESTAMPTZ NOT NULL DEFAULT now(),
    last_seen_at  TIMESTAMPTZ
);
```

`last_seen_at` must be updated on every successful push. This enables "agent last seen" monitoring and detection of stale/dead agents.

Token lookup must be fast. A single indexed lookup by `token` is sufficient. Tokens should be cached in memory (e.g. 30-second TTL) to avoid a database round-trip on every request.

### Prometheus storage integration

After label enrichment, forward the metric families via the Prometheus `remote_write` protocol to a compatible backend (Thanos, Cortex, VictoriaMetrics, Grafana Mimir, or a self-hosted Prometheus with remote write receiver).

**Recommended approach:** convert `dto.MetricFamily` objects to `prompb.WriteRequest` (protobuf) and POST to the backend's `/api/v1/write` endpoint.

Libraries:
- `github.com/prometheus/prometheus/prompb` — WriteRequest type
- `github.com/gogo/protobuf/proto` — encoding (used by Prometheus internally)

Alternatively, for simpler setups: write directly to a Prometheus pushgateway, though this has known limitations with Counter semantics and is not recommended for production scale.

### Security requirements

All of the following are mandatory before exposing the service to the internet:

- **HTTPS only.** The ingestion endpoint must be served over TLS. A valid certificate from a public CA is required. Self-signed certificates are not acceptable for production.
- **No plaintext fallback.** HTTP (port 80) should redirect to HTTPS or return `421 Misdirected Request`. It must never accept metric payloads over plaintext.
- **Token entropy.** Tokens must be generated with a cryptographically secure random source. Minimum 128 bits of entropy (e.g. 32 hex characters or a UUID v4). Tokens must never be stored in plaintext — store only a bcrypt or SHA-256 hash, and compare on lookup.
- **Rate limiting.** Apply per-token and per-IP rate limits to prevent abuse. A token-level limit of 1 request per `interval - 5s` is a reasonable starting point.
- **Token revocation.** Setting `status = 'revoked'` must take effect within one cache TTL (≤ 30 seconds). Provide an admin API or CLI tool for token management.
- **Audit logging.** Log every authenticated push with `token_id` (not the raw token), `project_id`, `source_ip`, `agent_id`, and timestamp. Logs must not contain raw token values.
- **Input validation.** Enforce a maximum number of metric families, labels per metric, and label name/value length to prevent malformed payloads from causing excessive memory allocation.

### Recommended stack

The service is deliberately small. A minimal implementation can be a single Go binary:

```
cmd/ingest-server/main.go
internal/
  tokenstore/     — token lookup, caching, revocation
  ingestion/      — HTTP handler, auth, label enrichment
  forward/        — remote_write client to Prometheus backend
  admin/          — token management API (create, revoke, list)
```

Dependencies: standard library + `github.com/prometheus/common/expfmt` + `github.com/prometheus/prometheus/prompb` + a database driver (PostgreSQL recommended).

### Token lifecycle

```
Dashboard/CLI
  → generate token (32-byte random, store hash + metadata)
  → return raw token to operator (shown once)

Operator
  → configures agent with raw token

Agent
  → sends token in Authorization header on every push

Ingestion service
  → hashes incoming token, looks up hash in DB
  → updates last_seen_at
  → enriches metrics with project labels
  → forwards to Prometheus

Dashboard/CLI
  → revoke: set status = 'revoked'
  → cache invalidated within 30s
  → next push returns 401
```

### Monitoring the server itself

The ingestion service should expose its own Prometheus metrics at `/metrics` (accessible only from internal/monitoring networks, not the public internet):

- `ingest_requests_total{status="2xx|4xx|5xx"}` — request counts by status class
- `ingest_request_duration_seconds` — histogram of handler latency
- `ingest_token_lookups_total{result="hit|miss|revoked"}` — cache/DB lookup outcomes
- `ingest_remote_write_duration_seconds` — histogram of forwarding latency
- `ingest_remote_write_errors_total` — forwarding failures

---

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
| Server | Ingestion HTTP endpoint | High |
| Server | Token validation and enrichment | High |
| Server | Prometheus remote_write forwarding | High |
| Server | Token store (database + cache) | High |
| Server | Rate limiting | High |
| Server | Audit logging | High |
| Server | Admin API for token management | Medium |
| Server | Server self-metrics | Medium |
| Server | arm64 Docker image | Medium |
