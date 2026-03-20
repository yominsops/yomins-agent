#!/usr/bin/env bash
# YominsOps Agent — one-command installer
#
# Usage:
#   curl -fsSL https://get.yominsops.com/agent | sudo bash -s -- --token <TOKEN>
#
# Options:
#   --token <TOKEN>       Project-scoped token (required)
#   --server <URL>        Ingestion endpoint (default: https://ingest.yominsops.com)
#   --interval <DURATION> Push interval, e.g. 30s, 2m (default: 60s)
#   --version <VERSION>   Agent version to install (default: latest)
#   --yes                 Skip confirmation prompt
#   --help                Show this help

set -euo pipefail

# ---------------------------------------------------------------------------
# Defaults
# ---------------------------------------------------------------------------
AGENT_TOKEN=""
AGENT_SERVER="https://ingest.yominsops.com"
AGENT_INTERVAL="60s"
AGENT_VERSION=""            # resolved to latest if empty
SKIP_CONFIRM=false

BINARY_NAME="yomins-agent"
SERVICE_NAME="yomins-agent"
INSTALL_DIR="/usr/local/bin"
CONFIG_DIR="/etc/yomins-agent"
STATE_DIR="/var/lib/yomins-agent"
SYSTEMD_DIR="/etc/systemd/system"
SERVICE_FILE="${SYSTEMD_DIR}/${SERVICE_NAME}.service"
RELEASES_BASE="https://github.com/yominsops/yomins-agent/releases"

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------
RED='\033[0;31m'; YELLOW='\033[1;33m'; GREEN='\033[0;32m'; BOLD='\033[1m'; RESET='\033[0m'

info()    { printf "${BOLD}[yomins-agent]${RESET} %s\n" "$*"; }
success() { printf "${GREEN}[yomins-agent]${RESET} %s\n" "$*"; }
warn()    { printf "${YELLOW}[yomins-agent] WARN:${RESET} %s\n" "$*" >&2; }
die()     { printf "${RED}[yomins-agent] ERROR:${RESET} %s\n" "$*" >&2; exit 1; }

require_cmd() { command -v "$1" >/dev/null 2>&1 || die "Required command not found: $1"; }

# ---------------------------------------------------------------------------
# Argument parsing
# ---------------------------------------------------------------------------
usage() {
    cat <<EOF
Usage: install.sh [OPTIONS]

Options:
  --token <TOKEN>       Project-scoped auth token (required)
  --server <URL>        Ingestion endpoint URL (default: ${AGENT_SERVER})
  --interval <DURATION> Metrics push interval (default: ${AGENT_INTERVAL})
  --version <VERSION>   Agent version to install (default: latest)
  --yes                 Skip confirmation prompt
  --help                Show this help and exit
EOF
}

parse_args() {
    while [[ $# -gt 0 ]]; do
        case "$1" in
            --token)     AGENT_TOKEN="$2";    shift 2 ;;
            --server)    AGENT_SERVER="$2";   shift 2 ;;
            --interval)  AGENT_INTERVAL="$2"; shift 2 ;;
            --version)   AGENT_VERSION="$2";  shift 2 ;;
            --yes|-y)    SKIP_CONFIRM=true;   shift   ;;
            --help|-h)   usage; exit 0 ;;
            *) die "Unknown option: $1. Run with --help for usage." ;;
        esac
    done
}

# ---------------------------------------------------------------------------
# Platform detection
# ---------------------------------------------------------------------------
detect_platform() {
    OS="$(uname -s | tr '[:upper:]' '[:lower:]')"
    ARCH="$(uname -m)"

    case "$OS" in
        linux) ;;
        *) die "Unsupported OS: $OS. Only Linux is supported." ;;
    esac

    case "$ARCH" in
        x86_64)          ARCH_LABEL="amd64" ;;
        aarch64|arm64)   ARCH_LABEL="arm64" ;;
        *) die "Unsupported architecture: $ARCH. Supported: x86_64, aarch64." ;;
    esac

    BINARY_ASSET="${BINARY_NAME}-linux-${ARCH_LABEL}"
}

# ---------------------------------------------------------------------------
# Version resolution
# ---------------------------------------------------------------------------
resolve_version() {
    if [[ -n "$AGENT_VERSION" ]]; then
        return
    fi
    info "Resolving latest release version..."
    require_cmd curl
    local latest_url="${RELEASES_BASE}/latest"
    # Follow redirects; the final URL contains the tag name.
    local final_url
    final_url="$(curl -fsSLI -o /dev/null -w '%{url_effective}' "$latest_url" 2>/dev/null)" \
        || die "Failed to resolve latest version from ${latest_url}"
    AGENT_VERSION="${final_url##*/}"
    [[ "$AGENT_VERSION" =~ ^v[0-9] ]] \
        || die "Could not parse version from URL: ${final_url}"
}

# ---------------------------------------------------------------------------
# Download
# ---------------------------------------------------------------------------
download_binary() {
    local bin_url="${RELEASES_BASE}/download/${AGENT_VERSION}/${BINARY_ASSET}"
    local sha_url="${bin_url}.sha256"
    local tmp_dir
    tmp_dir="$(mktemp -d)"
    trap 'rm -rf "${tmp_dir}"' EXIT

    TMP_BIN="${tmp_dir}/${BINARY_NAME}"
    TMP_SHA="${tmp_dir}/${BINARY_NAME}.sha256"

    info "Downloading ${BINARY_ASSET} ${AGENT_VERSION}..."
    curl -fsSL --progress-bar "$bin_url" -o "$TMP_BIN" \
        || die "Download failed: ${bin_url}"

    info "Verifying checksum..."
    curl -fsSL "$sha_url" -o "$TMP_SHA" \
        || die "Checksum download failed: ${sha_url}"

    # sha256sum expects "<hash>  <filename>" — rewrite path to match.
    local expected_hash
    expected_hash="$(awk '{print $1}' "$TMP_SHA")"
    local actual_hash
    actual_hash="$(sha256sum "$TMP_BIN" | awk '{print $1}')"

    if [[ "$expected_hash" != "$actual_hash" ]]; then
        die "Checksum mismatch!\n  expected: ${expected_hash}\n  got:      ${actual_hash}"
    fi
    success "Checksum OK (sha256: ${actual_hash})"

    chmod +x "$TMP_BIN"
}

# ---------------------------------------------------------------------------
# System user
# ---------------------------------------------------------------------------
ensure_user() {
    if id "$SERVICE_NAME" &>/dev/null; then
        info "System user '${SERVICE_NAME}' already exists."
    else
        info "Creating system user '${SERVICE_NAME}'..."
        useradd --system --no-create-home --shell /usr/sbin/nologin "$SERVICE_NAME"
    fi
}

# ---------------------------------------------------------------------------
# Confirmation prompt
# ---------------------------------------------------------------------------
confirm() {
    if [[ "$SKIP_CONFIRM" == true ]]; then
        return
    fi
    printf "\n"
    printf "${BOLD}Installation summary${RESET}\n"
    printf "  Binary:   %s\n" "${INSTALL_DIR}/${BINARY_NAME}"
    printf "  Config:   %s/env\n" "${CONFIG_DIR}"
    printf "  Service:  %s\n" "${SERVICE_FILE}"
    printf "  Server:   %s\n" "${AGENT_SERVER}"
    printf "  Interval: %s\n" "${AGENT_INTERVAL}"
    printf "  Version:  %s\n" "${AGENT_VERSION}"
    printf "\n"
    read -rp "Proceed with installation? [y/N] " answer
    [[ "$answer" =~ ^[Yy]$ ]] || { info "Installation cancelled."; exit 0; }
}

# ---------------------------------------------------------------------------
# Install
# ---------------------------------------------------------------------------
install_binary() {
    info "Installing binary to ${INSTALL_DIR}/${BINARY_NAME}..."
    install -m 755 "$TMP_BIN" "${INSTALL_DIR}/${BINARY_NAME}"
}

write_config() {
    mkdir -p "$CONFIG_DIR"
    local env_file="${CONFIG_DIR}/env"

    if [[ -f "$env_file" ]]; then
        local backup="${env_file}.bak.$(date +%s)"
        warn "Existing config found — backing up to ${backup}"
        cp "$env_file" "$backup"
    fi

    info "Writing ${env_file}..."
    cat > "$env_file" <<EOF
YOMINS_SERVER=${AGENT_SERVER}
YOMINS_TOKEN=${AGENT_TOKEN}
YOMINS_INTERVAL=${AGENT_INTERVAL}
EOF
    chmod 600 "$env_file"
    chown root:root "$env_file"
}

install_service() {
    info "Installing systemd unit to ${SERVICE_FILE}..."

    # If a local copy of the service file exists (running from the repo), use it.
    local script_dir
    script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
    local local_unit="${script_dir}/systemd/${SERVICE_NAME}.service"

    if [[ -f "$local_unit" ]]; then
        install -m 644 "$local_unit" "$SERVICE_FILE"
    else
        # Download directly from the release.
        local unit_url="${RELEASES_BASE}/download/${AGENT_VERSION}/${SERVICE_NAME}.service"
        curl -fsSL "$unit_url" -o "$SERVICE_FILE" \
            || die "Failed to download service file from ${unit_url}"
        chmod 644 "$SERVICE_FILE"
    fi

    mkdir -p "$STATE_DIR"
    chown "${SERVICE_NAME}:${SERVICE_NAME}" "$STATE_DIR"
    chmod 700 "$STATE_DIR"

    systemctl daemon-reload
    systemctl enable --now "$SERVICE_NAME"
}

# ---------------------------------------------------------------------------
# Post-install verification
# ---------------------------------------------------------------------------
verify_running() {
    info "Waiting for agent to start..."
    local retries=10
    while [[ $retries -gt 0 ]]; do
        if systemctl is-active --quiet "$SERVICE_NAME"; then
            success "Agent is running."
            return
        fi
        sleep 1
        (( retries-- )) || true
    done
    warn "Agent did not start within 10 seconds."
    warn "Check logs with: journalctl -u ${SERVICE_NAME} --no-pager -n 30"
    return 1
}

# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------
main() {
    parse_args "$@"

    # Validate before doing anything.
    [[ "$(id -u)" -eq 0 ]] || die "This script must be run as root (use sudo)."
    [[ -n "$AGENT_TOKEN" ]]  || die "--token is required. Run with --help for usage."
    [[ "$AGENT_SERVER" == https://* ]] \
        || die "--server must use HTTPS. Got: ${AGENT_SERVER}"

    require_cmd curl
    require_cmd sha256sum
    require_cmd systemctl
    require_cmd useradd
    require_cmd install

    detect_platform
    resolve_version
    confirm
    download_binary
    ensure_user
    install_binary
    write_config
    install_service
    verify_running

    printf "\n"
    success "YominsOps agent ${AGENT_VERSION} installed and running."
    info "Logs:   journalctl -u ${SERVICE_NAME} -f"
    info "Status: systemctl status ${SERVICE_NAME}"
}

main "$@"
