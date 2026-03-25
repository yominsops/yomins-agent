#!/usr/bin/env bash
# YominsOps Agent — one-command installer / upgrader
#
# Fresh install:
#   curl -fsSL https://get.yominsops.com/agent | sudo bash -s -- --token <TOKEN>
#
# Upgrade existing install (token read from /etc/yomins-agent/env):
#   curl -fsSL https://get.yominsops.com/agent | sudo bash
#
# Options:
#   --token <TOKEN>       Project-scoped token (required for fresh installs;
#                         optional when /etc/yomins-agent/env already exists)
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
ALLOW_HTTP=false            # dev/testing only: bypass HTTPS requirement
IS_UPGRADE=false            # set to true when upgrading an existing install

BINARY_NAME="yomins-agent"
SERVICE_NAME="yomins-agent"
INSTALL_DIR="/usr/local/bin"
UPGRADE_LIB_DIR="/usr/local/lib/yomins-agent"
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
  --token <TOKEN>       Project-scoped auth token
                        Required for fresh installs; optional when
                        ${CONFIG_DIR}/env already exists (upgrade mode)
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
            --token)      AGENT_TOKEN="$2";    shift 2 ;;
            --server)     AGENT_SERVER="$2";   shift 2 ;;
            --interval)   AGENT_INTERVAL="$2"; shift 2 ;;
            --version)    AGENT_VERSION="$2";  shift 2 ;;
            --yes|-y)     SKIP_CONFIRM=true;   shift   ;;
            --allow-http) ALLOW_HTTP=true;     shift   ;;
            --help|-h)   usage; exit 0 ;;
            *) die "Unknown option: $1. Run with --help for usage." ;;
        esac
    done
}

# ---------------------------------------------------------------------------
# Existing config detection
# ---------------------------------------------------------------------------
# If --token was not supplied but /etc/yomins-agent/env exists, read the
# current values from it so we can run in upgrade mode (no config rewrite).
load_existing_config() {
    local env_file="${CONFIG_DIR}/env"
    [[ -f "$env_file" ]] || return 1

    # Source only the variables we care about; ignore anything else.
    local line key value
    while IFS= read -r line || [[ -n "$line" ]]; do
        # Strip comments and blank lines.
        [[ "$line" =~ ^[[:space:]]*# ]] && continue
        [[ -z "${line// }" ]] && continue
        key="${line%%=*}"
        value="${line#*=}"
        case "$key" in
            YOMINS_TOKEN)    [[ -z "$AGENT_TOKEN" ]]    && AGENT_TOKEN="$value" ;;
            YOMINS_SERVER)   [[ "$AGENT_SERVER" == "https://ingest.yominsops.com" ]] \
                                 && AGENT_SERVER="$value" ;;
            YOMINS_INTERVAL) [[ "$AGENT_INTERVAL" == "60s" ]] \
                                 && AGENT_INTERVAL="$value" ;;
        esac
    done < "$env_file"
    return 0
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
    if [[ "$IS_UPGRADE" == true ]]; then
        printf "${BOLD}Upgrade summary${RESET}\n"
        printf "  Binary:   %s\n" "${INSTALL_DIR}/${BINARY_NAME}"
        printf "  Service:  %s\n" "${SERVICE_FILE}"
        printf "  Version:  %s\n" "${AGENT_VERSION}"
        printf "  Config:   preserved (${CONFIG_DIR}/env unchanged)\n"
    else
        printf "${BOLD}Installation summary${RESET}\n"
        printf "  Binary:   %s\n" "${INSTALL_DIR}/${BINARY_NAME}"
        printf "  Config:   %s/env\n" "${CONFIG_DIR}"
        printf "  Service:  %s\n" "${SERVICE_FILE}"
        printf "  Server:   %s\n" "${AGENT_SERVER}"
        printf "  Interval: %s\n" "${AGENT_INTERVAL}"
        printf "  Version:  %s\n" "${AGENT_VERSION}"
    fi
    printf "\n"
    local action; [[ "$IS_UPGRADE" == true ]] && action="upgrade" || action="installation"
    local prompt="Proceed with ${action}? [Y/n] "
    if [[ -t 0 ]]; then
        read -rp "$prompt" answer
    elif [[ -e /dev/tty ]]; then
        read -rp "$prompt" answer </dev/tty
    else
        warn "Non-interactive mode — skipping confirmation."
        answer="y"
    fi
    [[ -z "$answer" || "$answer" =~ ^[Yy]$ ]] || { info "Cancelled."; exit 0; }
}

# ---------------------------------------------------------------------------
# Install
# ---------------------------------------------------------------------------
install_binary() {
    info "Installing binary to ${INSTALL_DIR}/${BINARY_NAME}..."
    install -m 755 "$TMP_BIN" "${INSTALL_DIR}/${BINARY_NAME}"
}

write_config() {
    if [[ "$IS_UPGRADE" == true ]]; then
        info "Preserving existing config (${CONFIG_DIR}/env)."
        return
    fi

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

install_upgrade_script() {
    info "Installing upgrade helper script to ${UPGRADE_LIB_DIR}/apply-upgrade.sh..."
    mkdir -p "$UPGRADE_LIB_DIR"

    local script_dir
    script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
    local local_script="${script_dir}/systemd/apply-upgrade.sh"

    if [[ -f "$local_script" ]]; then
        install -m 755 "$local_script" "${UPGRADE_LIB_DIR}/apply-upgrade.sh"
    else
        local script_url="${RELEASES_BASE}/download/${AGENT_VERSION}/apply-upgrade.sh"
        curl -fsSL "$script_url" -o "${UPGRADE_LIB_DIR}/apply-upgrade.sh" \
            || die "Failed to download apply-upgrade.sh from ${script_url}"
        chmod 755 "${UPGRADE_LIB_DIR}/apply-upgrade.sh"
    fi
    chown root:root "${UPGRADE_LIB_DIR}/apply-upgrade.sh"
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

    # Create the upgrade staging directory owned by the service user.
    mkdir -p "${STATE_DIR}/upgrade"
    chown "${SERVICE_NAME}:${SERVICE_NAME}" "${STATE_DIR}/upgrade"
    chmod 700 "${STATE_DIR}/upgrade"

    systemctl daemon-reload
    systemctl enable "$SERVICE_NAME"
    if systemctl is-active --quiet "$SERVICE_NAME"; then
        info "Restarting ${SERVICE_NAME}..."
        systemctl restart "$SERVICE_NAME"
    else
        systemctl start "$SERVICE_NAME"
    fi
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

    [[ "$(id -u)" -eq 0 ]] || die "This script must be run as root (use sudo)."

    # Upgrade mode: --token not supplied but an existing config is present.
    # Load token and other values from the existing env file so they are
    # available for validation and the confirmation summary.
    if [[ -z "$AGENT_TOKEN" ]]; then
        if load_existing_config; then
            IS_UPGRADE=true
            info "Existing installation detected — running in upgrade mode."
        else
            die "--token is required for a fresh install. Run with --help for usage."
        fi
    fi

    [[ -n "$AGENT_TOKEN" ]] \
        || die "Could not read YOMINS_TOKEN from ${CONFIG_DIR}/env. Pass --token explicitly."
    [[ "$IS_UPGRADE" == true ]] \
        || [[ "$AGENT_SERVER" == https://* ]] || [[ "$ALLOW_HTTP" == true ]] \
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
    install_upgrade_script
    write_config
    install_service
    verify_running

    printf "\n"
    if [[ "$IS_UPGRADE" == true ]]; then
        success "YominsOps agent upgraded to ${AGENT_VERSION}."
    else
        success "YominsOps agent ${AGENT_VERSION} installed and running."
    fi
    info "Logs:   journalctl -u ${SERVICE_NAME} -f"
    info "Status: systemctl status ${SERVICE_NAME}"
}

main "$@"
