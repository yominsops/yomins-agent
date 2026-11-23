#!/bin/sh
# apply-upgrade.sh — run as root by systemd ExecStartPre=+.
#
# Applies a staged upgrade or rolls back a failed one.
# This script is intentionally simple and has no dependencies beyond standard
# POSIX shell utilities (sh, cp, mv, rm, chmod, touch).
#
# Marker files under UPGRADE_DIR:
#   pending   — agent staged a new binary, not yet applied
#   new       — the staged binary
#   backup    — copy of the old binary taken before replacement
#   applied   — upgrade was applied but agent has not yet committed healthy state
#   committed — agent's first successful push after the upgrade (safe to discard backup)
#
# This script always exits 0 on soft failures so that ExecStart still runs; it
# exits 1 only right after installing a new service unit, to be restarted under it.
# Only truly unrecoverable states (e.g., backup missing when we need it) log a
# warning and let the system continue with whatever binary is currently installed.

set -eu

UPGRADE_DIR="/var/lib/yomins/agent/upgrade"
BINARY="/usr/local/bin/yomins-agent"
BACKUP="${UPGRADE_DIR}/backup"
PENDING="${UPGRADE_DIR}/pending"
NEW="${UPGRADE_DIR}/new"
APPLIED="${UPGRADE_DIR}/applied"
COMMITTED="${UPGRADE_DIR}/committed"
UNIT="/etc/systemd/system/yomins-agent.service"
HELPER="/usr/local/lib/yomins-agent/apply-upgrade.sh"
RELEASES="https://github.com/yominsops/yomins-agent/releases/download"

log() {
    echo "apply-upgrade: $*" >&2
}

# refresh_unit VERSION — installs the service unit and this helper of VERSION
# when the unit differs from the installed one (v1.2.0, for one, added the
# capability to read logs). Both are fetched here, as root, straight from the
# release: never from the upgrade directory, which the unprivileged agent can
# write. Returns 0 only when the unit changed.
refresh_unit() {
    version="$1"
    if ! printf '%s' "$version" | grep -Eq '^v[0-9]+\.[0-9]+\.[0-9]+$'; then
        log "unit refresh: unexpected version '$version', skipped"
        return 1
    fi
    if ! command -v curl >/dev/null 2>&1; then
        log "unit refresh: no curl, skipped"
        return 1
    fi
    tmp=$(mktemp -d) || return 1
    if ! curl -fsSL --max-time 20 "${RELEASES}/${version}/yomins-agent.service" -o "${tmp}/unit" ||
        ! curl -fsSL --max-time 20 "${RELEASES}/${version}/apply-upgrade.sh" -o "${tmp}/helper"; then
        log "unit refresh: download failed, keeping the current unit"
        rm -rf "$tmp"
        return 1
    fi
    if ! grep -q '^ExecStart=/usr/local/bin/yomins-agent' "${tmp}/unit" || ! head -n 1 "${tmp}/helper" | grep -q '^#!/bin/sh'; then
        log "unit refresh: unexpected files in ${version}, skipped"
        rm -rf "$tmp"
        return 1
    fi

    # Only the supplementary groups this system has: a missing one fails the start.
    groups=""
    for g in systemd-journal adm shadow; do
        if getent group "$g" >/dev/null 2>&1; then
            groups="${groups:+$groups }$g"
        fi
    done
    awk -v groups="$groups" '
        /^SupplementaryGroups=/ { if (!done && groups != "") print "SupplementaryGroups=" groups; done = 1; next }
        { print }
    ' "${tmp}/unit" >"${tmp}/unit.final"

    cp "${tmp}/helper" "${HELPER}.new"
    chmod 755 "${HELPER}.new"
    mv "${HELPER}.new" "$HELPER"

    if cmp -s "${tmp}/unit.final" "$UNIT"; then
        rm -rf "$tmp"
        return 1
    fi
    cp "${tmp}/unit.final" "${UNIT}.new"
    chmod 644 "${UNIT}.new"
    mv "${UNIT}.new" "$UNIT"
    if command -v restorecon >/dev/null 2>&1; then restorecon "$UNIT" || true; fi
    systemctl daemon-reload
    rm -rf "$tmp"
    log "unit refresh: service unit of ${version} installed"
    return 0
}

# install_timer VERSION NAME MODE — installs a root timer of VERSION
# (yomins-agent-NAME.service and .timer, running `yomins-agent MODE`) and
# starts it: smart (disk health, smart-scan) and restart (services running
# replaced code, restart-scan). Run after the new binary is in place, so the
# timer never starts an older binary that lacks the mode. Like the unit,
# fetched as root from the release. A failure only leaves that part
# unreported; a release without the timer (older than it) is skipped.
install_timer() {
    version="$1" name="$2" mode="$3"
    printf '%s' "$version" | grep -Eq '^v[0-9]+\.[0-9]+\.[0-9]+$' || return 0
    command -v curl >/dev/null 2>&1 || return 0
    tmp=$(mktemp -d) || return 0
    if ! curl -fsSL --max-time 20 "${RELEASES}/${version}/yomins-agent-${name}.service" -o "${tmp}/service" ||
        ! curl -fsSL --max-time 20 "${RELEASES}/${version}/yomins-agent-${name}.timer" -o "${tmp}/timer"; then
        log "${name} timer: download failed, skipped"
        rm -rf "$tmp"
        return 0
    fi
    if ! grep -q "^ExecStart=/usr/local/bin/yomins-agent ${mode}" "${tmp}/service" || ! grep -q '^\[Timer\]' "${tmp}/timer"; then
        log "${name} timer: unexpected files in ${version}, skipped"
        rm -rf "$tmp"
        return 0
    fi
    changed=0
    for f in service timer; do
        dst="/etc/systemd/system/yomins-agent-${name}.${f}"
        if ! cmp -s "${tmp}/${f}" "$dst"; then
            cp "${tmp}/${f}" "${dst}.new"
            chmod 644 "${dst}.new"
            mv "${dst}.new" "$dst"
            if command -v restorecon >/dev/null 2>&1; then restorecon "$dst" || true; fi
            changed=1
        fi
    done
    rm -rf "$tmp"
    if [ "$changed" = 1 ]; then
        systemctl daemon-reload
        log "${name} timer: units of ${version} installed"
    fi
    systemctl enable --now "yomins-agent-${name}.timer" >/dev/null 2>&1 || log "${name} timer: could not start"
    return 0
}

# ensure_timers — installs the root timers of the installed binary's release
# once per version. The run that applies an upgrade is still the previous
# helper (refresh_unit replaces this file while it runs), which may not know
# a timer the new release added; the next start, under this helper, installs
# it. The marker only skips a repeat: an older release without a timer is
# tried once.
ensure_timers() {
    v=$("$BINARY" --version 2>/dev/null | awk 'NR == 1 { print $1 }')
    printf '%s' "$v" | grep -Eq '^v[0-9]+\.[0-9]+\.[0-9]+$' || return 0
    mark="${UPGRADE_DIR}/timers-${v}"
    [ -f "$mark" ] && return 0
    for t in smart:smart-scan restart:restart-scan; do
        # Already there: no download at start (an upgrade refreshes them).
        [ -f "/etc/systemd/system/yomins-agent-${t%%:*}.timer" ] && continue
        install_timer "$v" "${t%%:*}" "${t#*:}"
    done
    mkdir -p "$UPGRADE_DIR" 2>/dev/null || return 0
    rm -f "${UPGRADE_DIR}"/timers-v* 2>/dev/null || true
    touch "$mark" 2>/dev/null || true
    return 0
}

ensure_timers

# Fast path: no upgrade activity.
if [ ! -f "$PENDING" ] && [ ! -f "$APPLIED" ] && [ ! -f "$COMMITTED" ]; then
    exit 0
fi

# Rollback path: previous upgrade was applied but the agent never committed
# a healthy state (crashed or exited before its first successful push).
if [ -f "$APPLIED" ] && [ ! -f "$COMMITTED" ]; then
    log "rolling back failed upgrade"
    if [ -f "$BACKUP" ]; then
        # Write to a temp path on the same filesystem, then rename atomically.
        cp "$BACKUP" "${BINARY}.rollback"
        chmod 755 "${BINARY}.rollback"
        mv "${BINARY}.rollback" "$BINARY"
        log "rollback complete"
    else
        log "WARNING: no backup found, cannot roll back — manual intervention required"
    fi
    rm -f "$APPLIED" "$PENDING" "$NEW" "$BACKUP"
    exit 0
fi

# Housekeeping: upgrade was committed successfully on the previous run.
if [ -f "$COMMITTED" ]; then
    rm -f "$APPLIED" "$COMMITTED" "$BACKUP"
fi

# Apply path: staged upgrade is waiting to be installed.
if [ -f "$PENDING" ]; then
    if [ ! -f "$NEW" ]; then
        log "pending marker exists but staged binary is missing — skipping"
        rm -f "$PENDING"
        exit 0
    fi

    version=$(cat "$PENDING" 2>/dev/null || echo unknown)

    # A new unit first. The start fails on purpose and systemd starts the
    # service again (Restart=always) under the new unit; that run finds the
    # unit current and applies the binary. Nothing is applied yet, so the
    # failed start is not mistaken for a crashed upgrade.
    if refresh_unit "$version"; then
        log "restarting under the new unit"
        exit 1
    fi

    log "applying upgrade (pending=${version})"

    # Back up the current binary before touching it.
    cp "$BINARY" "$BACKUP"

    # NEW is on /var/lib/yomins-agent (potentially a different filesystem from
    # /usr/local/bin), so cp+mv is used instead of a direct mv to keep the
    # final rename atomic on the target filesystem.
    cp "$NEW" "${BINARY}.new"
    chmod 755 "${BINARY}.new"
    mv "${BINARY}.new" "$BINARY"

    rm -f "$PENDING" "$NEW"
    touch "$APPLIED"

    install_timer "$version" smart smart-scan
    install_timer "$version" restart restart-scan

    log "upgrade applied, binary replaced — waiting for agent to commit"
fi
