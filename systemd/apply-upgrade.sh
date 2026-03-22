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
# This script always exits 0 on soft failures so that ExecStart still runs.
# Only truly unrecoverable states (e.g., backup missing when we need it) log a
# warning and let the system continue with whatever binary is currently installed.

set -eu

UPGRADE_DIR="/var/lib/yomins-agent/upgrade"
BINARY="/usr/local/bin/yomins-agent"
BACKUP="${UPGRADE_DIR}/backup"
PENDING="${UPGRADE_DIR}/pending"
NEW="${UPGRADE_DIR}/new"
APPLIED="${UPGRADE_DIR}/applied"
COMMITTED="${UPGRADE_DIR}/committed"

log() {
    echo "apply-upgrade: $*" >&2
}

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

    log "applying upgrade (pending=$(cat "$PENDING" 2>/dev/null || echo unknown))"

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

    log "upgrade applied, binary replaced — waiting for agent to commit"
fi
