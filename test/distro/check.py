#!/usr/bin/env python3
"""Checks what the agent sent during scenario.sh.

    check.py <dir with metrics/events/logs> <os-release ID>
"""
import json
import re
import sys

d, distro = sys.argv[1], sys.argv[2]
failures = []


def check(ok, what):
    print(("  ok   " if ok else "  FAIL ") + what)
    if not ok:
        failures.append(what)


def read(name):
    try:
        with open(f"{d}/{name}") as f:
            return f.read()
    except FileNotFoundError:
        return ""


metrics = read("metrics")
check(f'distribution="{distro}"' in metrics, f"system_info distribution={distro}")
check(re.search(r"^system_last_software_update_timestamp\S* [1-9]", metrics, re.M) is not None,
      "system_last_software_update_timestamp")
check(re.search(r'^system_updates_pending\{[^}]*kind="all"', metrics, re.M) is not None, "system_updates_pending")
check(re.search(r"^system_reboot_required", metrics, re.M) is not None, "system_reboot_required")

evs = []
for line in read("events").splitlines():
    try:
        o = json.loads(line)
    except ValueError:
        continue
    evs += o if isinstance(o, list) else o.get("events", [o])


def count(typ, pred=lambda e: True):
    return sum(1 for e in evs if e.get("type") == typ and pred(e))


def actor(e):
    return e.get("actor") or {}


# One login without a terminal (only sshd's message has it) and one with a
# terminal (in wtmp too): two events, not three.
n = count("auth.login_success", lambda e: actor(e).get("user") == "alice")
check(n == 2, f"auth.login_success for alice == 2 (got {n})")
n = count("auth.logout", lambda e: actor(e).get("user") == "alice")
check(n >= 1, f"auth.logout for alice >= 1 (got {n})")
# 6 connections as a user that does not exist + 2 wrong passwords + 1
# rejected key, each counted once.
n = count("auth.login_failed")
check(n == 9, f"auth.login_failed == 9 (got {n})")
check(count("auth.bruteforce_detected", lambda e: actor(e).get("user") == "intruder") >= 1, "auth.bruteforce_detected")
check(count("auth.sudo", lambda e: actor(e).get("user") == "alice") >= 1, "auth.sudo by alice")
check(count("system.user_created", lambda e: actor(e).get("user") == "e2ebob"
            or "e2ebob" in json.dumps(e)) >= 1, "system.user_created e2ebob")
check(count("system.config_modified", lambda e: "sshd_config" in json.dumps(e)) >= 1, "system.config_modified sshd_config")
def tagged(*tags):
    return lambda e: all(t in (e.get("tags") or []) for t in tags)


check(count("system.persistence_changed", tagged("authorized_keys", "modified")) >= 1, "system.persistence_changed authorized_keys")
check(count("system.persistence_changed", tagged("cron", "added")) >= 1, "system.persistence_changed cron")
check(count("system.config_modified", tagged("sudoers", "added")) >= 1, "system.config_modified sudoers.d")
check(re.search(r'^security_ssh_option\{[^}]*option="passwordauthentication"[^}]*value="yes"', metrics, re.M) is not None
      or re.search(r'^security_ssh_option\{[^}]*value="yes"[^}]*option="passwordauthentication"', metrics, re.M) is not None,
      "security_ssh_option passwordauthentication=yes")
check(re.search(r'^security_accounts\{[^}]*kind="uid0_extra"', metrics, re.M) is not None, "security_accounts")
check(re.search(r'^security_firewall_enabled', metrics, re.M) is not None, "security_firewall_enabled")
# The root SMART timer wrote its report (a container has no disks with SMART).
check(re.search(r'^smart_smartctl_installed', metrics, re.M) is not None, "smart_smartctl_installed (SMART timer report)")
# The root restart timer read /proc and wrote its report.
check(re.search(r'^restart_scan_ok\{[^}]*\} 1', metrics, re.M) is not None or re.search(r'^restart_scan_ok 1', metrics, re.M) is not None, "restart_scan_ok 1 (restart timer report)")
check(re.search(r'^system_services_restart_required', metrics, re.M) is not None, "system_services_restart_required")
check(count("network.connection_open", lambda e: (e.get("network") or {}).get("local_port") == 2222) >= 1,
      "network.connection_open :2222")

print(f"{len(evs)} events; " + ("all checks passed" if not failures else f"{len(failures)} failed"))
sys.exit(1 if failures else 0)
