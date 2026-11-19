# A distribution image with systemd as PID 1, for the agent's end-to-end test.
ARG BASE
FROM ${BASE}
RUN if command -v apt-get >/dev/null; then \
      apt-get update -qq && DEBIAN_FRONTEND=noninteractive apt-get install -y -qq systemd systemd-sysv dbus >/dev/null; \
    elif command -v dnf >/dev/null; then dnf -y -q install systemd procps-ng >/dev/null; \
    elif command -v zypper >/dev/null; then zypper -q -n install systemd systemd-sysvinit >/dev/null; fi
STOPSIGNAL SIGRTMIN+3
CMD ["/sbin/init"]
