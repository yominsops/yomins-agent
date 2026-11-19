#!/bin/bash
# Runs inside a distribution container booted with systemd (see run.sh).
# Installs the agent with install.sh, then does what the agent must notice:
# SSH logins (with and without a terminal), failed logins, sudo, a new user,
# an edited sshd_config and a new listening port.
#
#   scenario.sh <token> <ingest URL> <rsyslog: yes|no>
set -u
TOKEN=$1 INGEST=$2 RSYSLOG=$3
log() { echo "[scenario] $*"; }

log "packages"
if command -v apt-get >/dev/null; then
  export DEBIAN_FRONTEND=noninteractive
  apt-get update -qq >/dev/null
  apt-get install -y -qq openssh-server openssh-client sudo curl ca-certificates iproute2 procps >/dev/null
  [ "$RSYSLOG" = yes ] && apt-get install -y -qq rsyslog >/dev/null
elif command -v dnf >/dev/null; then
  dnf -y -q install openssh-server openssh-clients sudo curl iproute procps-ng shadow-utils util-linux >/dev/null 2>&1 \
    || dnf -y -q install --allowerasing openssh-server openssh-clients sudo curl iproute procps-ng shadow-utils util-linux >/dev/null
  [ "$RSYSLOG" = yes ] && dnf -y -q install rsyslog >/dev/null
elif command -v zypper >/dev/null; then
  zypper -q -n install openssh-server openssh-clients sudo curl iproute2 procps shadow util-linux >/dev/null
  [ "$RSYSLOG" = yes ] && zypper -q -n install rsyslog >/dev/null
fi
[ "$RSYSLOG" = yes ] && systemctl enable --now rsyslog >/dev/null 2>&1

log "sshd"
mkdir -p /etc/ssh/sshd_config.d
printf 'PasswordAuthentication yes\nKbdInteractiveAuthentication no\nPubkeyAuthentication yes\n' > /etc/ssh/sshd_config.d/00-e2e.conf
grep -q '^Include /etc/ssh/sshd_config.d' /etc/ssh/sshd_config || sed -i '1i Include /etc/ssh/sshd_config.d/*.conf' /etc/ssh/sshd_config
ssh-keygen -A >/dev/null 2>&1
# OpenSSH 9.8+ refuses a source for a while after failed logins
# (PerSourcePenalties); the scenario makes them on purpose from one address.
if sshd -T 2>/dev/null | grep -qi '^persourcepenalties'; then
  echo 'PerSourcePenalties no' >> /etc/ssh/sshd_config.d/00-e2e.conf
fi
systemctl enable --now sshd >/dev/null 2>&1 || systemctl enable --now ssh >/dev/null 2>&1
systemctl restart sshd >/dev/null 2>&1 || systemctl restart ssh >/dev/null 2>&1

id alice >/dev/null 2>&1 || useradd -m -s /bin/bash alice
echo 'alice:E2e-Secret-1' | chpasswd
mkdir -p /etc/sudoers.d && echo 'alice ALL=(ALL) NOPASSWD: ALL' > /etc/sudoers.d/alice && chmod 440 /etc/sudoers.d/alice
install -d -m 700 -o alice -g alice /home/alice/.ssh
ssh-keygen -q -t ed25519 -N '' -f /root/e2e_key
install -m 600 -o alice -g alice /root/e2e_key.pub /home/alice/.ssh/authorized_keys

# In these containers the RHEL family's unix_chkpwd cannot read the account
# ("could not obtain user info"), so PAM's account check refuses every login
# and sudo. That is the container, not the host the agent runs on: let the
# account phase pass.
if [ -x /usr/sbin/unix_chkpwd ] && ! /usr/sbin/unix_chkpwd alice chkexpiry >/dev/null 2>&1; then
  for f in /etc/pam.d/sshd /etc/pam.d/sudo; do sed -i '1i account sufficient pam_permit.so' "$f"; done
fi

log "install.sh"
cd /e2e/repo && bash ./install.sh --binary /e2e/yomins-agent --token "$TOKEN" --server "$INGEST" --allow-http --yes || exit 1
cat >> /etc/yomins-agent/env <<E
YOMINS_INTERVAL=15s
YOMINS_LOGS=auto
YOMINS_DISABLE_AUTO_UPGRADE=true
YOMINS_EVENT_FLUSH_INTERVAL=5s
E
systemctl restart yomins-agent
sleep 20
systemctl is-active yomins-agent || { journalctl -u yomins-agent --no-pager | tail -30; exit 1; }

IP=$(ip -4 -o addr show scope global | awk '{print $4}' | cut -d/ -f1 | head -1)
SSH="ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o ConnectTimeout=5"

log "logins by key, without and with a terminal"
$SSH -i /root/e2e_key -o PasswordAuthentication=no alice@"$IP" 'sudo -n id' </dev/null >/dev/null 2>&1 || log "key login failed"
$SSH -tt -i /root/e2e_key -o PasswordAuthentication=no alice@"$IP" 'sleep 1' </dev/null >/dev/null 2>&1 || log "pty login failed"

log "failed logins: 6 for a user that does not exist, 2 wrong passwords"
printf '#!/bin/sh\necho "$E2E_PW"\n' > /root/askpass && chmod 700 /root/askpass
try() { E2E_PW=$2 DISPLAY=:0 SSH_ASKPASS=/root/askpass SSH_ASKPASS_REQUIRE=force setsid -w \
  $SSH -o PreferredAuthentications=password -o PubkeyAuthentication=no -o NumberOfPasswordPrompts=1 "$1@$IP" true </dev/null >/dev/null 2>&1; }
for _ in 1 2 3 4 5 6; do try intruder wrong; done
for _ in 1 2; do try alice wrong; done

log "user, config, port"
useradd -M e2ebob
echo "# e2e" >> /etc/ssh/sshd_config
/usr/sbin/sshd -p 2222

sleep 35
log "agent journal"
journalctl -u yomins-agent --no-pager -o cat | grep -E 'level=(WARN|ERROR)|auth:|logs: collecting' | head -40
