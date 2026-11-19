package collector

import (
	"context"
	"strings"
	"testing"

	"github.com/yominsops/yomins-agent/internal/metrics"
)

func postureWith(t *testing.T, files map[string]string, systemctl map[string]string) []metrics.MetricPoint {
	t.Helper()
	c := NewPostureCollector(fixture(t, files))
	c.run = func(_ context.Context, name string, args ...string) ([]byte, error) {
		if name != "systemctl" {
			t.Fatalf("unexpected %s", name)
		}
		var out []string
		for _, u := range args[1:] {
			s, ok := systemctl[args[0]+" "+u]
			if !ok {
				s = "inactive"
			}
			out = append(out, s)
		}
		return []byte(strings.Join(out, "\n") + "\n"), nil
	}
	pts, err := c.Collect(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	return pts
}

// A RHEL host: SELinux enforcing, firewalld and auditd running,
// dnf-automatic installing updates, root login over SSH by key only.
func TestPosture_RHEL(t *testing.T) {
	pts := postureWith(t, map[string]string{
		"sys/fs/selinux/enforce":                       "1",
		"etc/selinux/config":                           "SELINUX=enforcing\n",
		"usr/lib/systemd/system/firewalld.service":     "",
		"usr/lib/systemd/system/auditd.service":        "",
		"usr/lib/systemd/system/dnf-automatic.timer":   "",
		"etc/dnf/automatic.conf":                       "[commands]\napply_updates = yes\n",
		"etc/ssh/sshd_config":                          "Include /etc/ssh/sshd_config.d/*.conf\nPermitRootLogin yes\nMatch User backup\n  PasswordAuthentication no\n",
		"etc/ssh/sshd_config.d/50-redhat.conf":         "PermitRootLogin prohibit-password\nX11Forwarding yes\n",
		"etc/passwd":                                   "root:x:0:0::/root:/bin/bash\ntoor:x:0:0::/root:/bin/bash\nalice:x:1000:1000::/home/alice:/bin/bash\n",
		"etc/shadow":                                   "root:$6$x:1::::::\ntoor::1::::::\nalice:$6$y:1::::::\n",
		"etc/group":                                    "wheel:x:10:alice,bob\nalice:x:1000:\n",
		"proc/sys/kernel/tainted":                      "4096\n",
		"sys/kernel/livepatch/kpatch_5_14_0_1/enabled": "1",
	}, map[string]string{
		"is-active firewalld.service":    "active",
		"is-active auditd.service":       "active",
		"is-enabled dnf-automatic.timer": "enabled",
	})
	checks := []struct {
		name   string
		labels []string
		want   float64
	}{
		{"security_selinux_mode", []string{"mode", "enforcing"}, 1},
		{"security_firewall_active", []string{"tool", "firewalld"}, 1},
		{"security_firewall_enabled", nil, 1},
		{"security_auditd_active", nil, 1},
		{"security_auto_updates_enabled", []string{"method", "dnf-automatic"}, 1},
		{"security_kernel_livepatches", nil, 1},
		// The drop-in comes first (Include is at the top), so it wins; the
		// Match block is not read.
		{"security_ssh_option", []string{"option", "permitrootlogin", "value", "prohibit-password"}, 1},
		{"security_ssh_option", []string{"option", "x11forwarding", "value", "yes"}, 1},
		{"security_ssh_option", []string{"option", "passwordauthentication", "value", "yes"}, 1},
		{"security_accounts", []string{"kind", "uid0_extra"}, 1},
		{"security_accounts", []string{"kind", "empty_password"}, 1},
		{"security_privileged_users", []string{"group", "wheel"}, 2},
		{"security_ld_preload", nil, 0},
		{"security_kernel_tainted", nil, 4096},
	}
	for _, ck := range checks {
		if got := find(t, pts, ck.name, ck.labels...); got != ck.want {
			t.Errorf("%s%v = %v, want %v", ck.name, ck.labels, got, ck.want)
		}
	}
	if has(pts, "security_apparmor_enabled") || has(pts, "security_firewall_active", "tool", "ufw") {
		t.Error("AppArmor and ufw are not on this host")
	}
}

// A Debian/Ubuntu host: AppArmor, ufw switched off, unattended-upgrades on,
// a preload library.
func TestPosture_Debian(t *testing.T) {
	pts := postureWith(t, map[string]string{
		"sys/module/apparmor/parameters/enabled": "Y\n",
		"sys/kernel/security/apparmor/profiles":  "/usr/sbin/sshd (enforce)\nnginx (complain)\n/usr/bin/man (enforce)\n",
		"etc/ufw/ufw.conf":                       "ENABLED=no\n",
		"usr/bin/unattended-upgrade":             "",
		"etc/apt/apt.conf.d/20auto-upgrades":     "APT::Periodic::Update-Package-Lists \"1\";\nAPT::Periodic::Unattended-Upgrade \"1\";\n",
		"etc/ssh/sshd_config":                    "PasswordAuthentication no\n",
		"etc/ld.so.preload":                      "/lib/x86_64-linux-gnu/libprocesshider.so\n",
		"etc/passwd":                             "root:x:0:0::/root:/bin/bash\n",
		"etc/group":                              "sudo:x:27:\n",
	}, nil)
	checks := []struct {
		name   string
		labels []string
		want   float64
	}{
		{"security_apparmor_enabled", nil, 1},
		{"security_apparmor_profiles", []string{"mode", "enforce"}, 2},
		{"security_firewall_active", []string{"tool", "ufw"}, 0},
		{"security_firewall_enabled", nil, 0},
		{"security_auto_updates_enabled", []string{"method", "unattended-upgrades"}, 1},
		{"security_ssh_option", []string{"option", "passwordauthentication", "value", "no"}, 1},
		{"security_ssh_option", []string{"option", "permitrootlogin", "value", "prohibit-password"}, 1},
		{"security_ld_preload", nil, 1},
		{"security_privileged_users", []string{"group", "sudo"}, 0},
	}
	for _, ck := range checks {
		if got := find(t, pts, ck.name, ck.labels...); got != ck.want {
			t.Errorf("%s%v = %v, want %v", ck.name, ck.labels, got, ck.want)
		}
	}
	if has(pts, "security_selinux_mode") || has(pts, "security_auditd_active") || has(pts, "security_accounts", "kind", "empty_password") {
		t.Error("no SELinux, auditd or readable shadow on this host")
	}
}
