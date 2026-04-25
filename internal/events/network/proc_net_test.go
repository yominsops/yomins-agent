//go:build linux

package network

import (
	"os"
	"testing"
)

// sampleTCPContent is a sample /proc/net/tcp file with:
//   - One LISTEN socket on 0.0.0.0:22 (local_address = 00000000:0016, state = 0A)
//   - One ESTABLISHED connection (state = 01)
//   - One TIME_WAIT connection (state = 06)
const sampleTCPContent = `  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode
   0: 00000000:0016 00000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 12345 1 0000000000000000 100 0 0 10 0
   1: 0100007F:0035 00000000:0000 0A 00000000:00000000 00:00000000 00000000   101        0 23456 1 0000000000000000 100 0 0 10 0
   2: 850110AC:B22A C9830D22:0050 01 00000000:00000000 02:000B3F15 00000000  1000        0 34567 4 0000000000000000 20 4 24 10 -1
   3: 850110AC:C41A C9830D22:0050 06 00000000:00000000 00:00000000 00000000  1000        0 45678 0 0000000000000000 0 0 0
`

// sampleTCP6Content is a sample /proc/net/tcp6 file with:
//   - One LISTEN socket on :::80 (state = 0A)
//   - One ESTABLISHED (state = 01)
const sampleTCP6Content = `  sl  local_address                         remote_address                        st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode
   0: 00000000000000000000000001000000:0050 00000000000000000000000000000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 11111 1 0000000000000000 100 0 0 10 0
   1: 00000000000000000000000001000000:0BB8 00000000000000000000000001000000:D0A2 01 00000000:00000000 00:00000000 00000000  1000        0 22222 4 0000000000000000 20 4 24 10 -1
`

func writeTempFile(t *testing.T, content string) string {
	t.Helper()
	f, err := os.CreateTemp(t.TempDir(), "proc_net_tcp*")
	if err != nil {
		t.Fatalf("create temp file: %v", err)
	}
	if _, err := f.WriteString(content); err != nil {
		t.Fatalf("write temp file: %v", err)
	}
	f.Close()
	return f.Name()
}

func TestParseProcNetTCP_ListenOnly(t *testing.T) {
	path := writeTempFile(t, sampleTCPContent)
	listeners, total, err := parseProcNetTCP(path, "tcp")
	if err != nil {
		t.Fatalf("parseProcNetTCP: %v", err)
	}

	// 3 data lines (excluding header)
	if total != 4 {
		t.Errorf("total = %d, want 4", total)
	}

	// 2 LISTEN entries
	if len(listeners) != 2 {
		t.Fatalf("listeners count = %d, want 2", len(listeners))
	}

	// First listener: 0.0.0.0:22
	l0 := listeners[0]
	if l0.Proto != "tcp" {
		t.Errorf("l0.Proto = %q, want tcp", l0.Proto)
	}
	if l0.LocalIP != "0.0.0.0" {
		t.Errorf("l0.LocalIP = %q, want 0.0.0.0", l0.LocalIP)
	}
	if l0.LocalPort != 22 {
		t.Errorf("l0.LocalPort = %d, want 22", l0.LocalPort)
	}

	// Second listener: 127.0.0.1:53 (0100007F = 127.0.0.1, 0035 = 53)
	l1 := listeners[1]
	if l1.LocalIP != "127.0.0.1" {
		t.Errorf("l1.LocalIP = %q, want 127.0.0.1", l1.LocalIP)
	}
	if l1.LocalPort != 53 {
		t.Errorf("l1.LocalPort = %d, want 53", l1.LocalPort)
	}
}

func TestParseProcNetTCP_IPv6(t *testing.T) {
	path := writeTempFile(t, sampleTCP6Content)
	listeners, total, err := parseProcNetTCP(path, "tcp6")
	if err != nil {
		t.Fatalf("parseProcNetTCP: %v", err)
	}

	if total != 2 {
		t.Errorf("total = %d, want 2", total)
	}
	if len(listeners) != 1 {
		t.Fatalf("listeners count = %d, want 1", len(listeners))
	}

	l := listeners[0]
	if l.Proto != "tcp6" {
		t.Errorf("Proto = %q, want tcp6", l.Proto)
	}
	if l.LocalPort != 80 {
		t.Errorf("LocalPort = %d, want 80 (0x0050)", l.LocalPort)
	}
}

func TestParseProcNetTCP_EmptyFile(t *testing.T) {
	path := writeTempFile(t, "  sl  local_address rem_address   st\n")
	listeners, total, err := parseProcNetTCP(path, "tcp")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(listeners) != 0 {
		t.Errorf("listeners count = %d, want 0", len(listeners))
	}
	if total != 0 {
		t.Errorf("total = %d, want 0", total)
	}
}

func TestParseProcNetTCP_FileNotFound(t *testing.T) {
	_, _, err := parseProcNetTCP("/nonexistent/path/tcp", "tcp")
	if err == nil {
		t.Error("expected error for missing file, got nil")
	}
}

func TestParseAddr_IPv4(t *testing.T) {
	cases := []struct {
		hexAddr  string
		wantIP   string
		wantPort uint16
	}{
		{"00000000:0016", "0.0.0.0", 22},
		{"0100007F:0035", "127.0.0.1", 53},
		{"0F02000A:1F90", "10.0.2.15", 8080},
	}
	for _, tc := range cases {
		ip, port, err := parseAddr(tc.hexAddr, false)
		if err != nil {
			t.Errorf("parseAddr(%q) error: %v", tc.hexAddr, err)
			continue
		}
		if ip != tc.wantIP {
			t.Errorf("parseAddr(%q) IP = %q, want %q", tc.hexAddr, ip, tc.wantIP)
		}
		if port != tc.wantPort {
			t.Errorf("parseAddr(%q) port = %d, want %d", tc.hexAddr, port, tc.wantPort)
		}
	}
}

func TestParseAddr_IPv4_LittleEndian(t *testing.T) {
	// C0A80101 in hex = 192.168.1.1 in big-endian, but stored little-endian in /proc.
	// Little-endian stored as bytes: 01 01 A8 C0 → reversed = 192.168.1.1
	ip, port, err := parseAddr("0101A8C0:0050", false)
	if err != nil {
		t.Fatalf("parseAddr: %v", err)
	}
	if ip != "192.168.1.1" {
		t.Errorf("IP = %q, want 192.168.1.1", ip)
	}
	if port != 80 {
		t.Errorf("port = %d, want 80", port)
	}
}

func TestParseAddr_InvalidFormat(t *testing.T) {
	cases := []string{
		"",
		"nocoLon",
		"ZZZZZZZZ:0016",
		"00000000:GGGG",
		"0000:0016", // too short IPv4
	}
	for _, tc := range cases {
		_, _, err := parseAddr(tc, false)
		if err == nil {
			t.Errorf("parseAddr(%q): expected error, got nil", tc)
		}
	}
}

func TestListenEntry_Key(t *testing.T) {
	e := listenEntry{Proto: "tcp", LocalIP: "0.0.0.0", LocalPort: 80}
	got := e.key()
	want := "tcp:0.0.0.0:80"
	if got != want {
		t.Errorf("key() = %q, want %q", got, want)
	}
}

func TestListenEntry_KeyUniqueness(t *testing.T) {
	e1 := listenEntry{Proto: "tcp", LocalIP: "0.0.0.0", LocalPort: 80}
	e2 := listenEntry{Proto: "tcp6", LocalIP: "0.0.0.0", LocalPort: 80}
	e3 := listenEntry{Proto: "tcp", LocalIP: "0.0.0.0", LocalPort: 443}

	keys := map[string]bool{
		e1.key(): true,
		e2.key(): true,
		e3.key(): true,
	}
	if len(keys) != 3 {
		t.Error("key() produced non-unique keys for different listen entries")
	}
}

func TestParseProcNetTCP_MalformedLinesSkipped(t *testing.T) {
	content := "  sl  local_address rem_address   st\nmalformed line without enough fields\n   0: 00000000:0016 00000000:0000 0A 00000000:00000000\n"
	path := writeTempFile(t, content)
	listeners, _, err := parseProcNetTCP(path, "tcp")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	// The valid LISTEN line should be parsed.
	if len(listeners) != 1 {
		t.Errorf("listeners = %d, want 1", len(listeners))
	}
}
