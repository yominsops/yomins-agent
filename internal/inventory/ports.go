package inventory

import (
	"encoding/hex"
	"net"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"
)

// maxPorts bounds the ports listed for one component.
const maxPorts = 50

// listeners maps a socket inode to the port it listens on, from the host's
// /proc/net/{tcp,tcp6,udp,udp6}: TCP sockets in LISTEN, UDP sockets bound
// with no peer.
func listeners(e *Env) map[uint64]Port {
	out := map[uint64]Port{}
	for _, f := range []struct{ file, proto string }{
		{"/proc/net/tcp", "tcp"}, {"/proc/net/tcp6", "tcp"}, {"/proc/net/udp", "udp"}, {"/proc/net/udp6", "udp"},
	} {
		b, err := e.ReadFile(f.file, 16<<20)
		if err != nil {
			continue
		}
		parseNetFile(b, f.proto, out)
	}
	return out
}

// parseNetFile reads one /proc/net table:
//
//	sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode
//	 0: 00000000:0050 00000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 12345 …
func parseNetFile(b []byte, proto string, out map[uint64]Port) {
	lines := strings.Split(string(b), "\n")
	for _, line := range lines[1:] {
		f := strings.Fields(line)
		if len(f) < 10 {
			continue
		}
		st := f[3]
		if (proto == "tcp" && st != "0A") || (proto == "udp" && st != "07") {
			continue
		}
		if proto == "udp" && !strings.HasSuffix(f[2], ":0000") {
			continue // a connected UDP socket: a client
		}
		addr, port, ok := parseHexAddr(f[1])
		if !ok || port == 0 {
			continue
		}
		inode, err := strconv.ParseUint(f[9], 10, 64)
		if err != nil || inode == 0 {
			continue
		}
		out[inode] = Port{Proto: proto, Addr: addr, Port: port}
	}
}

// parseHexAddr reads "0100007F:0050" (IPv4) or the 32-digit IPv6 form; the
// address is in the kernel's byte order, 32 bits at a time.
func parseHexAddr(s string) (string, int, bool) {
	a, p, ok := strings.Cut(s, ":")
	if !ok {
		return "", 0, false
	}
	port, err := strconv.ParseUint(p, 16, 16)
	if err != nil {
		return "", 0, false
	}
	raw, err := hex.DecodeString(a)
	if err != nil || (len(raw) != 4 && len(raw) != 16) {
		return "", 0, false
	}
	ip := make(net.IP, len(raw))
	for i := 0; i < len(raw); i += 4 {
		ip[i], ip[i+1], ip[i+2], ip[i+3] = raw[i+3], raw[i+2], raw[i+1], raw[i]
	}
	if v4 := ip.To4(); v4 != nil && len(raw) == 16 && !ip.Equal(net.IPv6zero) {
		ip = v4 // ::ffff:127.0.0.1
	}
	return ip.String(), int(port), true
}

// socketInodes are the sockets a process holds open.
func socketInodes(e *Env, pid int) []uint64 {
	dir := e.Path(filepath.Join("/proc", strconv.Itoa(pid), "fd"))
	fds, err := os.ReadDir(dir)
	if err != nil {
		return nil
	}
	var out []uint64
	for _, fd := range fds {
		l, err := os.Readlink(filepath.Join(dir, fd.Name()))
		if err != nil {
			continue
		}
		if n, ok := strings.CutPrefix(l, "socket:["); ok {
			if v, err := strconv.ParseUint(strings.TrimSuffix(n, "]"), 10, 64); err == nil {
				out = append(out, v)
			}
		}
	}
	return out
}

// sortPorts orders ports by number, then protocol and address.
func sortPorts(ps []Port) {
	sort.Slice(ps, func(i, j int) bool {
		a, b := ps[i], ps[j]
		if a.Port != b.Port {
			return a.Port < b.Port
		}
		if a.Proto != b.Proto {
			return a.Proto < b.Proto
		}
		return a.Addr < b.Addr
	})
}

// clockTicks is USER_HZ, the unit of a process's start time: 100 on every
// architecture Linux runs on servers.
const clockTicks = 100

// bootTime reads btime (seconds since the epoch) from /proc/stat.
func bootTime(e *Env) int64 {
	b, err := e.ReadFile("/proc/stat", 1<<20)
	if err != nil {
		return 0
	}
	for line := range strings.SplitSeq(string(b), "\n") {
		if v, ok := strings.CutPrefix(line, "btime "); ok {
			n, _ := strconv.ParseInt(strings.TrimSpace(v), 10, 64)
			return n
		}
	}
	return 0
}

// startTime is when a process started, from field 22 of /proc/<pid>/stat
// (clock ticks since boot).
func startTime(e *Env, pid int, btime int64) *time.Time {
	if btime <= 0 {
		return nil
	}
	b, err := e.ReadFile(filepath.Join("/proc", strconv.Itoa(pid), "stat"), 4096)
	if err != nil {
		return nil
	}
	s := string(b)
	i := strings.LastIndexByte(s, ')')
	if i < 0 {
		return nil
	}
	// After "pid (comm)": state is field 3, starttime field 22.
	f := strings.Fields(s[i+1:])
	if len(f) < 20 {
		return nil
	}
	ticks, err := strconv.ParseInt(f[19], 10, 64)
	if err != nil {
		return nil
	}
	t := time.Unix(btime+ticks/clockTicks, 0).UTC()
	return &t
}
