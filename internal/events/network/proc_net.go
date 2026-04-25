//go:build linux

package network

import (
	"bufio"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"net"
	"os"
	"strconv"
	"strings"
)

// tcpState0A is the hex state code for a LISTEN socket in /proc/net/tcp.
const tcpStateListen = "0A"

// listenEntry represents a single LISTEN socket parsed from /proc/net/tcp.
type listenEntry struct {
	Proto     string // "tcp" or "tcp6"
	LocalIP   string
	LocalPort uint16
}

// key returns a unique string identifier for this listener.
func (e listenEntry) key() string {
	return fmt.Sprintf("%s:%s:%d", e.Proto, e.LocalIP, e.LocalPort)
}

// scanListeners reads /proc/net/tcp and /proc/net/tcp6 and returns all
// sockets in LISTEN (0x0A) state, plus the total number of socket entries
// across all states (used for scan/burst detection).
func scanListeners() (listeners []listenEntry, totalConnections int, err error) {
	for _, file := range []string{"/proc/net/tcp", "/proc/net/tcp6"} {
		proto := "tcp"
		if strings.HasSuffix(file, "6") {
			proto = "tcp6"
		}
		l, total, ferr := parseProcNetTCP(file, proto)
		if ferr != nil {
			if os.IsNotExist(ferr) {
				continue
			}
			err = ferr
			return
		}
		listeners = append(listeners, l...)
		totalConnections += total
	}
	return
}

// parseProcNetTCP parses a single /proc/net/tcp or /proc/net/tcp6 file.
// It returns the LISTEN entries and the total line count (all states).
func parseProcNetTCP(path, proto string) (listeners []listenEntry, total int, err error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, 0, err
	}
	defer f.Close()

	scanner := bufio.NewScanner(f)
	first := true
	for scanner.Scan() {
		if first {
			first = false
			continue // skip header line
		}
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}
		total++

		fields := strings.Fields(line)
		if len(fields) < 4 {
			continue
		}

		state := strings.ToUpper(fields[3])
		if state != tcpStateListen {
			continue
		}

		ip, port, parseErr := parseAddr(fields[1], proto == "tcp6")
		if parseErr != nil {
			continue
		}
		listeners = append(listeners, listenEntry{
			Proto:     proto,
			LocalIP:   ip,
			LocalPort: port,
		})
	}
	return listeners, total, scanner.Err()
}

// parseAddr decodes a hex-encoded "IP:port" field from /proc/net/tcp[6].
// IPv4 addresses are stored as a single little-endian 32-bit hex word.
// IPv6 addresses are stored as four little-endian 32-bit hex words.
func parseAddr(hexAddr string, isIPv6 bool) (string, uint16, error) {
	parts := strings.SplitN(hexAddr, ":", 2)
	if len(parts) != 2 {
		return "", 0, fmt.Errorf("invalid addr: %q", hexAddr)
	}

	portNum, err := strconv.ParseUint(parts[1], 16, 16)
	if err != nil {
		return "", 0, err
	}

	var ipStr string
	if !isIPv6 {
		b, err := hex.DecodeString(parts[0])
		if err != nil || len(b) != 4 {
			return "", 0, fmt.Errorf("invalid ipv4 addr: %q", parts[0])
		}
		// Little-endian byte order in /proc/net/tcp.
		ip := net.IP([]byte{b[3], b[2], b[1], b[0]})
		ipStr = ip.String()
	} else {
		b, err := hex.DecodeString(parts[0])
		if err != nil || len(b) != 16 {
			return "", 0, fmt.Errorf("invalid ipv6 addr: %q", parts[0])
		}
		// Each group of 4 bytes is stored little-endian.
		var ordered [16]byte
		for i := 0; i < 4; i++ {
			word := binary.LittleEndian.Uint32(b[i*4 : i*4+4])
			binary.BigEndian.PutUint32(ordered[i*4:], word)
		}
		ip := net.IP(ordered[:])
		ipStr = ip.String()
	}

	return ipStr, uint16(portNum), nil
}
