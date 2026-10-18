package collector

import (
	"context"
	"fmt"
	"strconv"
	"strings"

	"github.com/yominsops/yomins-agent/internal/metrics"
)

// NetstatCollector reports the TCP/UDP counters behind "the site is slow or
// refuses connections": retransmits, accept-queue overflows, resets, UDP
// buffer drops, and TCP connections by state.
type NetstatCollector struct {
	paths HostPaths
}

// NewNetstatCollector creates the collector.
func NewNetstatCollector(paths HostPaths) *NetstatCollector { return &NetstatCollector{paths: paths} }

func (c *NetstatCollector) Name() string { return "netstat" }

// counters picked from /proc/net/snmp and /proc/net/netstat ("Proto:Field").
var netCounters = map[string][2]string{
	"Tcp:ActiveOpens":         {"tcp_active_opens_total", "Outgoing TCP connections opened"},
	"Tcp:PassiveOpens":        {"tcp_passive_opens_total", "Incoming TCP connections accepted"},
	"Tcp:AttemptFails":        {"tcp_attempt_fails_total", "TCP connection attempts that failed"},
	"Tcp:EstabResets":         {"tcp_established_resets_total", "Established TCP connections reset"},
	"Tcp:RetransSegs":         {"tcp_retransmitted_segments_total", "TCP segments retransmitted"},
	"Tcp:OutSegs":             {"tcp_out_segments_total", "TCP segments sent"},
	"Tcp:InErrs":              {"tcp_in_errors_total", "TCP segments received in error"},
	"Tcp:OutRsts":             {"tcp_out_resets_total", "TCP resets sent"},
	"Udp:InErrors":            {"udp_in_errors_total", "UDP datagrams received in error"},
	"Udp:RcvbufErrors":        {"udp_receive_buffer_errors_total", "UDP datagrams dropped: receive buffer full"},
	"Udp:SndbufErrors":        {"udp_send_buffer_errors_total", "UDP datagrams dropped: send buffer full"},
	"Udp:NoPorts":             {"udp_no_ports_total", "UDP datagrams to a port nobody listens on"},
	"TcpExt:ListenOverflows":  {"tcp_listen_overflows_total", "Connections dropped: the accept queue was full"},
	"TcpExt:ListenDrops":      {"tcp_listen_drops_total", "Connections dropped while listening"},
	"TcpExt:TCPTimeouts":      {"tcp_timeouts_total", "TCP retransmission timeouts"},
	"TcpExt:TCPSynRetrans":    {"tcp_syn_retransmits_total", "SYN retransmits"},
	"TcpExt:SyncookiesSent":   {"tcp_syncookies_sent_total", "SYN cookies sent (SYN flood or full backlog)"},
	"TcpExt:TCPAbortOnMemory": {"tcp_abort_on_memory_total", "Connections aborted: out of socket memory"},
}

var tcpStates = map[string]string{
	"01": "established", "02": "syn_sent", "03": "syn_recv", "04": "fin_wait1", "05": "fin_wait2",
	"06": "time_wait", "07": "close", "08": "close_wait", "09": "last_ack", "0A": "listen", "0B": "closing",
}

func (c *NetstatCollector) Collect(_ context.Context) ([]metrics.MetricPoint, error) {
	var pts []metrics.MetricPoint
	found := false
	for _, file := range []string{"snmp", "netstat"} {
		lines, err := readLines(c.paths.proc("net", file))
		if err != nil {
			continue
		}
		found = true
		// Pairs of lines: "Proto: names…" then "Proto: values…".
		for i := 0; i+1 < len(lines); i += 2 {
			names, values := strings.Fields(lines[i]), strings.Fields(lines[i+1])
			if len(names) != len(values) || len(names) < 2 || names[0] != values[0] {
				continue
			}
			proto := strings.TrimSuffix(names[0], ":")
			for j := 1; j < len(names); j++ {
				m, ok := netCounters[proto+":"+names[j]]
				if !ok {
					continue
				}
				v, err := strconv.ParseFloat(values[j], 64)
				if err == nil {
					pts = append(pts, counter(m[0], m[1], v, nil))
				}
			}
		}
	}
	if !found {
		return nil, fmt.Errorf("no /proc/net/snmp")
	}

	states := map[string]float64{}
	for _, st := range tcpStates {
		states[st] = 0
	}
	for _, file := range []string{"tcp", "tcp6"} {
		lines, err := readLines(c.paths.proc("net", file))
		if err != nil {
			continue
		}
		for _, line := range lines[min(1, len(lines)):] {
			f := strings.Fields(line)
			if len(f) > 3 {
				if st, ok := tcpStates[f[3]]; ok {
					states[st]++
				}
			}
		}
	}
	for st, n := range states {
		pts = append(pts, gauge("tcp_connections", "TCP sockets by state", n, map[string]string{"state": st}))
	}
	return pts, nil
}
