package collector

import (
	"context"

	"github.com/shirou/gopsutil/v3/net"
)

type realNetworkReader struct{}

func (realNetworkReader) IOCountersWithContext(ctx context.Context, pernic bool) ([]IOCountersStat, error) {
	counters, err := net.IOCountersWithContext(ctx, pernic)
	if err != nil {
		return nil, err
	}
	result := make([]IOCountersStat, len(counters))
	for i, c := range counters {
		result[i] = IOCountersStat{
			Name:        c.Name,
			BytesSent:   c.BytesSent,
			BytesRecv:   c.BytesRecv,
			PacketsSent: c.PacketsSent,
			PacketsRecv: c.PacketsRecv,
			Errin:       c.Errin,
			Errout:      c.Errout,
			Dropin:      c.Dropin,
			Dropout:     c.Dropout,
		}
	}
	return result, nil
}

func (realNetworkReader) UpInterfaceNames(ctx context.Context) (map[string]bool, error) {
	ifaces, err := net.InterfacesWithContext(ctx)
	if err != nil {
		return nil, err
	}
	m := make(map[string]bool, len(ifaces))
	for _, iface := range ifaces {
		for _, flag := range iface.Flags {
			if flag == "up" {
				m[iface.Name] = true
				break
			}
		}
	}
	return m, nil
}
