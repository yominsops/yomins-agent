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
