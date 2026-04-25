package process

import (
	"time"

	gopsprocess "github.com/shirou/gopsutil/v3/process"
)

const rollingWindowSize = 5

// ProcessSnapshot holds per-process state used for anomaly detection and
// start/stop tracking.
type ProcessSnapshot struct {
	PID  int32
	PPID int32
	Name string
	Exe  string
	// Cmdline is captured once at process discovery time.
	Cmdline string
	// isNew is true for processes discovered after agent startup.
	// Baseline processes (present at startup) have isNew=false.
	isNew bool

	// proc is the gopsutil Process object reused across poll ticks.
	// CPUPercentWithContext computes a delta between consecutive calls on the
	// SAME object; using a freshly-created object every poll always returns 0.
	proc *gopsprocess.Process

	// Rolling windows for anomaly detection (circular buffers).
	cpuHistory    [rollingWindowSize]float64
	memHistory    [rollingWindowSize]float32
	historyIdx    int
	historyFilled int // number of valid readings (0..rollingWindowSize)

	// Cooldown tracking: suppress repeated anomaly alerts.
	lastCPUAlertAt time.Time
	lastMemAlertAt time.Time
}

// pushCPU records a new CPU reading and returns the rolling average.
// The average is only meaningful once historyFilled >= 3.
func (s *ProcessSnapshot) pushCPU(v float64) float64 {
	s.cpuHistory[s.historyIdx] = v
	s.advance()
	return s.cpuAvg()
}

// pushMem records a new memory reading and returns the rolling average.
func (s *ProcessSnapshot) pushMem(v float32) float32 {
	s.memHistory[s.historyIdx] = v
	// historyIdx already advanced by pushCPU if called in the same tick;
	// mem uses the same slot updated together.
	return s.memAvg()
}

// pushMetrics records CPU and mem together (single index advance).
func (s *ProcessSnapshot) pushMetrics(cpu float64, mem float32) (cpuAvg float64, memAvg float32) {
	s.cpuHistory[s.historyIdx] = cpu
	s.memHistory[s.historyIdx] = mem
	s.advance()
	return s.cpuAvg(), s.memAvg()
}

func (s *ProcessSnapshot) advance() {
	s.historyIdx = (s.historyIdx + 1) % rollingWindowSize
	if s.historyFilled < rollingWindowSize {
		s.historyFilled++
	}
}

func (s *ProcessSnapshot) cpuAvg() float64 {
	if s.historyFilled == 0 {
		return 0
	}
	var sum float64
	for i := 0; i < s.historyFilled; i++ {
		sum += s.cpuHistory[i]
	}
	return sum / float64(s.historyFilled)
}

func (s *ProcessSnapshot) memAvg() float32 {
	if s.historyFilled == 0 {
		return 0
	}
	var sum float32
	for i := 0; i < s.historyFilled; i++ {
		sum += s.memHistory[i]
	}
	return sum / float32(s.historyFilled)
}

// readyForAnomaly returns true if we have enough history to make a reliable
// anomaly decision (requires at least 3 readings).
func (s *ProcessSnapshot) readyForAnomaly() bool {
	return s.historyFilled >= 3
}
