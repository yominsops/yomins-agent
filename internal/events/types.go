package events

import "time"

// EventType identifies the specific event that occurred.
type EventType string

const (
	// auth.*
	EventAuthLoginSuccess       EventType = "auth.login_success"
	EventAuthLoginFailed        EventType = "auth.login_failed"
	EventAuthLogout             EventType = "auth.logout"
	EventAuthSudo               EventType = "auth.sudo"
	EventAuthBruteforceDetected EventType = "auth.bruteforce_detected"
	EventAuthLoginNewIP         EventType = "auth.login_new_ip"

	// process.*
	EventProcessStart        EventType = "process.start"
	EventProcessStop         EventType = "process.stop"
	EventProcessHighCPU      EventType = "process.high_cpu"
	EventProcessHighMemory   EventType = "process.high_memory"
	EventProcessSuspicious   EventType = "process.suspicious"
	EventProcessExecTmp      EventType = "process.exec_tmp"
	EventProcessReverseShell EventType = "process.reverse_shell"

	// network.*
	EventNetworkConnectionOpen  EventType = "network.connection_open"
	EventNetworkScanDetected    EventType = "network.scan_detected"
	EventNetworkSuspiciousPort  EventType = "network.suspicious_port"

	// system.*
	EventSystemReboot        EventType = "system.reboot"
	EventSystemOOMKiller     EventType = "system.oom_killer"
	EventSystemUserCreated   EventType = "system.user_created"
	EventSystemUserDeleted   EventType = "system.user_deleted"
	EventSystemConfigModified EventType = "system.config_modified"
)

// Category groups events by broad domain.
type Category string

const (
	CategoryAccessEvent    Category = "access_event"
	CategoryThreatActivity Category = "threat_activity"
	CategorySystemCheck    Category = "system_check"
)

// Severity indicates the urgency of an event.
type Severity string

const (
	SeverityInfo     Severity = "info"
	SeverityWarning  Severity = "warning"
	SeverityCritical Severity = "critical"
)

// Confidence indicates the likelihood that the event represents a real threat.
type Confidence string

const (
	ConfidenceLow    Confidence = "low"
	ConfidenceMedium Confidence = "medium"
	ConfidenceHigh   Confidence = "high"
)

// HostInfo identifies the machine that produced the event.
type HostInfo struct {
	Hostname string `json:"hostname"`
	IP       string `json:"ip"`
}

// AgentInfo identifies the agent build that produced the event.
type AgentInfo struct {
	Name    string `json:"name"`
	Version string `json:"version"`
}

// ActorInfo describes the user principal associated with an event.
type ActorInfo struct {
	User       string `json:"user,omitempty"`
	UID        int    `json:"uid,omitempty"`
	IP         string `json:"ip,omitempty"`
	Method     string `json:"method,omitempty"`
	TargetUser string `json:"target_user,omitempty"`
	Command    string `json:"command,omitempty"`
}

// ContextInfo carries event-specific session and tracing identifiers.
type ContextInfo struct {
	SessionID string `json:"session_id,omitempty"`
	TTY       string `json:"tty,omitempty"`
	RemoteIP  string `json:"remote_ip,omitempty"`
	Reason    string `json:"reason,omitempty"`
	Service   string `json:"service,omitempty"`
}

// ProcessDetail is the domain payload for process.* events.
type ProcessDetail struct {
	Name          string  `json:"name,omitempty"`
	PID           int32   `json:"pid,omitempty"`
	PPID          int32   `json:"ppid,omitempty"`
	Cmdline       string  `json:"cmdline,omitempty"`
	Exe           string  `json:"exe,omitempty"`
	CPUPercent    float64 `json:"cpu_percent,omitempty"`
	MemoryPercent float32 `json:"memory_percent,omitempty"`
}

// NetworkDetail is the domain payload for network.* events.
type NetworkDetail struct {
	LocalIP   string `json:"local_ip,omitempty"`
	LocalPort uint16 `json:"local_port,omitempty"`
	Proto     string `json:"proto,omitempty"`
}

// Event is the canonical envelope for all security events produced by the agent.
// At most one domain payload field (Process, Network) will be non-nil per event.
type Event struct {
	ID         string     `json:"id"`
	Timestamp  time.Time  `json:"timestamp"`
	Type       EventType  `json:"type"`
	Category   Category   `json:"category"`
	Severity   Severity   `json:"severity"`
	Confidence Confidence `json:"confidence,omitempty"`

	Host  HostInfo  `json:"host"`
	Agent AgentInfo `json:"agent"`

	Actor   *ActorInfo   `json:"actor,omitempty"`
	Context *ContextInfo `json:"context,omitempty"`

	Tags []string `json:"tags,omitempty"`

	// Domain-specific payloads — at most one non-nil per event.
	Process *ProcessDetail `json:"process,omitempty"`
	Network *NetworkDetail `json:"network,omitempty"`
}
