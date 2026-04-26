//go:build linux

package auth

import (
	"bytes"
	"encoding/binary"
	"time"
)

// utmp record types relevant to login tracking.
const (
	utUserProcess = 7 // UT_USER_PROCESS — a session is open
	utDeadProcess = 8 // UT_DEAD_PROCESS — a session has ended
)

// utmpRecord mirrors the Linux x86_64 utmp struct (384 bytes per record).
// Field sizes from <utmp.h> with __WORDSIZE_COMPAT32 (standard on x86_64);
// all values are little-endian.
//
//	Offset  Size  Field
//	0       2     ut_type
//	2       2     padding (align pid_t)
//	4       4     ut_pid
//	8       32    ut_line (TTY)
//	40      4     ut_id
//	44      32    ut_user
//	76      256   ut_host (remote host / IP)
//	332     4     ut_exit
//	336     4     ut_session  (int32_t under COMPAT32)
//	340     4     ut_tv.tv_sec
//	344     4     ut_tv.tv_usec
//	348     16    ut_addr_v6
//	364     20    __unused
//
// Total: 384 bytes.
const utmpRecordSize = 384

type utmpRecord struct {
	Type    int16
	_       [2]byte
	PID     int32
	Line    [32]byte
	ID      [4]byte
	User    [32]byte
	Host    [256]byte
	Exit    [4]byte
	Session int32
	TvSec   int32
	TvUsec  int32
	Addr    [16]byte
	_       [20]byte
}

// parsedRecord holds the decoded fields we care about.
type parsedRecord struct {
	Type      int16
	PID       int32
	TTY       string
	User      string
	Host      string
	Timestamp time.Time
}

// minValidSec is the earliest Unix timestamp (2020-01-01 00:00:00 UTC) we
// consider plausible in a wtmp record.  Records written before NTP sync (when
// the system clock sits near the Unix epoch) have tv_sec values orders of
// magnitude smaller than this and would produce misleading 1970 timestamps.
const minValidSec = 1577836800 // 2020-01-01 00:00:00 UTC

// parseRecord decodes a single 384-byte utmp record.
// Returns false if the byte slice is not exactly utmpRecordSize bytes or if
// the embedded timestamp pre-dates minValidSec (indicating a pre-NTP-sync
// record written while the system clock was near the Unix epoch).
func parseRecord(data []byte) (parsedRecord, bool) {
	if len(data) != utmpRecordSize {
		return parsedRecord{}, false
	}
	var raw utmpRecord
	if err := binary.Read(bytes.NewReader(data), binary.LittleEndian, &raw); err != nil {
		return parsedRecord{}, false
	}
	sec := int64(raw.TvSec)
	var ts time.Time
	if sec >= minValidSec {
		ts = time.Unix(sec, int64(raw.TvUsec)*1000).UTC()
	} else {
		ts = time.Now().UTC()
	}
	return parsedRecord{
		Type:      raw.Type,
		PID:       raw.PID,
		TTY:       nullTerminated(raw.Line[:]),
		User:      nullTerminated(raw.User[:]),
		Host:      nullTerminated(raw.Host[:]),
		Timestamp: ts,
	}, true
}

// nullTerminated converts a NUL-terminated byte slice to a Go string.
func nullTerminated(b []byte) string {
	if idx := bytes.IndexByte(b, 0); idx >= 0 {
		return string(b[:idx])
	}
	return string(b)
}
