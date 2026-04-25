//go:build linux

package auth

import (
	"bytes"
	"encoding/binary"
	"testing"
	"time"
)

// buildRecord constructs a synthetic 384-byte utmp record for testing.
func buildRecord(utType int16, pid int32, line, user, host string, tvSec, tvUsec int32) []byte {
	buf := make([]byte, utmpRecordSize)
	binary.LittleEndian.PutUint16(buf[0:], uint16(utType))
	// 2 bytes padding at offset 2
	binary.LittleEndian.PutUint32(buf[4:], uint32(pid))
	copyField(buf[8:], line, 32)
	// ut_id at offset 40 (4 bytes) — leave zero
	copyField(buf[44:], user, 32)
	copyField(buf[76:], host, 256)
	// ut_exit at 332 (4), ut_session at 336 (4), ut_tv.tv_sec at 340 (4), ut_tv.tv_usec at 344 (4)
	binary.LittleEndian.PutUint32(buf[340:], uint32(tvSec))
	binary.LittleEndian.PutUint32(buf[344:], uint32(tvUsec))
	// ut_addr_v6 at 352 (16) and __unused at 368 (20) — leave zero
	return buf
}

func copyField(dst []byte, s string, maxLen int) {
	b := []byte(s)
	if len(b) > maxLen {
		b = b[:maxLen]
	}
	copy(dst, b)
}

// ── parseRecord ──────────────────────────────────────────────────────────────

func TestParseRecord_Login(t *testing.T) {
	raw := buildRecord(utUserProcess, 1234, "pts/0", "alice", "192.168.1.10", 1_700_000_000, 500_000)
	rec, ok := parseRecord(raw)
	if !ok {
		t.Fatal("parseRecord returned ok=false for valid record")
	}
	if rec.Type != utUserProcess {
		t.Errorf("Type = %d, want %d (UT_USER_PROCESS)", rec.Type, utUserProcess)
	}
	if rec.PID != 1234 {
		t.Errorf("PID = %d, want 1234", rec.PID)
	}
	if rec.TTY != "pts/0" {
		t.Errorf("TTY = %q, want pts/0", rec.TTY)
	}
	if rec.User != "alice" {
		t.Errorf("User = %q, want alice", rec.User)
	}
	if rec.Host != "192.168.1.10" {
		t.Errorf("Host = %q, want 192.168.1.10", rec.Host)
	}
}

func TestParseRecord_Logout(t *testing.T) {
	raw := buildRecord(utDeadProcess, 5678, "pts/1", "bob", "", 1_700_001_000, 0)
	rec, ok := parseRecord(raw)
	if !ok {
		t.Fatal("parseRecord returned ok=false for logout record")
	}
	if rec.Type != utDeadProcess {
		t.Errorf("Type = %d, want %d (UT_DEAD_PROCESS)", rec.Type, utDeadProcess)
	}
	if rec.User != "bob" {
		t.Errorf("User = %q, want bob", rec.User)
	}
}

func TestParseRecord_Timestamp(t *testing.T) {
	tvSec := int32(1_700_000_000)
	tvUsec := int32(123_456)
	raw := buildRecord(utUserProcess, 1, "tty1", "root", "", tvSec, tvUsec)
	rec, ok := parseRecord(raw)
	if !ok {
		t.Fatal("parseRecord returned ok=false")
	}

	want := time.Unix(int64(tvSec), int64(tvUsec)*1000).UTC()
	if !rec.Timestamp.Equal(want) {
		t.Errorf("Timestamp = %v, want %v", rec.Timestamp, want)
	}
	if rec.Timestamp.Location() != time.UTC {
		t.Error("Timestamp must be in UTC")
	}
}

func TestParseRecord_WrongSize(t *testing.T) {
	_, ok := parseRecord(make([]byte, 100))
	if ok {
		t.Error("expected ok=false for undersized record")
	}

	_, ok = parseRecord(make([]byte, utmpRecordSize+1))
	if ok {
		t.Error("expected ok=false for oversized record")
	}

	_, ok = parseRecord(nil)
	if ok {
		t.Error("expected ok=false for nil input")
	}
}

func TestParseRecord_ExactSize(t *testing.T) {
	raw := buildRecord(utUserProcess, 99, "tty1", "test", "host", 0, 0)
	if len(raw) != utmpRecordSize {
		t.Fatalf("buildRecord length = %d, want %d", len(raw), utmpRecordSize)
	}
	_, ok := parseRecord(raw)
	if !ok {
		t.Error("expected ok=true for exact-size record")
	}
}

func TestParseRecord_OtherType(t *testing.T) {
	// Type 1 (RUN_LVL) should be parseable but callers filter it out.
	raw := buildRecord(1, 0, "", "", "", 0, 0)
	rec, ok := parseRecord(raw)
	if !ok {
		t.Fatal("parseRecord returned ok=false for type=1")
	}
	if rec.Type != 1 {
		t.Errorf("Type = %d, want 1", rec.Type)
	}
}

// ── nullTerminated ────────────────────────────────────────────────────────────

func TestNullTerminated_WithNul(t *testing.T) {
	b := []byte{'h', 'e', 'l', 'l', 'o', 0, 'X', 'X'}
	got := nullTerminated(b)
	if got != "hello" {
		t.Errorf("nullTerminated = %q, want hello", got)
	}
}

func TestNullTerminated_NoNul(t *testing.T) {
	b := []byte{'a', 'b', 'c'}
	got := nullTerminated(b)
	if got != "abc" {
		t.Errorf("nullTerminated = %q, want abc", got)
	}
}

func TestNullTerminated_AllZero(t *testing.T) {
	b := make([]byte, 32)
	got := nullTerminated(b)
	if got != "" {
		t.Errorf("nullTerminated of zero bytes = %q, want empty string", got)
	}
}

func TestNullTerminated_FirstByteNul(t *testing.T) {
	b := []byte{0, 'a', 'b'}
	got := nullTerminated(b)
	if got != "" {
		t.Errorf("nullTerminated = %q, want empty string", got)
	}
}

func TestNullTerminated_Empty(t *testing.T) {
	got := nullTerminated([]byte{})
	if got != "" {
		t.Errorf("nullTerminated of empty = %q, want empty", got)
	}
}

// ── NUL-padded fields in parsed record ────────────────────────────────────────

func TestParseRecord_ShortUserField(t *testing.T) {
	// User field shorter than 32 bytes, rest zero-padded.
	raw := buildRecord(utUserProcess, 1, "pts/0", "jo", "", 0, 0)
	rec, ok := parseRecord(raw)
	if !ok {
		t.Fatal("parseRecord returned ok=false")
	}
	if rec.User != "jo" {
		t.Errorf("User = %q, want jo", rec.User)
	}
}

func TestParseRecord_EmptyHost(t *testing.T) {
	raw := buildRecord(utUserProcess, 1, "tty1", "root", "", 0, 0)
	rec, ok := parseRecord(raw)
	if !ok {
		t.Fatal("parseRecord returned ok=false")
	}
	if rec.Host != "" {
		t.Errorf("Host = %q, want empty string (console login)", rec.Host)
	}
}

func TestParseRecord_RecordSize(t *testing.T) {
	if utmpRecordSize != 384 {
		t.Errorf("utmpRecordSize = %d, want 384", utmpRecordSize)
	}
}

// ── Binary encoding integrity ─────────────────────────────────────────────────

func TestParseRecord_PIDLittleEndian(t *testing.T) {
	// Write a known PID and verify binary.Read decodes it correctly.
	raw := make([]byte, utmpRecordSize)
	binary.LittleEndian.PutUint32(raw[4:], 0xDEADBEEF)
	rec, ok := parseRecord(raw)
	if !ok {
		t.Fatal("parseRecord returned ok=false")
	}
	if uint32(rec.PID) != 0xDEADBEEF {
		t.Errorf("PID = %08X, want DEADBEEF", uint32(rec.PID))
	}
}

func TestBuildRecord_AllFieldsRoundTrip(t *testing.T) {
	raw := buildRecord(utUserProcess, 42, "pts/2", "charlie", "10.0.0.5", 1234567890, 999)
	rec, ok := parseRecord(raw)
	if !ok {
		t.Fatal("parseRecord returned ok=false")
	}
	if rec.Type != utUserProcess {
		t.Errorf("Type = %d", rec.Type)
	}
	if rec.PID != 42 {
		t.Errorf("PID = %d", rec.PID)
	}
	if rec.TTY != "pts/2" {
		t.Errorf("TTY = %q", rec.TTY)
	}
	if rec.User != "charlie" {
		t.Errorf("User = %q", rec.User)
	}
	if rec.Host != "10.0.0.5" {
		t.Errorf("Host = %q", rec.Host)
	}
}

// Verify the utmpRecord struct fits in a bytes.Reader of size utmpRecordSize.
func TestParseRecord_BinaryReadConsumesExactBytes(t *testing.T) {
	raw := buildRecord(utUserProcess, 1, "pts/0", "x", "y", 1000, 0)
	r := bytes.NewReader(raw)
	var rec utmpRecord
	if err := binary.Read(r, binary.LittleEndian, &rec); err != nil {
		t.Fatalf("binary.Read: %v", err)
	}
	if r.Len() != 0 {
		t.Errorf("binary.Read did not consume all bytes: %d remaining", r.Len())
	}
}
