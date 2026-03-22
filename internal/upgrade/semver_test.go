package upgrade

import (
	"testing"
)

func TestParseVersion(t *testing.T) {
	tests := []struct {
		input   string
		want    [3]int
		wantErr bool
	}{
		{"v1.2.3", [3]int{1, 2, 3}, false},
		{"1.2.3", [3]int{1, 2, 3}, false},
		{"v0.0.0", [3]int{0, 0, 0}, false},
		{"v10.20.30", [3]int{10, 20, 30}, false},
		// pre-release tags must be rejected
		{"v1.2.3-rc1", [3]int{}, true},
		{"v1.2.3+build", [3]int{}, true},
		// malformed
		{"v1.2", [3]int{}, true},
		{"v1.2.3.4", [3]int{}, true},
		{"v1.x.3", [3]int{}, true},
		{"", [3]int{}, true},
	}
	for _, tt := range tests {
		got, err := parseVersion(tt.input)
		if (err != nil) != tt.wantErr {
			t.Errorf("parseVersion(%q) error = %v, wantErr %v", tt.input, err, tt.wantErr)
			continue
		}
		if !tt.wantErr && got != tt.want {
			t.Errorf("parseVersion(%q) = %v, want %v", tt.input, got, tt.want)
		}
	}
}

func TestIsNewer(t *testing.T) {
	tests := []struct {
		current   string
		candidate string
		want      bool
		wantErr   bool
	}{
		{"v1.0.0", "v1.0.1", true, false},
		{"v1.0.0", "v1.1.0", true, false},
		{"v1.0.0", "v2.0.0", true, false},
		{"v1.0.0", "v1.0.0", false, false},
		{"v1.0.1", "v1.0.0", false, false},
		{"v2.0.0", "v1.9.9", false, false},
		// pre-release in candidate → error
		{"v1.0.0", "v1.0.1-rc1", false, true},
		// dev build in current → error (can't compare)
		{"dev", "v1.0.0", false, true},
	}
	for _, tt := range tests {
		got, err := isNewer(tt.current, tt.candidate)
		if (err != nil) != tt.wantErr {
			t.Errorf("isNewer(%q, %q) error = %v, wantErr %v",
				tt.current, tt.candidate, err, tt.wantErr)
			continue
		}
		if !tt.wantErr && got != tt.want {
			t.Errorf("isNewer(%q, %q) = %v, want %v",
				tt.current, tt.candidate, got, tt.want)
		}
	}
}
