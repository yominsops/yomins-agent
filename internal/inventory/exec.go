package inventory

import (
	"bytes"
	"context"
	"fmt"
	"os/exec"
	"time"
)

// commandTimeout bounds one command.
const commandTimeout = 30 * time.Second

// maxOutput bounds what a command may print.
const maxOutput = 8 << 20

// limitedBuffer keeps the first max bytes written to it.
type limitedBuffer struct {
	bytes.Buffer
	max int
}

func (b *limitedBuffer) Write(p []byte) (int, error) {
	if room := b.max - b.Len(); room > 0 {
		if len(p) > room {
			b.Buffer.Write(p[:room])
		} else {
			b.Buffer.Write(p)
		}
	}
	return len(p), nil
}

// runCommand runs name with args and returns stdout and stderr together.
// With user set the command runs as nobody (see asNobody): it is a program
// found on the server, asked only for its version.
func runCommand(ctx context.Context, user bool, name string, args ...string) ([]byte, error) {
	ctx, cancel := context.WithTimeout(ctx, commandTimeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, name, args...)
	cmd.Env = []string{"PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin", "LANG=C", "LC_ALL=C"}
	cmd.Dir = "/"
	out := &limitedBuffer{max: maxOutput}
	cmd.Stdout, cmd.Stderr = out, out
	if user {
		if err := asNobody(cmd); err != nil {
			return nil, err
		}
	}
	err := cmd.Run()
	if ctx.Err() != nil {
		return out.Bytes(), fmt.Errorf("%s: %w", name, ctx.Err())
	}
	return out.Bytes(), err
}
