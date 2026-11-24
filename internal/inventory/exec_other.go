//go:build !unix

package inventory

import (
	"errors"
	"os"
	"os/exec"
)

func asNobody(*exec.Cmd) error { return errors.New("not supported on this system") }

func rootOwned(os.FileInfo) bool { return false }
