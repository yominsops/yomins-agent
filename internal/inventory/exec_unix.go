//go:build unix

package inventory

import (
	"os"
	"os/exec"
	"syscall"
)

// nobody is the unprivileged user version probes run as.
const nobody = 65534

// asNobody runs the command as nobody, without root's groups.
func asNobody(cmd *exec.Cmd) error {
	cmd.SysProcAttr = &syscall.SysProcAttr{Credential: &syscall.Credential{Uid: nobody, Gid: nobody, Groups: []uint32{}}}
	return nil
}

// rootOwned: the file belongs to root.
func rootOwned(st os.FileInfo) bool {
	sys, ok := st.Sys().(*syscall.Stat_t)
	return ok && sys.Uid == 0
}
