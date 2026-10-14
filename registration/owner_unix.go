//go:build unix

package registration

import (
	"io/fs"
	"syscall"
)

func fileOwner(info fs.FileInfo) int {
	if st, ok := info.Sys().(*syscall.Stat_t); ok {
		return int(st.Uid)
	}
	return -1
}
