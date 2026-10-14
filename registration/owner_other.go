//go:build !unix

package registration

import "io/fs"

// fileOwner reports -1, matching os.Geteuid on systems without Unix owners, so only the 0600 rule applies.
func fileOwner(fs.FileInfo) int {
	return -1
}
