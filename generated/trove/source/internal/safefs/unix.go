//go:build !windows

package safefs

import (
	"errors"
	"io/fs"
	"os"
	"syscall"
)

func openRead(r *Root, name string) (*os.File, error) {
	return r.R.OpenFile(name, os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
}
func checkPrivate(f *os.File) error {
	st, err := f.Stat()
	if err != nil {
		return err
	}
	if st.Mode().Perm()&0077 != 0 {
		return errors.New("private file must be owner-only (0600)")
	}
	if s, ok := st.Sys().(*syscall.Stat_t); !ok || s.Uid != uint32(os.Geteuid()) {
		return errors.New("private file must be owned by the current user")
	}
	return nil
}

func forbidden(st fs.FileInfo) bool { return st.Mode()&os.ModeSymlink != 0 }
func protect(f *os.File) error {
	st, err := f.Stat()
	if err != nil {
		return err
	}
	if st.IsDir() {
		return f.Chmod(0700)
	}
	return f.Chmod(0600)
}
func syncDir(r *Root) error {
	f, err := r.R.Open(".")
	if err != nil {
		return err
	}
	defer f.Close()
	return f.Sync()
}
