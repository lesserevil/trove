// Package safefs confines store operations to held os.Root directory handles.
package safefs

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"strings"
)

var segment = regexp.MustCompile(`^[A-Za-z0-9_@.-]+$`)

func Name(s string, nested bool) error {
	if s == "" || len(s) > 180 || strings.Contains(s, "\\") || strings.HasPrefix(s, "/") {
		return errors.New("invalid name")
	}
	parts := strings.Split(s, "/")
	if !nested && len(parts) != 1 {
		return errors.New("identity must be one path component")
	}
	for _, p := range parts {
		if len(p) > 80 || p == "." || p == ".." || !segment.MatchString(p) || strings.HasSuffix(p, ".") || strings.HasPrefix(p, ".create-") {
			return errors.New("invalid name component")
		}
		base := strings.ToUpper(strings.Split(p, ".")[0])
		if base == "CON" || base == "PRN" || base == "AUX" || base == "NUL" || base == "CONIN$" || base == "CONOUT$" ||
			(len(base) == 4 && (strings.HasPrefix(base, "COM") || strings.HasPrefix(base, "LPT")) && base[3] >= '1' && base[3] <= '9') {
			return errors.New("reserved Windows name")
		}
	}
	return nil
}

type Root struct{ R *os.Root }

// Open walks from the volume root. Each child is opened relative to its held parent;
// a swapped symlink cannot escape that parent. Absolute symlinks are rejected by Go.
func Open(dir string, create bool) (*Root, error) {
	abs, err := filepath.Abs(dir)
	if err != nil {
		return nil, err
	}
	volume := filepath.VolumeName(abs)
	anchor := volume + string(filepath.Separator)
	r, err := os.OpenRoot(anchor)
	if err != nil {
		return nil, err
	}
	for _, part := range strings.Split(strings.TrimPrefix(abs, anchor), string(filepath.Separator)) {
		if part == "" {
			continue
		}
		st, e := r.Lstat(part)
		if e != nil && create && errors.Is(e, fs.ErrNotExist) {
			e = r.Mkdir(part, 0700)
			if e == nil {
				st, e = r.Lstat(part)
			}
		}
		if e != nil {
			r.Close()
			return nil, e
		}
		if forbidden(st) || !st.IsDir() {
			r.Close()
			return nil, errors.New("directory path contains a link or non-directory")
		}
		next, e := r.OpenRoot(part)
		if e == nil {
			f, checkErr := next.Open(".")
			if checkErr == nil {
				var opened fs.FileInfo
				opened, checkErr = f.Stat()
				f.Close()
				if checkErr == nil && !os.SameFile(st, opened) {
					checkErr = errors.New("directory changed during open")
				}
			}
			if checkErr != nil {
				next.Close()
				e = checkErr
			}
		}
		r.Close()
		if e != nil {
			return nil, e
		}
		r = next
	}
	return &Root{r}, nil
}

func (r *Root) Close() error { return r.R.Close() }

func (r *Root) Check(name string) error {
	if name == "." {
		return nil
	}
	if !fs.ValidPath(name) {
		return errors.New("invalid relative path")
	}
	p := ""
	for _, part := range strings.Split(name, "/") {
		p = path.Join(p, part)
		st, err := r.R.Lstat(p)
		if err != nil {
			return err
		}
		if forbidden(st) {
			return errors.New("symbolic links and reparse points are forbidden")
		}
	}
	return nil
}

func (r *Root) Sub(name string) (*Root, error) {
	if err := r.Check(name); err != nil {
		return nil, err
	}
	st, err := r.R.Lstat(name)
	if err != nil {
		return nil, err
	}
	if forbidden(st) {
		return nil, errors.New("directory link forbidden")
	}
	x, err := r.R.OpenRoot(name)
	if err != nil {
		return nil, err
	}
	f, err := x.Open(".")
	if err != nil {
		x.Close()
		return nil, err
	}
	opened, err := f.Stat()
	f.Close()
	if err != nil || !os.SameFile(st, opened) {
		x.Close()
		return nil, errors.New("directory changed during open")
	}
	return &Root{x}, nil
}

func (r *Root) Private() error {
	f, err := r.R.Open(".")
	if err != nil {
		return err
	}
	defer f.Close()
	return protect(f)
}

func (r *Root) Mkdir(name string) error {
	if err := r.Check(path.Dir(name)); err != nil {
		return err
	}
	if err := r.R.Mkdir(name, 0700); err != nil {
		return err
	}
	d, err := r.Sub(name)
	if err != nil {
		return err
	}
	defer d.Close()
	return d.Private()
}

func (r *Root) MkdirAll(name string) error {
	p := ""
	for _, part := range strings.Split(name, "/") {
		p = path.Join(p, part)
		if _, err := r.R.Lstat(p); errors.Is(err, fs.ErrNotExist) {
			if err = r.Mkdir(p); err != nil {
				return err
			}
		} else if err != nil {
			return err
		}
		if err := r.Check(p); err != nil {
			return err
		}
	}
	return nil
}

func ReadBounded(reader io.Reader, limit int64) ([]byte, error) {
	b, err := io.ReadAll(io.LimitReader(reader, limit+1))
	if err != nil {
		return nil, err
	}
	if int64(len(b)) > limit {
		clear(b)
		return nil, errors.New("input exceeds size limit")
	}
	return b, nil
}

func (r *Root) Read(name string, limit int64) ([]byte, error) {
	return r.read(name, limit, false)
}

func (r *Root) ReadPrivate(name string, limit int64) ([]byte, error) {
	return r.read(name, limit, true)
}

func (r *Root) read(name string, limit int64, private bool) ([]byte, error) {
	d, err := r.Sub(path.Dir(name))
	if err != nil {
		return nil, err
	}
	defer d.Close()
	base := path.Base(name)
	if err := d.Check(base); err != nil {
		return nil, err
	}
	before, err := d.R.Lstat(base)
	if err != nil {
		return nil, err
	}
	if forbidden(before) {
		return nil, errors.New("file link forbidden")
	}
	f, err := openRead(d, base)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	st, err := f.Stat()
	if err != nil {
		return nil, err
	}
	if !st.Mode().IsRegular() {
		return nil, errors.New("input must be a regular file")
	}
	if !os.SameFile(before, st) {
		return nil, errors.New("file changed during open")
	}
	if private {
		if err := checkPrivate(f); err != nil {
			return nil, err
		}
	}
	return ReadBounded(f, limit)
}

func (r *Root) List(name string) ([]fs.DirEntry, error) {
	if err := r.Check(name); err != nil {
		return nil, err
	}
	f, err := r.R.Open(name)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	return f.ReadDir(-1)
}

// Write requires the caller's writer lock for a create. Private bytes are only
// written after the newly created file has its platform permissions established.
func (r *Root) Write(name string, data []byte, replace bool) error {
	d, err := r.Sub(path.Dir(name))
	if err != nil {
		return err
	}
	defer d.Close()
	base := path.Base(name)
	if e := d.Check(base); e == nil {
		if !replace {
			return fs.ErrExist
		}
	} else if !errors.Is(e, fs.ErrNotExist) {
		return e
	}
	var random [16]byte
	if _, err = rand.Read(random[:]); err != nil {
		return err
	}
	tmp := ".trove-" + hex.EncodeToString(random[:]) + ".tmp"
	f, err := d.R.OpenFile(tmp, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		return err
	}
	defer d.R.Remove(tmp)
	if err = protect(f); err == nil {
		_, err = f.Write(data)
	}
	if err == nil {
		err = f.Sync()
	}
	closeErr := f.Close()
	if err != nil {
		return err
	}
	if closeErr != nil {
		return closeErr
	}
	if e := d.Check(base); e == nil {
		if !replace {
			return fs.ErrExist
		}
	} else if !errors.Is(e, fs.ErrNotExist) {
		return e
	}
	if replace {
		err = d.R.Rename(tmp, base)
	} else {
		err = d.R.Link(tmp, base)
	}
	if err != nil {
		return err
	}
	return syncDir(d)
}

func (r *Root) Remove(name string) error {
	if err := r.Check(name); err != nil {
		return err
	}
	return r.R.Remove(name)
}

// RemoveTree traverses held child handles, rejects all links, and never calls
// path-based RemoveAll. Preflight rejects links before deleting any child.
func (r *Root) ValidateTree(name string) error {
	d, err := r.Sub(name)
	if err != nil {
		return err
	}
	defer d.Close()
	entries, err := d.List(".")
	if err != nil {
		return err
	}
	for _, e := range entries {
		if err := d.Check(e.Name()); err != nil {
			return err
		}
		if e.IsDir() {
			if err := d.ValidateTree(e.Name()); err != nil {
				return err
			}
		}
	}
	return nil
}

func (r *Root) RemoveTree(name string) error {
	if err := r.ValidateTree(name); err != nil {
		return err
	}
	d, err := r.Sub(name)
	if err != nil {
		return err
	}
	entries, err := d.List(".")
	if err != nil {
		d.Close()
		return err
	}
	for _, e := range entries {
		if e.IsDir() {
			err = d.RemoveTree(e.Name())
		} else {
			err = d.Remove(e.Name())
		}
		if err != nil {
			d.Close()
			return err
		}
	}
	d.Close()
	return r.Remove(name)
}

func (r *Root) Lock() (func(), error) {
	f, err := r.R.OpenFile(".trove.lock", os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		return nil, fmt.Errorf("writer lock: %w (recover stale locks explicitly)", err)
	}
	if err = protect(f); err != nil {
		f.Close()
		r.R.Remove(".trove.lock")
		return nil, err
	}
	owned, err := f.Stat()
	f.Close()
	if err != nil {
		r.R.Remove(".trove.lock")
		return nil, err
	}
	return func() {
		current, err := r.R.Lstat(".trove.lock")
		if err == nil && os.SameFile(owned, current) {
			_ = r.R.Remove(".trove.lock")
		}
	}, nil
}
