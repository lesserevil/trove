package safefs

import (
	"bytes"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

func fixture(t *testing.T) (*Root, string) {
	t.Helper()
	// macOS's system temporary directory has a /var alias; fixtures use its canonical path.
	d, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	r, err := Open(d, false)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { r.Close() })
	if err := r.Private(); err != nil {
		t.Fatal(err)
	}
	return r, d
}

func TestNames(t *testing.T) {
	for _, bad := range []string{"", ".", "..", "/absolute", "a/../b", "a//b", "a\\b", "a;id", "$(id)", "a\n", "NUL", "con.txt", "COM1", "LPT9.log", "trail.", "a b"} {
		if Name(bad, true) == nil {
			t.Fatalf("accepted %q", bad)
		}
	}
	for _, good := range []string{"alice", "alice@host", "foo/bar", "db-password_2", "COM10"} {
		if err := Name(good, true); err != nil {
			t.Fatalf("%q: %v", good, err)
		}
	}
	if Name("a/b", false) == nil {
		t.Fatal("nested identity accepted")
	}
}

func TestAtomicWritesLockAndPermissions(t *testing.T) {
	r, d := fixture(t)
	unlock, err := r.Lock()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := r.Lock(); err == nil {
		t.Fatal("concurrent writer admitted")
	}
	unlock()
	unlock, err = r.Lock()
	if err != nil {
		t.Fatal(err)
	}
	defer unlock()
	if err := r.MkdirAll("one/two"); err != nil {
		t.Fatal(err)
	}
	if err := r.Write("one/two/key", []byte("original"), false); err != nil {
		t.Fatal(err)
	}
	if err := r.Write("one/two/key", []byte("bad"), false); !errors.Is(err, fs.ErrExist) {
		t.Fatal("overwrote existing file")
	}
	if err := r.Write("one/two/key", []byte("new"), true); err != nil {
		t.Fatal(err)
	}
	b, err := r.Read("one/two/key", 3)
	if err != nil || string(b) != "new" {
		t.Fatal(err)
	}
	if _, err := r.Read("one/two/key", 2); err == nil {
		t.Fatal("size limit not enforced")
	}
	if runtime.GOOS != "windows" {
		for p, mode := range map[string]fs.FileMode{"one": 0700, "one/two": 0700, "one/two/key": 0600} {
			st, err := os.Stat(filepath.Join(d, p))
			if err != nil || st.Mode().Perm() != mode {
				t.Fatalf("%s permissions: %v", p, err)
			}
		}
	}
	entries, _ := r.List("one/two")
	if len(entries) != 1 {
		t.Fatal("temporary files leaked")
	}
}

func TestLinksCannotReadWriteOrDeleteOutside(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Windows reparse fixtures require target runner")
	}
	r, d := fixture(t)
	_, outside := fixture(t)
	sentinel := filepath.Join(outside, "sentinel")
	if err := os.WriteFile(sentinel, []byte("untouched"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, filepath.Join(d, "escape")); err != nil {
		t.Fatal(err)
	}
	if _, err := r.Read("escape/sentinel", 20); err == nil {
		t.Fatal("link read accepted")
	}
	if err := r.Write("escape/sentinel", []byte("bad"), true); err == nil {
		t.Fatal("link write accepted")
	}
	if err := r.RemoveTree("escape"); err == nil {
		t.Fatal("link delete accepted")
	}
	if err := r.Mkdir("owned"); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(sentinel, filepath.Join(d, "owned", "link")); err != nil {
		t.Fatal(err)
	}
	if err := r.RemoveTree("owned"); err == nil {
		t.Fatal("mixed tree with link deleted")
	}
	b, _ := os.ReadFile(sentinel)
	if string(b) != "untouched" {
		t.Fatal("outside changed")
	}
	if _, err := Open(filepath.Join(d, "escape"), false); err == nil {
		t.Fatal("linked root accepted")
	}
}

func TestHeldRootSurvivesReplacement(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("directory rename with held handles requires target runner")
	}
	r, d := fixture(t)
	if err := r.Mkdir("owned"); err != nil {
		t.Fatal(err)
	}
	child, err := r.Sub("owned")
	if err != nil {
		t.Fatal(err)
	}
	defer child.Close()
	if err := r.R.Rename("owned", "moved"); err != nil {
		t.Fatal(err)
	}
	_, outside := fixture(t)
	if err := os.Symlink(outside, filepath.Join(d, "owned")); err != nil {
		t.Fatal(err)
	}
	if err := child.Write("inside", []byte("held"), false); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(outside, "inside")); !errors.Is(err, fs.ErrNotExist) {
		t.Fatal("held root escaped")
	}
	b, err := r.Read("moved/inside", 10)
	if err != nil || string(b) != "held" {
		t.Fatal(err)
	}
}

func TestBoundedInputAndRecursiveDelete(t *testing.T) {
	if _, err := ReadBounded(bytes.NewReader([]byte("1234")), 3); err == nil {
		t.Fatal("unbounded input")
	}
	r, _ := fixture(t)
	if err := r.MkdirAll("a/b/c"); err != nil {
		t.Fatal(err)
	}
	if err := r.Write("a/b/c/f", []byte("x"), false); err != nil {
		t.Fatal(err)
	}
	if err := r.RemoveTree("a"); err != nil {
		t.Fatal(err)
	}
	if err := r.Check("a"); !errors.Is(err, fs.ErrNotExist) {
		t.Fatal("delete incomplete")
	}
}

func TestCreateRaceDoesNotOverwrite(t *testing.T) {
	r, _ := fixture(t)
	results := make(chan error, 2)
	for _, value := range []string{"first", "second"} {
		go func(v string) { results <- r.Write("create", []byte(v), false) }(value)
	}
	a, b := <-results, <-results
	if (a == nil) == (b == nil) {
		t.Fatalf("expected one exclusive create: %v / %v", a, b)
	}
	got, err := r.Read("create", 20)
	if err != nil || string(got) != "first" && string(got) != "second" {
		t.Fatal("racing create corrupted data")
	}
}

func TestUnlockPreservesReplacedLock(t *testing.T) {
	r, _ := fixture(t)
	unlock, err := r.Lock()
	if err != nil {
		t.Fatal(err)
	}
	if err = r.R.Rename(".trove.lock", "owned-lock"); err != nil {
		t.Fatal(err)
	}
	if err = r.Write(".trove.lock", []byte("replacement"), false); err != nil {
		t.Fatal(err)
	}
	unlock()
	got, err := r.Read(".trove.lock", 20)
	if err != nil || string(got) != "replacement" {
		t.Fatal("unlock removed another writer's replacement")
	}
}
