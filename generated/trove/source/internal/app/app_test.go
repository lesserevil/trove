package app

import (
	"bytes"
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

// These tests do not supply a crypto backend. They qualify only parsing and setup.
func TestLiteralInputRejectedBeforeStoreCreation(t *testing.T) {
	d, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"$(touch pwn)", "a;touch pwn", "../../escape", "NUL", "a\\b"} {
		a := App{In: bytes.NewReader(nil), Out: &bytes.Buffer{}, Err: &bytes.Buffer{}}
		if err := a.Run([]string{"create-secret", "--name", name, "--store", filepath.Join(d, "missing")}); err == nil {
			t.Fatal("unsafe name accepted")
		}
	}
	entries, _ := os.ReadDir(d)
	if len(entries) != 0 {
		t.Fatal("validation mutated files")
	}
}

func TestHelpVersionAndDependencyCheckNeedNoStore(t *testing.T) {
	for _, name := range []string{"HOME", "APPDATA", "XDG_CONFIG_HOME"} {
		t.Setenv(name, "")
	}
	for _, args := range [][]string{{"help"}, {"version"}, {"check-deps"}, {"create-secret", "--help"}} {
		var out, errout bytes.Buffer
		a := App{In: bytes.NewReader(nil), Out: &out, Err: &errout, Version: "test"}
		if err := a.Run(args); err != nil {
			t.Fatal(err)
		}
		if out.Len()+errout.Len() == 0 {
			t.Fatal("no help output")
		}
	}
}

func TestInitDoesNotCreateRepositoryIdentities(t *testing.T) {
	// Go may propagate workspace GOTMPDIR as test TMPDIR. Identity fixtures must
	// still be outside the source repository, like actual personal identities.
	parent := os.TempDir()
	if runtime.GOOS != "windows" {
		parent = "/tmp"
	}
	tmp, err := os.MkdirTemp(parent, "trove-native-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(tmp) })
	d, err := filepath.EvalSymlinks(tmp)
	if err != nil {
		t.Fatal(err)
	}
	store, identities := filepath.Join(d, "store"), filepath.Join(d, "personal")
	a := App{In: bytes.NewReader(nil), Out: &bytes.Buffer{}, Err: &bytes.Buffer{}}
	if err := a.Run([]string{"init", "--store", store, "--identity-dir", identities}); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"users", "secrets"} {
		if _, err := os.Stat(filepath.Join(store, name)); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := os.Stat(identities); !os.IsNotExist(err) {
		t.Fatal("init created personal identity state")
	}
	if err := a.Run([]string{"init", "--store", store, "--identity-dir", filepath.Join(store, "private")}); err == nil {
		t.Fatal("repository identity directory accepted")
	}
}
