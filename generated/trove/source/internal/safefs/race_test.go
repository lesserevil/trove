//go:build !windows

package safefs

import (
	"os"
	"path/filepath"
	"sync"
	"testing"
)

func TestConcurrentDirectoryReplacementCannotEscape(t *testing.T) {
	r, d := fixture(t)
	_, outside := fixture(t)
	if err := r.Mkdir("slot"); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(outside, "sentinel"), []byte("untouched"), 0600); err != nil {
		t.Fatal(err)
	}
	stop := make(chan struct{})
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		for {
			select {
			case <-stop:
				return
			default:
			}
			if os.Rename(filepath.Join(d, "slot"), filepath.Join(d, "moved")) == nil {
				if os.Symlink(outside, filepath.Join(d, "slot")) == nil {
					os.Remove(filepath.Join(d, "slot"))
				}
				os.Rename(filepath.Join(d, "moved"), filepath.Join(d, "slot"))
			}
		}
	}()
	leaked := false
	for i := 0; i < 200; i++ {
		_ = r.Write("slot/sentinel", []byte("contained"), true)
		if got, err := r.Read("slot/sentinel", 100); err == nil && string(got) != "contained" {
			leaked = true
		}
	}
	close(stop)
	wg.Wait()
	if leaked {
		t.Fatal("read escaped during directory replacement")
	}
	b, err := os.ReadFile(filepath.Join(outside, "sentinel"))
	if err != nil || string(b) != "untouched" {
		t.Fatal("outside write/read escape")
	}
}

func TestPrivateFileRejectsBroadPermissions(t *testing.T) {
	r, d := fixture(t)
	if err := r.Write("private", []byte("synthetic"), false); err != nil {
		t.Fatal(err)
	}
	if _, err := r.ReadPrivate("private", 100); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(filepath.Join(d, "private"), 0644); err != nil {
		t.Fatal(err)
	}
	if _, err := r.ReadPrivate("private", 100); err == nil {
		t.Fatal("readable private file accepted")
	}
}
