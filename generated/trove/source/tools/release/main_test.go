package main

import (
	"archive/tar"
	"archive/zip"
	"bytes"
	"compress/gzip"
	"io"
	"os"
	"path/filepath"
	"testing"
)

func TestDeterministicPortableArchives(t *testing.T) {
	for _, kind := range []string{"zip", "tar.gz"} {
		t.Run(kind, func(t *testing.T) {
			d := t.TempDir()
			binary := "trove"
			if kind == "zip" {
				binary += ".exe"
			}
			entries := []entry{{binary, []byte{0, 255, 10, 128}, 0755}, {"README.md", []byte("guide\n"), 0644}}
			one, two := filepath.Join(d, "one"), filepath.Join(d, "two")
			if err := archive(one, kind, entries); err != nil {
				t.Fatal(err)
			}
			if err := archive(two, kind, entries); err != nil {
				t.Fatal(err)
			}
			a, _ := os.ReadFile(one)
			b, _ := os.ReadFile(two)
			if !bytes.Equal(a, b) {
				t.Fatal("nondeterministic archive")
			}
			if err := archive(one, kind, entries); err == nil {
				t.Fatal("existing archive overwritten")
			}
			if kind == "zip" {
				r, err := zip.OpenReader(one)
				if err != nil {
					t.Fatal(err)
				}
				defer r.Close()
				if len(r.File) != len(entries) {
					t.Fatal("unexpected entries")
				}
				for i, f := range r.File {
					if f.Name != entries[i].name || f.Mode().Perm() != os.FileMode(entries[i].mode) {
						t.Fatal("incorrect ZIP name or permissions")
					}
					in, _ := f.Open()
					got, err := io.ReadAll(in)
					in.Close()
					if err != nil || !bytes.Equal(got, entries[i].data) {
						t.Fatal("incorrect ZIP bytes")
					}
				}
			} else {
				g, err := gzip.NewReader(bytes.NewReader(a))
				if err != nil {
					t.Fatal(err)
				}
				defer g.Close()
				r := tar.NewReader(g)
				for _, e := range entries {
					h, err := r.Next()
					if err != nil || h.Name != e.name || h.Mode != e.mode {
						t.Fatal("incorrect tar entry")
					}
					got, err := io.ReadAll(r)
					if err != nil || !bytes.Equal(got, e.data) {
						t.Fatal("incorrect tar bytes")
					}
				}
				if _, err := r.Next(); err != io.EOF {
					t.Fatal("unexpected tar member")
				}
			}
		})
	}
}
