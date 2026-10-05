// Contributor packaging only. Product commands never execute external programs.
package main

import (
	"archive/tar"
	"archive/zip"
	"compress/gzip"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"sort"
	"strings"
	"time"
)

type target struct{ OS, Arch, Label, Archive string }
type entry struct {
	name string
	data []byte
	mode int64
}

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, "package:", err)
		os.Exit(1)
	}
}

func run() error {
	version := flag.String("version", "development", "version label")
	matrix := flag.String("matrix", "../../../flavors/go-trove/release-targets.json", "authored target matrix")
	out := flag.String("out", "../../../_build/releases", "new output directory")
	guide := flag.String("guide", "../../../docs/user/native-client.md", "native usage guide")
	license := flag.String("license", "", "optional authored application distribution license; no license is invented")
	flag.Parse()
	if !regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,60}$`).MatchString(*version) {
		return fmt.Errorf("invalid version")
	}
	b, err := os.ReadFile(*matrix)
	if err != nil {
		return err
	}
	var targets []target
	if err = json.Unmarshal(b, &targets); err != nil {
		return err
	}
	if len(targets) != 5 {
		return fmt.Errorf("release matrix must contain exactly five targets")
	}
	expected := map[string]bool{"linux/amd64": true, "linux/arm64": true, "windows/amd64": true, "windows/arm64": true, "darwin/arm64": true}
	for _, t := range targets {
		id := t.OS + "/" + t.Arch
		if !expected[id] {
			return fmt.Errorf("duplicate or invalid target %s", id)
		}
		delete(expected, id)
		if !regexp.MustCompile(`^[a-z0-9_]+$`).MatchString(t.Label) {
			return fmt.Errorf("invalid archive label")
		}
		if t.OS == "windows" && t.Archive != "zip" || t.OS != "windows" && t.Archive != "tar.gz" {
			return fmt.Errorf("invalid archive format")
		}
	}
	readme, err := os.ReadFile(*guide)
	if err != nil {
		return err
	}
	thirdParty, err := dependencyNotices()
	if err != nil {
		return err
	}
	licenseText := append([]byte("Third-party software licenses. These texts do not grant a license to Trove itself.\n"), thirdParty...)
	if *license != "" {
		application, err := os.ReadFile(*license)
		if err != nil {
			return err
		}
		licenseText = append(append(application, '\n'), licenseText...)
	}
	// Refuse existing output, so partial builds cannot be confused with a complete
	// set or erase a caller's archives. Remove only this allocated tree on failure.
	if err = os.Mkdir(*out, 0700); err != nil {
		return err
	}
	complete := false
	defer func() {
		if !complete {
			os.RemoveAll(*out)
		}
	}()
	var sums []string
	for _, t := range targets {
		binary := "trove"
		if t.OS == "windows" {
			binary += ".exe"
		}
		binaryPath := filepath.Join(*out, t.Label+"-"+binary)
		cmd := exec.Command("go", "build", "-mod=readonly", "-trimpath", "-buildvcs=false", "-ldflags=-s -w -X main.version="+*version, "-o", binaryPath, "./cmd/trove")
		for _, v := range os.Environ() {
			if !strings.HasPrefix(v, "GOOS=") && !strings.HasPrefix(v, "GOARCH=") && !strings.HasPrefix(v, "CGO_ENABLED=") {
				cmd.Env = append(cmd.Env, v)
			}
		}
		cmd.Env = append(cmd.Env, "GOOS="+t.OS, "GOARCH="+t.Arch, "CGO_ENABLED=0")
		cmd.Stdout = os.Stdout
		cmd.Stderr = os.Stderr
		if err = cmd.Run(); err != nil {
			return fmt.Errorf("build %s/%s: %w", t.OS, t.Arch, err)
		}
		data, err := os.ReadFile(binaryPath)
		if err != nil {
			return err
		}
		name := "trove_" + *version + "_" + t.Label + "." + t.Archive
		archivePath := filepath.Join(*out, name)
		if err = archive(archivePath, t.Archive, []entry{{binary, data, 0755}, {"README.md", readme, 0644}, {"LICENSE", licenseText, 0644}, {"THIRD_PARTY_NOTICES", thirdParty, 0644}}); err != nil {
			return err
		}
		file, err := os.Open(archivePath)
		if err != nil {
			return err
		}
		h := sha256.New()
		_, err = io.Copy(h, file)
		closeErr := file.Close()
		if err != nil {
			return err
		}
		if closeErr != nil {
			return closeErr
		}
		sums = append(sums, hex.EncodeToString(h.Sum(nil))+"  "+name)
		if err = os.Remove(binaryPath); err != nil {
			return err
		}
	}
	sort.Strings(sums)
	if err = os.WriteFile(filepath.Join(*out, "SHA256SUMS"), []byte(strings.Join(sums, "\n")+"\n"), 0600); err != nil {
		return err
	}
	complete = true
	fmt.Fprintln(os.Stderr, "Built five archives. Target runtime qualification is still required before release.")
	return nil
}

func dependencyNotices() ([]byte, error) {
	cmd := exec.Command("go", "list", "-mod=readonly", "-deps", "-json", "./cmd/trove")
	data, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("resolve dependency notices: %w", err)
	}
	type module struct {
		Path, Version, Dir string
		Main               bool
	}
	type pkg struct{ Module *module }
	dec := json.NewDecoder(strings.NewReader(string(data)))
	var notices strings.Builder
	goLicense, err := os.ReadFile(filepath.Join(runtime.GOROOT(), "LICENSE"))
	if err != nil {
		return nil, fmt.Errorf("collect Go runtime license: %w", err)
	}
	fmt.Fprintf(&notices, "Go runtime and standard library %s — LICENSE\n\n%s\n", runtime.Version(), goLicense)
	seen := map[string]bool{}
	for {
		var p pkg
		if err := dec.Decode(&p); err == io.EOF {
			break
		} else if err != nil {
			return nil, err
		}
		if p.Module == nil || p.Module.Main || seen[p.Module.Path] {
			continue
		}
		m := *p.Module
		seen[m.Path] = true
		files, err := os.ReadDir(m.Dir)
		if err != nil {
			return nil, err
		}
		found := false
		for _, f := range files {
			name := strings.ToUpper(f.Name())
			if !f.IsDir() && (strings.HasPrefix(name, "LICENSE") || strings.HasPrefix(name, "COPYING")) {
				b, err := os.ReadFile(filepath.Join(m.Dir, f.Name()))
				if err != nil {
					return nil, err
				}
				fmt.Fprintf(&notices, "\n%s %s — %s\n\n%s\n", m.Path, m.Version, f.Name(), b)
				found = true
			}
		}
		if !found {
			return nil, fmt.Errorf("dependency %s has no collected distribution license", m.Path)
		}
	}
	return []byte(notices.String()), nil
}

func archive(filename, kind string, entries []entry) error {
	f, err := os.OpenFile(filename, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if err != nil {
		return err
	}
	defer f.Close()
	if kind == "zip" {
		w := zip.NewWriter(f)
		for _, e := range entries {
			h := &zip.FileHeader{Name: e.name, Method: zip.Deflate}
			h.SetMode(os.FileMode(e.mode))
			h.SetModTime(time.Unix(0, 0).UTC())
			item, err := w.CreateHeader(h)
			if err != nil {
				w.Close()
				return err
			}
			if _, err = item.Write(e.data); err != nil {
				w.Close()
				return err
			}
		}
		if err = w.Close(); err != nil {
			return err
		}
	} else {
		g := gzip.NewWriter(f)
		w := tar.NewWriter(g)
		for _, e := range entries {
			if err = w.WriteHeader(&tar.Header{Name: e.name, Mode: e.mode, Size: int64(len(e.data)), ModTime: time.Unix(0, 0).UTC(), Format: tar.FormatUSTAR}); err != nil {
				w.Close()
				g.Close()
				return err
			}
			if _, err = w.Write(e.data); err != nil {
				w.Close()
				g.Close()
				return err
			}
		}
		if err = w.Close(); err != nil {
			g.Close()
			return err
		}
		if err = g.Close(); err != nil {
			return err
		}
	}
	return f.Sync()
}
