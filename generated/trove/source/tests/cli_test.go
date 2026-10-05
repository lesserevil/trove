// These are actual executable tests with real embedded OpenPGP. There is no mock
// or skip path: missing dependencies prevent compilation and acceptance.
package tests

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"encoding/hex"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"trove/internal/pgp"
	"trove/internal/safefs"
)

var binaryPath string

func TestMain(m *testing.M) {
	// Target workers can qualify the exact packaged executable, without rebuilding.
	if artifact := os.Getenv("TROVE_TEST_BINARY"); artifact != "" {
		var err error
		binaryPath, err = filepath.Abs(artifact)
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
		os.Exit(m.Run())
	}
	d, err := os.MkdirTemp("", "trove-binary-")
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	binaryPath = filepath.Join(d, "trove")
	if runtime.GOOS == "windows" {
		binaryPath += ".exe"
	}
	c := exec.Command("go", "build", "-mod=readonly", "-trimpath", "-buildvcs=false", "-o", binaryPath, "./cmd/trove")
	c.Dir = ".."
	c.Stdout = os.Stdout
	c.Stderr = os.Stderr
	if err = c.Run(); err != nil {
		os.RemoveAll(d)
		os.Exit(1)
	}
	status := m.Run()
	os.RemoveAll(d)
	os.Exit(status)
}

type env struct {
	t                             *testing.T
	root, store, alice, bob, pass string
}

func setup(t *testing.T) *env {
	t.Helper()
	parent := os.TempDir()
	if runtime.GOOS != "windows" {
		parent = "/tmp"
	}
	d, err := os.MkdirTemp(parent, "trove-cli-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(d) })
	d, err = filepath.EvalSymlinks(d)
	if err != nil {
		t.Fatal(err)
	}
	e := &env{t: t, root: d, store: filepath.Join(d, "store"), alice: filepath.Join(d, "alice-id"), bob: filepath.Join(d, "bob-id"), pass: filepath.Join(d, "passphrase")}
	private, err := safefs.Open(d, false)
	if err != nil {
		t.Fatal(err)
	}
	if err = private.Private(); err == nil {
		err = private.Write("passphrase", []byte("synthetic-test-passphrase\n"), false)
	}
	private.Close()
	if err != nil {
		t.Fatal(err)
	}
	e.ok(nil, "alice", "init")
	e.ok(nil, "alice", "new-user", "--name", "alice", "--email", "alice@example.invalid")
	e.ok(nil, "bob", "new-user", "--name", "bob", "--email", "bob@example.invalid")
	return e
}

func (e *env) run(input []byte, user string, args ...string) ([]byte, []byte, error) {
	e.t.Helper()
	id := e.alice
	if user == "bob" {
		id = e.bob
	}
	args = append(args, "--store", e.store, "--identity-dir", id, "--user", user, "--passphrase-file", e.pass)
	c := exec.Command(binaryPath, args...)
	c.Stdin = bytes.NewReader(input)
	// Product runs without Go/Make/GPG/OpenSSL/Python or shell discovery.
	for _, v := range os.Environ() {
		if !strings.HasPrefix(v, "PATH=") && !strings.HasPrefix(v, "PM_USER=") {
			c.Env = append(c.Env, v)
		}
	}
	c.Env = append(c.Env, "PATH=")
	var out, errout bytes.Buffer
	c.Stdout = &out
	c.Stderr = &errout
	err := c.Run()
	return out.Bytes(), errout.Bytes(), err
}

func (e *env) ok(input []byte, user string, args ...string) []byte {
	e.t.Helper()
	out, errout, err := e.run(input, user, args...)
	if err != nil {
		e.t.Fatalf("%v: %v: %s", args, err, errout)
	}
	return out
}
func (e *env) fail(input []byte, user string, args ...string) {
	e.t.Helper()
	out, _, err := e.run(input, user, args...)
	if err == nil {
		e.t.Fatalf("expected failure: %v", args)
	}
	if len(out) != 0 {
		e.t.Fatalf("failure released stdout: %v", args)
	}
}
func (e *env) create(name string, p []byte) {
	e.t.Helper()
	e.ok(p, "alice", "create-secret", "--name", name, "--file", "-")
}
func (e *env) read(user, name string) []byte {
	e.t.Helper()
	return e.ok(nil, user, "read-secret", "--name", name)
}

func TestNativeBehaviorParity(t *testing.T) {
	cases := map[string]func(*env){
		"missing params": func(e *env) { e.fail(nil, "alice", "create-secret") },
		"grant without access": func(e *env) {
			e.create("key", nil)
			e.fail(nil, "bob", "grant-access", "--name", "key", "--recipient", "bob")
		},
		"empty store lists": func(e *env) {
			if len(e.ok(nil, "alice", "list-secrets")) != 0 {
				e.t.Fatal("empty store not empty")
			}
		},
		"check dependencies": func(e *env) { e.ok(nil, "alice", "check-deps") },
		"delete nonexistent": func(e *env) { e.fail(nil, "alice", "delete-secret", "--name", "missing") },
		"revoke nonexistent envelope": func(e *env) {
			e.create("key", nil)
			e.fail(nil, "alice", "revoke-access", "--name", "key", "--recipient", "bob")
		},
		"grant duplicate": func(e *env) {
			e.create("key", nil)
			e.ok(nil, "alice", "grant-access", "--name", "key", "--recipient", "bob")
			e.fail(nil, "alice", "grant-access", "--name", "key", "--recipient", "bob")
		},
		"update without access": func(e *env) {
			e.create("key", []byte("keep"))
			e.fail([]byte("bad"), "bob", "update-secret", "--name", "key")
			if string(e.read("alice", "key")) != "keep" {
				e.t.Fatal("unauthorized update changed data")
			}
		},
		"init structure": func(e *env) {
			for _, d := range []string{"users", "secrets"} {
				if _, err := os.Stat(filepath.Join(e.store, d)); err != nil {
					e.t.Fatal(err)
				}
			}
			if _, err := os.Stat(filepath.Join(e.store, ".gnupg")); !os.IsNotExist(err) {
				e.t.Fatal("repository keyring created")
			}
		},
		"public registration": func(e *env) {
			pub, err := os.ReadFile(filepath.Join(e.store, "users/alice.pub"))
			if err != nil {
				e.t.Fatal(err)
			}
			e.ok(pub, "alice", "add-user", "--name", "carol", "--key", "-")
		},
		"text round trip": func(e *env) {
			p := []byte("secret text\n")
			e.create("text", p)
			if !bytes.Equal(e.read("alice", "text"), p) {
				e.t.Fatal("changed text bytes")
			}
		},
		"binary round trip": func(e *env) {
			p := bytes.Repeat([]byte{0, 255, 10, 13, 128}, 2048)
			e.create("binary", p)
			if !bytes.Equal(e.read("alice", "binary"), p) {
				e.t.Fatal("changed binary bytes")
			}
		},
		"duplicate create": func(e *env) {
			e.create("dup", []byte("first"))
			e.fail([]byte("second"), "alice", "create-secret", "--name", "dup")
			if string(e.read("alice", "dup")) != "first" {
				e.t.Fatal("original changed")
			}
		},
		"grant access": func(e *env) {
			e.create("shared", []byte("shared"))
			e.ok(nil, "alice", "grant-access", "--name", "shared", "--recipient", "bob")
			if string(e.read("bob", "shared")) != "shared" {
				e.t.Fatal("grant failed")
			}
		},
		"revoke envelope": func(e *env) {
			e.create("rev", []byte("rev"))
			e.ok(nil, "alice", "grant-access", "--name", "rev", "--recipient", "bob")
			e.ok(nil, "alice", "revoke-access", "--name", "rev", "--recipient", "bob")
			if _, err := os.Stat(filepath.Join(e.store, "secrets/rev/bob.key.enc")); !os.IsNotExist(err) {
				e.t.Fatal("envelope retained")
			}
		},
		"revoke denies read": func(e *env) {
			e.create("rev", []byte("rev"))
			e.ok(nil, "alice", "grant-access", "--name", "rev", "--recipient", "bob")
			e.ok(nil, "alice", "revoke-access", "--name", "rev", "--recipient", "bob")
			e.fail(nil, "bob", "read-secret", "--name", "rev")
		},
		"unauthorized read": func(e *env) {
			e.create("private", []byte("private"))
			e.fail(nil, "bob", "read-secret", "--name", "private")
		},
		"list secrets": func(e *env) {
			e.create("nested/key", []byte("x"))
			if !bytes.Contains(e.ok(nil, "alice", "list-secrets"), []byte("nested/key")) {
				e.t.Fatal("secret absent")
			}
		},
		"list users": func(e *env) {
			out := e.ok(nil, "alice", "list-users")
			if !bytes.Contains(out, []byte("alice")) || !bytes.Contains(out, []byte("bob")) {
				e.t.Fatal("missing users")
			}
		},
		"delete secret": func(e *env) {
			e.create("delete", nil)
			e.ok(nil, "alice", "delete-secret", "--name", "delete")
			if _, err := os.Stat(filepath.Join(e.store, "secrets/delete")); !os.IsNotExist(err) {
				e.t.Fatal("delete failed")
			}
		},
		"missing file": func(e *env) {
			e.fail(nil, "alice", "create-secret", "--name", "missing", "--file", filepath.Join(e.root, "absent"))
		},
		"missing secret": func(e *env) { e.fail(nil, "alice", "read-secret", "--name", "missing") },
		"invalid name":   func(e *env) { e.fail(nil, "alice", "create-secret", "--name", "../escape") },
		"unregistered recipient": func(e *env) {
			e.create("key", nil)
			e.fail(nil, "alice", "grant-access", "--name", "key", "--recipient", "missing")
		},
		"update text": func(e *env) {
			e.create("update", []byte("old"))
			e.ok([]byte("new\n"), "alice", "update-secret", "--name", "update")
			if string(e.read("alice", "update")) != "new\n" {
				e.t.Fatal("update failed")
			}
		},
		"update preserves recipients": func(e *env) {
			e.create("update", []byte("old"))
			e.ok(nil, "alice", "grant-access", "--name", "update", "--recipient", "bob")
			old, _ := os.ReadFile(filepath.Join(e.store, "secrets/update/bob.key.enc"))
			e.ok([]byte("new"), "alice", "update-secret", "--name", "update")
			now, _ := os.ReadFile(filepath.Join(e.store, "secrets/update/bob.key.enc"))
			if !bytes.Equal(old, now) || string(e.read("bob", "update")) != "new" {
				e.t.Fatal("recipient lost")
			}
		},
		"update binary": func(e *env) {
			e.create("update", nil)
			p := []byte{0, 1, 255, 10, 13}
			e.ok(p, "alice", "update-secret", "--name", "update")
			if !bytes.Equal(e.read("alice", "update"), p) {
				e.t.Fatal("binary update corrupted")
			}
		},
		"update missing secret": func(e *env) { e.fail(nil, "alice", "update-secret", "--name", "missing") },
		"update missing input": func(e *env) {
			e.create("update", []byte("keep"))
			e.fail(nil, "alice", "update-secret", "--name", "update", "--file", filepath.Join(e.root, "absent"))
			if string(e.read("alice", "update")) != "keep" {
				e.t.Fatal("failed update changed content")
			}
		},
		"protected export": func(e *env) {
			d := filepath.Join(e.root, "export")
			if err := os.Mkdir(d, 0700); err != nil {
				e.t.Fatal(err)
			}
			e.ok(nil, "alice", "export-key", "--name", "alice", "--dir", d)
			if runtime.GOOS != "windows" {
				st, _ := os.Stat(filepath.Join(d, "alice.secret.key"))
				if st.Mode().Perm() != 0600 {
					e.t.Fatal("readable private export")
				}
			}
		},
		"private import": func(e *env) {
			priv, err := os.ReadFile(filepath.Join(e.alice, "alice.secret.key"))
			if err != nil {
				e.t.Fatal(err)
			}
			e.ok(priv, "bob", "import-secret-key", "--name", "carol", "--key", "-")
		},
		"duplicate user": func(e *env) {
			pub, _ := os.ReadFile(filepath.Join(e.store, "users/alice.pub"))
			e.fail(pub, "alice", "add-user", "--name", "alice", "--key", "-")
		},
		"empty secret": func(e *env) {
			e.create("empty", nil)
			if len(e.read("alice", "empty")) != 0 {
				e.t.Fatal("empty bytes changed")
			}
		},
	}
	for name, fn := range cases {
		t.Run(name, func(t *testing.T) { e := setup(t); fn(e) })
	}
}

func TestSecurityRegressions(t *testing.T) {
	e := setup(t)
	private, _ := os.ReadFile(filepath.Join(e.alice, "alice.secret.key"))
	e.fail(private, "alice", "add-user", "--name", "private-leak", "--key", "-")
	pub, _ := os.ReadFile(filepath.Join(e.store, "users/alice.pub"))
	e.fail(append(pub, private...), "alice", "add-user", "--name", "mixed", "--key", "-")
	e.fail([]byte("junk"), "alice", "add-user", "--name", "bad", "--key", "-")
	e.fail(nil, "alice", "create-secret", "--name", "$(touch-pwn)")
	e.create("auth", []byte("must never leak"))
	f := filepath.Join(e.store, "secrets/auth/secret.enc")
	original, _ := os.ReadFile(f)
	for i := range original {
		bad := append([]byte(nil), original...)
		bad[i] ^= 1
		if err := os.WriteFile(f, bad, 0600); err != nil {
			t.Fatal(err)
		}
		e.fail(nil, "alice", "read-secret", "--name", "auth")
	}
	if err := os.WriteFile(f, original, 0600); err != nil {
		t.Fatal(err)
	}
	if runtime.GOOS != "windows" {
		outside := filepath.Join(e.root, "sentinel")
		os.WriteFile(outside, []byte("outside"), 0600)
		if err := os.Symlink(outside, filepath.Join(e.store, "secrets/auth/link")); err != nil {
			t.Fatal(err)
		}
		e.fail(nil, "alice", "delete-secret", "--name", "auth")
		b, _ := os.ReadFile(outside)
		if string(b) != "outside" {
			t.Fatal("outside sentinel changed")
		}
		st, _ := os.Stat(filepath.Join(e.alice, "alice.secret.key"))
		if st.Mode().Perm() != 0600 {
			t.Fatal("private key permissions")
		}
	}
	entries, _ := os.ReadDir(e.store)
	for _, x := range entries {
		if x.Name() != "users" && x.Name() != "secrets" {
			t.Fatalf("runtime state leaked: %s", x.Name())
		}
	}
}

func TestExplicitLegacyMigration(t *testing.T) {
	e := setup(t)
	e.create("legacy", []byte("fixture"))
	e.ok(nil, "alice", "grant-access", "--name", "legacy", "--recipient", "bob")
	priv, _ := os.ReadFile(filepath.Join(e.alice, "alice.secret.key"))
	env, _ := os.ReadFile(filepath.Join(e.store, "secrets/legacy/alice.key.enc"))
	rootText, err := (pgp.Backend{}).Unwrap(priv, []byte("synthetic-test-passphrase"), env)
	if err != nil {
		t.Fatal(err)
	}
	defer clear(rootText)
	key, err := hex.DecodeString(strings.TrimSpace(string(rootText)))
	if err != nil {
		t.Fatal(err)
	}
	defer clear(key)
	plain := []byte("independent CBC fixture\x00\xff")
	iv := bytes.Repeat([]byte{13}, 16)
	n := 16 - len(plain)%16
	padded := append(append([]byte(nil), plain...), bytes.Repeat([]byte{byte(n)}, n)...)
	c := make([]byte, len(padded))
	block, _ := aes.NewCipher(key)
	cipher.NewCBCEncrypter(block, iv).CryptBlocks(c, padded)
	legacy := append([]byte(hex.EncodeToString(iv)+"\n"), c...)
	f := filepath.Join(e.store, "secrets/legacy/secret.enc")
	if err := os.WriteFile(f, legacy, 0600); err != nil {
		t.Fatal(err)
	}
	e.fail(nil, "alice", "read-secret", "--name", "legacy")
	e.fail(nil, "alice", "migrate", "--name", "legacy")
	e.ok(nil, "alice", "migrate", "--name", "legacy", "--accept-unauthenticated-legacy")
	backup, _ := os.ReadFile(f + ".legacy")
	if !bytes.Equal(backup, legacy) {
		t.Fatal("backup changed")
	}
	if !bytes.Equal(e.read("alice", "legacy"), plain) || !bytes.Equal(e.read("bob", "legacy"), plain) {
		t.Fatal("migration changed access or content")
	}
	before, _ := os.ReadFile(f)
	e.ok(nil, "alice", "migrate", "--name", "legacy", "--accept-unauthenticated-legacy")
	after, _ := os.ReadFile(f)
	if !bytes.Equal(before, after) {
		t.Fatal("restart rewrote authenticated content")
	}
}
