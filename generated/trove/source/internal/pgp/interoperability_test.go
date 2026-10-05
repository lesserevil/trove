//go:build interoperability

package pgp

import (
	"bytes"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// This explicit contributor gate requires GPG. The product never calls it.
// All commands use this test's newly allocated, synthetic keyring.
func TestGPGInteroperability(t *testing.T) {
	gpg, err := exec.LookPath("gpg")
	if err != nil {
		t.Fatal("GPG is required for the explicit interoperability gate:", err)
	}
	home, err := os.MkdirTemp("", "trove-interop-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if conf, err := exec.LookPath("gpgconf"); err == nil {
			_ = exec.Command(conf, "--homedir", home, "--kill", "gpg-agent").Run()
		}
		_ = os.RemoveAll(home)
	})
	if err := os.Chmod(home, 0700); err != nil {
		t.Fatal(err)
	}
	pass := []byte("synthetic-interop-passphrase")
	passfile := filepath.Join(home, "passphrase")
	if err := os.WriteFile(passfile, pass, 0600); err != nil {
		t.Fatal(err)
	}
	run := func(input []byte, args ...string) []byte {
		t.Helper()
		base := []string{"--homedir", home, "--batch", "--yes", "--pinentry-mode", "loopback", "--passphrase-file", passfile}
		cmd := exec.Command(gpg, append(base, args...)...)
		cmd.Stdin = bytes.NewReader(input)
		var out, stderr bytes.Buffer
		cmd.Stdout, cmd.Stderr = &out, &stderr
		if err := cmd.Run(); err != nil {
			t.Fatalf("GPG %v: %v: %s", args, err, stderr.Bytes())
		}
		return out.Bytes()
	}
	b := Backend{}
	pub, priv, fingerprint, err := b.Generate("synthetic", "trove@example.invalid", pass)
	if err != nil {
		t.Fatal(err)
	}
	run(priv, "--import")
	root := []byte("0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef\n")
	envelope, err := b.Wrap(pub, root)
	if err != nil {
		t.Fatal(err)
	}
	if got := run(envelope, "--decrypt"); !bytes.Equal(got, root) {
		t.Fatal("GPG could not decrypt the native root-key envelope")
	}
	envelope = run(root, "--armor", "--trust-model", "always", "--recipient", fingerprint, "--encrypt")
	if got, err := b.Unwrap(priv, pass, envelope); err != nil || !bytes.Equal(got, root) {
		t.Fatal("native adapter could not decrypt GPG's envelope:", err)
	}
	// A independently generated GPG identity exercises import in the other direction.
	uid := "gpg-synthetic <gpg-trove@example.invalid>"
	run(nil, "--quick-generate-key", uid, "future-default", "default", "1d")
	gpgpub := run(nil, "--armor", "--export", uid)
	gpgpriv := run(nil, "--armor", "--export-secret-keys", uid)
	normal, imported, _, err := b.Import(gpgpriv, pass)
	if err != nil {
		t.Fatal("GPG private identity import:", err)
	}
	if _, _, err := b.Public(gpgpub); err != nil {
		t.Fatal("GPG public identity import:", err)
	}
	envelope, err = b.Wrap(normal, root)
	if err != nil {
		t.Fatal(err)
	}
	if got := run(envelope, "--decrypt"); !bytes.Equal(got, root) {
		t.Fatal("GPG could not decrypt envelope for its imported identity")
	}
	if got, err := b.Unwrap(imported, pass, envelope); err != nil || !bytes.Equal(got, root) {
		t.Fatal("imported identity round trip:", err)
	}
	// Retained software identities also commonly use RSA encryption subkeys.
	rsaUID := "rsa-synthetic <rsa-trove@example.invalid>"
	run(nil, "--quick-generate-key", rsaUID, "rsa3072", "cert,sign", "1d")
	var rsaFingerprint string
	for _, line := range strings.Split(string(run(nil, "--with-colons", "--list-keys", rsaUID)), "\n") {
		fields := strings.Split(line, ":")
		if len(fields) > 9 && fields[0] == "fpr" {
			rsaFingerprint = fields[9]
			break
		}
	}
	if rsaFingerprint == "" {
		t.Fatal("GPG did not return the synthetic RSA fingerprint")
	}
	run(nil, "--quick-add-key", rsaFingerprint, "rsa3072", "encrypt", "1d")
	rsaPrivate := run(nil, "--armor", "--export-secret-keys", rsaUID)
	rsaPublic, rsaImported, _, err := b.Import(rsaPrivate, pass)
	if err != nil {
		t.Fatal("GPG RSA private identity import:", err)
	}
	envelope, err = b.Wrap(rsaPublic, root)
	if err != nil {
		t.Fatal(err)
	}
	if got := run(envelope, "--decrypt"); !bytes.Equal(got, root) {
		t.Fatal("GPG could not decrypt native RSA envelope")
	}
	envelope = run(root, "--armor", "--trust-model", "always", "--recipient", rsaFingerprint, "--encrypt")
	if got, err := b.Unwrap(rsaImported, pass, envelope); err != nil || !bytes.Equal(got, root) {
		t.Fatal("native adapter could not decrypt GPG RSA envelope:", err)
	}
}
