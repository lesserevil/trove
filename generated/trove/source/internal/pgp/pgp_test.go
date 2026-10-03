package pgp

import (
	"bytes"
	"testing"

	"github.com/ProtonMail/go-crypto/openpgp/armor"
	"github.com/ProtonMail/gopenpgp/v3/crypto"
)

func TestPublicPacketBoundary(t *testing.T) {
	b := Backend{}
	pass := []byte("synthetic-packet-test")
	pub, priv, _, err := b.Generate("packet-test", "packet@example.invalid", pass)
	if err != nil {
		t.Fatal(err)
	}
	k, err := crypto.NewKey(priv)
	if err != nil {
		t.Fatal(err)
	}
	defer k.ClearPrivateParams()
	raw, err := k.GetPublicKey()
	if err != nil {
		t.Fatal(err)
	}
	var mixed bytes.Buffer
	mixed.Write(raw)
	if err := k.GetEntity().Subkeys[0].PrivateKey.Serialize(&mixed); err != nil {
		t.Fatal(err)
	}
	var armored bytes.Buffer
	w, err := armor.Encode(&armored, "PGP PUBLIC KEY BLOCK", nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := w.Write(mixed.Bytes()); err != nil {
		t.Fatal(err)
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	for name, data := range map[string][]byte{
		"private primary":               priv,
		"hidden private subkey binary":  mixed.Bytes(),
		"hidden private subkey armored": armored.Bytes(),
		"two public primary keys":       append(append([]byte(nil), raw...), raw...),
		"additional armor":              append(append([]byte(nil), pub...), priv...),
		"trailing garbage":              append(append([]byte(nil), pub...), []byte("garbage")...),
	} {
		t.Run(name, func(t *testing.T) {
			if _, _, err := b.Public(data); err == nil {
				t.Fatal("invalid public registration accepted")
			}
		})
	}
	for _, data := range [][]byte{pub, raw} {
		if _, _, err := b.Public(data); err != nil {
			t.Fatal("valid public key rejected:", err)
		}
	}
}
