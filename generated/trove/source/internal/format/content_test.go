package format

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"encoding/hex"
	"testing"
)

func TestRoundTripBinaryAndFreshRandomness(t *testing.T) {
	k := bytes.Repeat([]byte{42}, 32)
	for _, p := range [][]byte{nil, []byte("text\n"), {0, 1, 255, 13, 10, 128}} {
		a, err := Encrypt(k, "nested/key", p)
		if err != nil {
			t.Fatal(err)
		}
		b, err := Encrypt(k, "nested/key", p)
		if err != nil {
			t.Fatal(err)
		}
		if bytes.Equal(a, b) {
			t.Fatal("writes reused randomness")
		}
		out, err := Decrypt(k, "nested/key", a)
		if err != nil || !bytes.Equal(out, p) {
			t.Fatalf("round trip: %v", err)
		}
	}
}

func TestEveryByteAuthenticated(t *testing.T) {
	k := bytes.Repeat([]byte{17}, 32)
	c, err := Encrypt(k, "one", []byte("never release unauthenticated plaintext"))
	if err != nil {
		t.Fatal(err)
	}
	for i := range c {
		corrupt := append([]byte(nil), c...)
		corrupt[i] ^= 1
		p, err := Decrypt(k, "one", corrupt)
		if err == nil || len(p) != 0 {
			t.Fatalf("byte %d accepted or released plaintext", i)
		}
	}
	if p, err := Decrypt(k, "two", c); err == nil || len(p) != 0 {
		t.Fatal("cross-name substitution accepted")
	}
	if _, err := Decrypt(bytes.Repeat([]byte{18}, 32), "one", c); err == nil {
		t.Fatal("wrong key accepted")
	}
	for n := 0; n < len(c); n++ {
		if _, err := Decrypt(k, "one", c[:n]); err == nil {
			t.Fatalf("truncation %d accepted", n)
		}
	}
	if _, err := Decrypt(k, "one", append(c, 0)); err == nil {
		t.Fatal("trailing ciphertext accepted")
	}
}

func TestLegacyExplicitAndStrict(t *testing.T) {
	k := bytes.Repeat([]byte{9}, 32)
	iv := bytes.Repeat([]byte{3}, 16)
	p := []byte("legacy\x00binary")
	n := aes.BlockSize - len(p)%aes.BlockSize
	padded := append(append([]byte(nil), p...), bytes.Repeat([]byte{byte(n)}, n)...)
	b, _ := aes.NewCipher(k)
	encrypted := make([]byte, len(padded))
	cipher.NewCBCEncrypter(b, iv).CryptBlocks(encrypted, padded)
	data := append([]byte(hex.EncodeToString(iv)+"\n"), encrypted...)
	if _, err := Decrypt(k, "name", data); err != ErrLegacy {
		t.Fatal("legacy read did not require migration")
	}
	got, err := DecryptLegacy(k, data)
	if err != nil || !bytes.Equal(got, p) {
		t.Fatalf("legacy decode: %v", err)
	}
	// Change IV byte corresponding to final plaintext padding byte deterministically.
	badIV := append([]byte(nil), iv...)
	badIV[15] ^= byte(n)
	bad := append([]byte(hex.EncodeToString(badIV)+"\n"), encrypted...)
	if _, err := DecryptLegacy(k, bad); err == nil {
		t.Fatal("zero padding accepted")
	}
	for _, invalid := range [][]byte{nil, []byte("garbage"), data[:len(data)-1], append([]byte("z"), data[1:]...)} {
		if _, err := DecryptLegacy(k, invalid); err == nil {
			t.Fatal("invalid legacy input accepted")
		}
	}
}

func TestLimitsAndKeyParsing(t *testing.T) {
	if _, err := Encrypt(make([]byte, 31), "x", nil); err == nil {
		t.Fatal("short key")
	}
	if _, err := Encrypt(make([]byte, 32), "x", make([]byte, MaxContent+1)); err == nil {
		t.Fatal("unbounded plaintext")
	}
	good := []byte(hex.EncodeToString(make([]byte, 32)) + "\n")
	if k, err := ParseRootKey(good); err != nil || len(k) != 32 {
		t.Fatal(err)
	}
	for _, bad := range [][]byte{nil, append(good, '\n'), bytes.Repeat([]byte{'z'}, 64), good[:63]} {
		if _, err := ParseRootKey(bad); err == nil {
			t.Fatal("invalid root key accepted")
		}
	}
}

func FuzzDecrypt(f *testing.F) {
	k := make([]byte, 32)
	c, _ := Encrypt(k, "fixture", []byte("fixture"))
	f.Add(c)
	f.Add([]byte("not a secret"))
	f.Fuzz(func(t *testing.T, data []byte) {
		if len(data) < 4096 {
			_, _ = Decrypt(k, "fixture", data)
			_, _ = DecryptLegacy(k, data)
		}
	})
}
