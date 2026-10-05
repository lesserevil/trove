// Package format implements Trove content formats. OpenPGP is deliberately separate.
package format

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hkdf"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
)

const MaxContent = 64 << 20
const HeaderSize = 50

var magic = []byte{'T', 'R', 'O', 'V', 'E', 2}
var ErrLegacy = errors.New("legacy or unknown content format; use explicit migrate for CBC")

func IsV2(data []byte) bool { return bytes.HasPrefix(data, magic) }

func aead(key, salt []byte) (cipher.AEAD, error) {
	if len(key) != 32 {
		return nil, errors.New("root key must contain exactly 32 bytes")
	}
	k, err := hkdf.Key(sha256.New, key, salt, "trove/content/v2", 32)
	if err != nil {
		return nil, err
	}
	defer clear(k)
	b, err := aes.NewCipher(k)
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(b)
}

func aad(header []byte, name string) []byte {
	b := append([]byte(nil), header...)
	b = binary.BigEndian.AppendUint32(b, uint32(len(name)))
	return append(b, name...)
}

func Encrypt(key []byte, name string, plain []byte) ([]byte, error) {
	if len(plain) > MaxContent {
		return nil, errors.New("content exceeds 64 MiB")
	}
	header := make([]byte, HeaderSize)
	copy(header, magic)
	if _, err := rand.Read(header[6:]); err != nil {
		return nil, err
	}
	g, err := aead(key, header[6:38])
	if err != nil {
		return nil, err
	}
	return g.Seal(header, header[38:50], plain, aad(header, name)), nil
}

func Decrypt(key []byte, name string, data []byte) ([]byte, error) {
	if !IsV2(data) {
		return nil, ErrLegacy
	}
	if len(data) < HeaderSize+16 || len(data) > HeaderSize+16+MaxContent {
		return nil, errors.New("invalid content size")
	}
	g, err := aead(key, data[6:38])
	if err != nil {
		return nil, err
	}
	p, err := g.Open(nil, data[38:50], data[50:], aad(data[:50], name))
	if err != nil {
		return nil, errors.New("content authentication failed")
	}
	return p, nil
}

// DecryptLegacy is reachable only from the explicitly acknowledged migration command.
// Correct padding cannot prove authenticity of this historical format.
func DecryptLegacy(key, data []byte) ([]byte, error) {
	if len(data) < 49 || data[32] != '\n' {
		return nil, errors.New("invalid legacy IV header")
	}
	iv, err := hex.DecodeString(string(data[:32]))
	if err != nil || len(iv) != aes.BlockSize {
		return nil, errors.New("invalid legacy IV")
	}
	c := data[33:]
	if len(c) == 0 || len(c)%aes.BlockSize != 0 || len(c) > MaxContent+aes.BlockSize {
		return nil, errors.New("invalid legacy ciphertext size")
	}
	if len(key) != 32 {
		return nil, errors.New("invalid root key")
	}
	b, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	p := make([]byte, len(c))
	cipher.NewCBCDecrypter(b, iv).CryptBlocks(p, c)
	n := int(p[len(p)-1])
	if n == 0 || n > aes.BlockSize || !bytes.Equal(p[len(p)-n:], bytes.Repeat([]byte{byte(n)}, n)) {
		clear(p)
		return nil, errors.New("invalid legacy padding")
	}
	if len(p)-n > MaxContent {
		clear(p)
		return nil, errors.New("content exceeds 64 MiB")
	}
	return p[:len(p)-n], nil
}

func ParseRootKey(data []byte) ([]byte, error) {
	if len(data) == 65 && data[64] == '\n' {
		data = data[:64]
	}
	if len(data) != 64 {
		return nil, errors.New("invalid recipient root key")
	}
	b, err := hex.DecodeString(string(data))
	if err != nil {
		return nil, errors.New("invalid recipient root key")
	}
	return b, nil
}
