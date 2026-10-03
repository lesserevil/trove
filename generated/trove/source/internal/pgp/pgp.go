// Package pgp embeds Proton's OpenPGP implementation. No agent or process is used.
package pgp

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/ProtonMail/go-crypto/openpgp/armor"
	"github.com/ProtonMail/go-crypto/openpgp/packet"
	"github.com/ProtonMail/gopenpgp/v3/crypto"
	"github.com/ProtonMail/gopenpgp/v3/profile"
)

const MaxKey = 1 << 20

type Backend struct{}

// scan reads every packet before the high-level library can normalize the key.
// This rejects private subkeys hidden behind an otherwise public primary key.
func scan(data []byte, private bool) error {
	if len(data) == 0 || len(data) > MaxKey {
		return errors.New("invalid key size")
	}
	b := data
	if bytes.HasPrefix(bytes.TrimSpace(b), []byte("-----BEGIN")) {
		b = bytes.TrimSpace(b)
		kind := "PGP PUBLIC KEY BLOCK"
		if private {
			kind = "PGP PRIVATE KEY BLOCK"
		}
		begin, end := "-----BEGIN "+kind+"-----", "-----END "+kind+"-----"
		if !bytes.HasPrefix(b, []byte(begin)) {
			return errors.New("unexpected armor type")
		}
		i := bytes.Index(b, []byte(end))
		if i < 0 || len(bytes.TrimSpace(b[i+len(end):])) != 0 {
			return errors.New("additional armor or trailing data")
		}
		block, err := armor.Decode(bytes.NewReader(b))
		if err != nil || block.Type != kind {
			return errors.New("invalid armor")
		}
		b, err = io.ReadAll(io.LimitReader(block.Body, MaxKey+1))
		if err != nil || len(b) > MaxKey {
			return errors.New("invalid armor body")
		}
	}
	r := packet.NewReader(bytes.NewReader(b))
	primary := 0
	for {
		p, err := r.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return fmt.Errorf("invalid key packet: %w", err)
		}
		switch p := p.(type) {
		case *packet.PrivateKey:
			if !private {
				return errors.New("private packets forbidden in public registration")
			}
			if !p.IsSubkey {
				primary++
			}
		case *packet.PublicKey:
			if !p.IsSubkey {
				primary++
			}
		case *packet.Signature, *packet.UserId, *packet.UserAttribute:
		default:
			return errors.New("unexpected packet in key")
		}
	}
	if primary != 1 {
		return errors.New("exactly one primary key is required")
	}
	return nil
}

func usable(k *crypto.Key) error {
	now := time.Now().Unix()
	if !k.CanEncrypt(now) || k.IsExpired(now) || k.IsRevoked(now) {
		return errors.New("key is not a usable current encryption identity")
	}
	return nil
}

func (Backend) Public(data []byte) ([]byte, string, error) {
	if err := scan(data, false); err != nil {
		return nil, "", err
	}
	k, err := crypto.NewKey(data)
	if err != nil {
		return nil, "", err
	}
	if k.IsPrivate() {
		return nil, "", errors.New("private registration forbidden")
	}
	if err = usable(k); err != nil {
		return nil, "", err
	}
	a, err := k.GetArmoredPublicKey()
	return []byte(a), strings.ToUpper(k.GetFingerprint()), err
}

func (Backend) Generate(name, email string, pass []byte) ([]byte, []byte, string, error) {
	if len(pass) == 0 {
		return nil, nil, "", errors.New("nonempty passphrase required")
	}
	p := crypto.PGPWithProfile(profile.RFC4880())
	k, err := p.KeyGeneration().AddUserId(name, email).New().GenerateKey()
	if err != nil {
		return nil, nil, "", err
	}
	defer k.ClearPrivateParams()
	return lock(k, pass)
}

func lock(k *crypto.Key, pass []byte) ([]byte, []byte, string, error) {
	pub, err := k.GetArmoredPublicKey()
	if err != nil {
		return nil, nil, "", err
	}
	locked, err := crypto.PGPWithProfile(profile.RFC4880()).LockKey(k, pass)
	if err != nil {
		return nil, nil, "", err
	}
	defer locked.ClearPrivateParams()
	priv, err := locked.Armor()
	return []byte(pub), []byte(priv), strings.ToUpper(k.GetFingerprint()), err
}

func (Backend) Import(data, pass []byte) ([]byte, []byte, string, error) {
	if len(pass) == 0 {
		return nil, nil, "", errors.New("nonempty passphrase required")
	}
	if err := scan(data, true); err != nil {
		return nil, nil, "", err
	}
	k, err := crypto.NewKey(data)
	if err != nil {
		return nil, nil, "", err
	}
	if !k.IsPrivate() {
		return nil, nil, "", errors.New("private identity required")
	}
	unlocked, err := k.IsUnlocked()
	if err != nil {
		return nil, nil, "", err
	}
	if !unlocked {
		u, e := k.Unlock(pass)
		k.ClearPrivateParams()
		if e != nil {
			return nil, nil, "", e
		}
		k = u
	}
	defer k.ClearPrivateParams()
	if err = usable(k); err != nil {
		return nil, nil, "", err
	}
	return lock(k, pass)
}

func (b Backend) Wrap(pub, key []byte) ([]byte, error) {
	normal, _, err := b.Public(pub)
	if err != nil {
		return nil, err
	}
	k, err := crypto.NewKey(normal)
	if err != nil {
		return nil, err
	}
	h, err := crypto.PGPWithProfile(profile.RFC4880()).Encryption().Recipient(k).New()
	if err != nil {
		return nil, err
	}
	m, err := h.Encrypt(key)
	if err != nil {
		return nil, err
	}
	return m.ArmorBytes()
}

func (Backend) Unwrap(priv, pass, envelope []byte) ([]byte, error) {
	if len(envelope) > MaxKey {
		return nil, errors.New("envelope exceeds size limit")
	}
	if err := scan(priv, true); err != nil {
		return nil, err
	}
	k, err := crypto.NewPrivateKeyFromArmored(string(priv), pass)
	if err != nil {
		return nil, err
	}
	defer k.ClearPrivateParams()
	h, err := crypto.PGPWithProfile(profile.RFC4880()).Decryption().DecryptionKey(k).MaxDecompressedMessageSize(4096).New()
	if err != nil {
		return nil, err
	}
	defer h.ClearPrivateParams()
	r, err := h.Decrypt(envelope, crypto.Armor)
	if err != nil {
		return nil, err
	}
	data := r.Bytes()
	if len(data) > 65 {
		clear(data)
		return nil, errors.New("invalid decrypted root-key size")
	}
	return data, nil
}
