package superdog

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"errors"
)

var DefaultKeyProvider KeyProvider = new(DevKeyProvider)
var DefaultSaltProvider SaltProvider = new(DevSaltProvider)

// Encrypt will encrypt the provided byte slice with the latesg key. It returns a new slice as it prepends the key version, and IV.
func Encrypt(prefix string, dst, src []byte) ([]byte, error) {
	v, err := DefaultKeyProvider.CurrentKeyVersion(prefix)
	if err != nil {
		return nil, err
	}
	return EncryptWithVersion(prefix, v, dst, src)
}

// EncryptWithVersion will encrypt the provided byte slice with the supplied key version. It returns a new slice as it prepends the key version, and IV.
func EncryptWithVersion(keyPrefix string, keyVersion uint64, dst []byte, src []byte) ([]byte, error) {
	if len(src) == 0 {
		return dst[:0], nil
	}

	k, err := DefaultKeyProvider.GetKey(keyPrefix, keyVersion)
	if err != nil {
		return nil, err
	}

	return k.Encrypt(dst, src)
}

// Decrypt will decrypt the provided byte slice using the provided key at the version it was encrypted with. It returns a new slice as it trims the prefixed key version and IV. It modifies the same underlying array.
func Decrypt(keyPrefix string, dst, src []byte) ([]byte, error) {
	if len(src) == 0 {
		return []byte{}, nil
	}

	if len(src) <= 8 {
		return nil, errors.New("Insufficient length")
	}

	buf := bytes.NewBuffer(src)
	version, err := binary.ReadUvarint(buf)
	if err != nil {
		return src, err
	}

	k, err := DefaultKeyProvider.GetKey(keyPrefix, version)
	if err != nil {
		return nil, err
	}

	return k.Decrypt(src, src[8:])
}

// Reencrypt takes encrypted ciphertext, decrypts it with the version of the key used to decrypt it, and re-encrypts the plaintext with the current version of the key.
func Reencrypt(keyPrefix string, dst, src []byte) ([]byte, error) {
	dst, err := Decrypt(keyPrefix, dst, src)
	if err != nil {
		return src, err
	}
	v, err := DefaultKeyProvider.CurrentKeyVersion(keyPrefix)
	if err != nil {
		return nil, err
	}
	return EncryptWithVersion(keyPrefix, v, dst, dst)
}

// CurrentHashes returns a list of all possible hashes for the given prefix and value, used as search criteria during rotation
func CurrentHashes(prefix string, value []byte) ([][]byte, error) {
	hashes := make([][]byte, 0)
	salts, err := DefaultSaltProvider.CurrentSalts(prefix)
	if err != nil {
		return nil, err
	}

	for _, v := range salts {
		h, err := HashWithVersion(prefix, v, value)
		if err != nil {
			return nil, err
		}
		hashes = append(hashes, h)
	}

	return hashes, nil
}

// CurrentHashesString returns a list of all possible hashes for the given prefix and value, used as search criteria during rotation
func CurrentHashesString(prefix string, value string) ([]string, error) {
	hashes := make([]string, 0)
	if len(value) == 0 {
		return hashes, nil
	}

	salts, err := DefaultSaltProvider.CurrentSalts(prefix)
	if err != nil {
		return nil, err
	}

	for _, v := range salts {
		h, err := HashWithVersion(prefix, v, []byte(value))
		if err != nil {
			return nil, err
		}
		hashes = append(hashes, string(h))
	}

	return hashes, nil
}

// Hash returns a hash to be used for the given value using the current version
func Hash(prefix string, value []byte) ([]byte, error) {
	v, err := DefaultSaltProvider.CurrentSaltVersion(prefix)
	if err != nil {
		return nil, err
	}
	return HashWithVersion(prefix, v, value)
}

// HashWithVersion returns a hash to be used for the given value using the supplied version
func HashWithVersion(prefix string, version uint64, value []byte) ([]byte, error) {
	if len(value) == 0 {
		return []byte{}, nil
	}
	s, err := DefaultSaltProvider.GetSalt(prefix, version)
	if err != nil {
		return nil, err
	}

	hash := sha256.Sum256(append(s, value...))
	i := base64.StdEncoding.EncodedLen(32)
	out := make([]byte, i)

	base64.StdEncoding.Encode(out, hash[:])

	return out, nil
}

// HashString returns a hash to be used for the given value using the current version
func HashString(prefix string, value string) (string, error) {
	b, err := Hash(prefix, []byte(value))
	if err != nil {
		return "", err
	}
	return string(b), nil
}
