package superdog

import (
	"errors"
	"log"
	"strconv"
)

var (
	ErrKeyNotFound = errors.New("Key not found")
)

var _ KeyProvider = &DevKeyProvider{}

// KeyProvider is an interface that wraps the GetKey method, responsible for retrieving encryption keys at a specified version.
type KeyProvider interface {
	GetKey(prefix string, version uint64) (*Key, error)
	CurrentKeyVersion(prefix string) (uint64, error)
}

// DevKeyProvider is a KeyProvider used for development purposes only, and contains a hardcoded key.
type DevKeyProvider struct {
	DisableWarn bool // Disable log messages whenever this provider is used.
	KeyVersion  uint64
}

// CurrentKeyVersion returns the version number of the latest key for a given prefix
func (kp *DevKeyProvider) CurrentKeyVersion(prefix string) (uint64, error) {
	return kp.KeyVersion, nil
}

func (kp *DevKeyProvider) GetKey(prefix string, version uint64) (*Key, error) {
	if !kp.DisableWarn {
		log.Println("USING DEV KEY PROVIDER!")
	}

	if version == 1 {
		return NewKey(version, AES, CFB, []byte("DEFAULT XOR KEY DEFAULT XOR KEY "))
	}
	v := strconv.FormatUint(version, 10)
	return NewKey(version, AES, GCM, []byte("DEFAULT XOR KEY DEFAULT XOR KEY"+v))
}
