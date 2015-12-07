package vault

import (
	"log"
	"strconv"

	"github.com/xordataexchange/superdog"
)

// Vault is an interface wrapping a store for secrets.
type Vault interface {
	superdog.KeyProvider
	superdog.SaltProvider
}

var _ Vault = &DevVault{}

// DevVault returns hardcoded stubbed responses to remove development dependencies from a true vault. Insecure, do not use in production.
type DevVault struct {
	DisableWarn bool // Disable log messages when this is used
	SaltVersion uint64
	KeyVersion  uint64
}

func (v *DevVault) CurrentKeyVersion(prefix string) (uint64, error) {
	return v.KeyVersion, nil
}

func (v *DevVault) CurrentSaltVersion(prefix string) (uint64, error) {
	return v.SaltVersion, nil
}

// GetKey returns a stubbed encryption key for development purposes.
func (v *DevVault) GetKey(prefix string, version uint64) (*superdog.Key, error) {
	if !v.DisableWarn {
		log.Println("USING DEV KEY PROVIDER!")
	}

	if version == 1 {
		return superdog.NewKey(version, superdog.AES, superdog.CFB, []byte("DEFAULT  KEY "))
	}

	vs := strconv.FormatUint(version, 10)
	return superdog.NewKey(version, superdog.AES, superdog.GCM, []byte("DEFAULT  KEY DEFAULT  KEY"+vs))
}

// CurrentSalts returns a stubbed list of salts to be used for the given prefix
func (v *DevVault) CurrentSalts(prefix string) ([]uint64, error) {
	if !v.DisableWarn {
		log.Println("USING DEV SALT PROVIDER!")
	}

	return []uint64{v.KeyVersion}, nil
}

// GetSalt returns a stubbed salt to be used for the given prefix
func (v *DevVault) GetSalt(prefix string, version uint64) ([]byte, error) {
	if !v.DisableWarn {
		log.Println("USING DEV SALT PROVIDER!")
	}
	return []byte("DEV SALT " + prefix), nil
}
