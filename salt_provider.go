package superdog

import (
	"log"
	"strconv"
)

var _ SaltProvider = &DevSaltProvider{}

type SaltProvider interface {
	CurrentSalts(prefix string) ([]uint64, error)
	GetSalt(prefix string, version uint64) ([]byte, error)
	CurrentSaltVersion(prefix string) (uint64, error)
}

// DevSaltProvider is a KeyProvider used for development purposes only, and contains a hardcoded key.
type DevSaltProvider struct {
	DisableWarn bool // Disable log messages whenever this provider is used.
	SaltVersion uint64
}

// CurrentSaltVersion returns the version number of the latest salt for a given prefix
func (sp *DevSaltProvider) CurrentSaltVersion(prefix string) (uint64, error) {
	return sp.SaltVersion, nil

}

// CurrentSalts returns a stubbed list of salts to be used for the given prefix
func (sp *DevSaltProvider) CurrentSalts(prefix string) ([]uint64, error) {
	if !sp.DisableWarn {
		log.Println("USING DEV SALT PROVIDER!")
	}
	return []uint64{1, 2, 3}, nil
}

// GetSalt returns a stubbed salt to be used for the given prefix
func (sp *DevSaltProvider) GetSalt(prefix string, version uint64) ([]byte, error) {
	if !sp.DisableWarn {
		log.Println("USING DEV SALT PROVIDER!")
	}
	return []byte("DEV SALT " + prefix + " " + strconv.FormatUint(version, 10)), nil
}
