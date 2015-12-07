package hashi

import (
	"bytes"
	"encoding/base64"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"sync"

	"github.com/xordataexchange/superdog"
	"github.com/xordataexchange/superdog/vault"

	"github.com/hashicorp/vault/api"
)

var ErrVersionMismatch = errors.New("Key returned does no match requested version")

var _ vault.Vault = &Vault{}

type Vault struct {
	client       *api.Client
	logical      *api.Logical
	config       *api.Config
	keyCache     map[string]*superdog.Key
	latestKey    map[string]uint64
	saltCache    map[string][]byte
	currentSalts map[string][]uint64
	latestSalt   map[string]uint64
	l            sync.Mutex
}

// NewVault returns a new hashicorp Vault client
func NewVault(c *api.Config) (*Vault, error) {
	v := Vault{
		keyCache:     make(map[string]*superdog.Key),
		latestKey:    make(map[string]uint64),
		saltCache:    make(map[string][]byte),
		currentSalts: make(map[string][]uint64),
		latestSalt:   make(map[string]uint64),
	}
	client, err := api.NewClient(c)
	if err != nil {
		return &v, nil
	}

	v.config = c
	v.client = client
	v.logical = client.Logical()
	return &v, nil
}

// SetToken sets the token cookie to the new value.
func (v *Vault) SetToken(t string) {
	v.client.SetToken(t)
}

// Token returns the access token currently being used.
func (v *Vault) Token() string {
	return v.client.Token()
}

// ClearToken deletes the token cookie if it's set.
func (v *Vault) ClearToken() {
	v.client.ClearToken()
}

// AuthAppID authenticates with Vault using an AppID and UserID and sets the access token for requests.
func (v *Vault) AuthAppID(app, user string) error {
	resp, err := v.config.HttpClient.Post(v.config.Address+"/v1/auth/app-id/login", "application/json", strings.NewReader(fmt.Sprintf(
		"{\"app_id\":\"%s\", \"user_id\":\"%s\"}", app, user)))
	if err != nil {
		return err
	}

	var r api.Response
	r.Response = resp
	err = r.Error()
	if err != nil {
		return err
	}

	s, err := api.ParseSecret(r.Body)
	if err != nil {
		return err
	}

	v.l.Lock()
	v.client.SetToken(s.Auth.ClientToken)
	v.l.Unlock()

	return nil
}

// GetKey fetches the encryption key information for the key version provided.
func (v *Vault) GetKey(prefix string, version uint64) (*superdog.Key, error) {
	ckey := prefix + strconv.FormatUint(version, 10)
	v.l.Lock()
	defer v.l.Unlock()
	if k, ok := v.keyCache[ckey]; ok {
		return k, nil
	}

	s, err := v.logical.Read("secret/keys/" + prefix + "/" + strconv.FormatUint(version, 10))
	if err != nil {
		return nil, err
	}

	sv, err := strconv.ParseUint(s.Data["version"].(string), 10, 64)
	if err != nil {
		return nil, err
	}
	if sv != version {
		return nil, ErrVersionMismatch
	}

	var cipher superdog.Cipher
	switch s.Data["cipher"] {
	case "AES":
		cipher = superdog.AES
	default:
		return nil, fmt.Errorf("Unsupported cipher %s", s.Data["cipher"])
	}

	var blockMode superdog.CipherBlockMode
	switch s.Data["block_mode"] {
	case "CFB":
		blockMode = superdog.CFB
	case "CTR":
		blockMode = superdog.CTR
	case "OFB":
		blockMode = superdog.OFB
	case "GCM":
		blockMode = superdog.GCM
	default:
		return nil, fmt.Errorf("Unsupported cipher block mode %s", s.Data["block_mode"])
	}

	key, err := base64.URLEncoding.DecodeString(s.Data["key"].(string))
	if err != nil {
		return nil, err
	}

	k, err := superdog.NewKey(version, cipher, blockMode, bytes.Trim(key, "\n"))
	if err != nil {
		return nil, err
	}
	v.keyCache[ckey] = k

	return k, nil
}

// CurrentKeyVersion retrieves the latest version of the specified key to be used
func (v *Vault) CurrentKeyVersion(prefix string) (uint64, error) {
	v.l.Lock()
	defer v.l.Unlock()

	if v, ok := v.latestKey[prefix]; ok {
		return v, nil
	}

	s, err := v.logical.Read("secret/keys/" + prefix + "/current")
	if err != nil {
		return 0, err
	}

	kv, err := strconv.ParseUint(s.Data["latest"].(string), 10, 64)
	if err != nil {
		return 0, fmt.Errorf("Error parsing key for %s: %s", prefix, err)
	}

	v.latestKey[prefix] = kv

	return v.latestKey[prefix], nil
}

// GetSalt fetches the salt for the prefix and version provided.
func (v *Vault) GetSalt(prefix string, version uint64) ([]byte, error) {
	v.l.Lock()
	defer v.l.Unlock()
	ckey := prefix + strconv.FormatUint(version, 10)
	if s, ok := v.saltCache[ckey]; ok {
		return s, nil
	}

	s, err := v.logical.Read("secret/salts/" + prefix + "/" + strconv.FormatUint(version, 10))
	if err != nil {
		return nil, err
	}

	sv, err := strconv.ParseUint(s.Data["version"].(string), 10, 64)
	if err != nil {
		return nil, err
	}
	if sv != version {
		return nil, ErrVersionMismatch
	}

	salt, err := base64.URLEncoding.DecodeString(s.Data["salt"].(string))
	if err != nil {
		return nil, err
	}

	v.saltCache[ckey] = bytes.Trim(salt, "\n")

	return v.saltCache[ckey], nil
}

// CurrentSaltVersion retrieves the latest version of the specified salt to be used
func (v *Vault) CurrentSaltVersion(prefix string) (uint64, error) {
	v.l.Lock()

	if version, ok := v.latestSalt[prefix]; ok {
		v.l.Unlock()
		return version, nil
	}

	v.l.Unlock()
	_, err := v.CurrentSalts(prefix)
	if err != nil {
		return 0, err
	}

	v.l.Lock()
	defer v.l.Unlock()
	return v.latestSalt[prefix], nil
}

// CurrentSalts fetches the list of currently active salts for the prefix and version provided.
func (v *Vault) CurrentSalts(prefix string) ([]uint64, error) {
	v.l.Lock()
	defer v.l.Unlock()

	if salts, ok := v.currentSalts[prefix]; ok {
		return salts, nil
	}

	var salts = make([]uint64, 0)

	s, err := v.logical.Read("secret/salts/" + prefix + "/current")
	if err != nil {
		return nil, err
	}

	for _, s := range strings.Split(s.Data["salts"].(string), ",") {
		sv, err := strconv.ParseUint(s, 10, 64)
		if err != nil {
			return nil, err
		}

		salts = append(salts, sv)
	}

	sv, err := strconv.ParseUint(s.Data["latest"].(string), 10, 64)
	if err != nil {
		return nil, err
	}

	v.latestSalt[prefix] = sv
	v.currentSalts[prefix] = salts
	return salts, nil
}
