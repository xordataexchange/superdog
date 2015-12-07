/*
See LICENSE file for license details
Copyright (c) 2015 XOR Data Exchange, Inc.


Superdog - the Crypto library for Vault from Hashicorp


Superdog is a library for managing strong cryptography in both development and test environments.  Superdog provides an elegant wrapper to the Vault(https://www.vaultproject.io) API that allows you to manage your cryptographic keys in Vault using any code that implements the `KeyProvider` interface.  An implemention of the `KeyProvider` interface is provided for Vault, but others could be supported.

Features

-  Versioned Keys - Key version is stored as the first few bytes of the encrypted text
-  Key Rotation - Rotate your keys safely, knowing that you'll always be able to decrypt older versionss
-  Development implementation for tests and local development
-  Versioned and Rotated IV/Salt - `SaltProvider` interface works the same as `KeyProvider` to allow development and testing access to the crypto libraries without requiring a live Key (Vault) server
-  `Reencrypt` function to simplify key rotation, decrypts with given key, reencrypts with latest key

Cypher Suites

`superdog` supports AES encryption with CFB/CTR/GCM/OFB modes.


Production Usage
By default, `superdog` uses the `DevKeyProvider` which is a static key with static IV.  This is extremely insecure, and SHOULD NOT ever be used in production.

We reccommend using Go's [build tags](https://golang.org/pkg/go/build/) to enable strong cryptography in production usage.

Create a file with your connection routines in the init() function.  Add the build tag `// +build production` to the top of that file.

// +build production

package main
import (
	"github.com/xordataexchange/superdog"
	"github.com/xordataexxchange/superdog/vault/hashi"
	"github.com/hashicorp/vault/api"
)

// Assign each application a unique UUID
// and use Vault's AppID authentication mechanism
const (
	appid = "SOME RANDOM UUID"
)

func init() {
	user := os.Getenv("VAULT_USER")
	vaultaddr := os.Getenv("VAULT_ADDRESS")
	// TEST these for empty strings & handle appropriately in your code

	cfg:= api.DefaultConfig()
	cfg.Address = vaultaddr

	vault, err := hashi.NewVault(cfg)
	if err != nil {
		// handle appropriately
	}
	err = vault.AuthAppID(appid, user)
	if err != nil {
		// handle appropriately
	}

	crypto.DefaultKeyProvider = vault
	crypto.DefaultSaltProvider = vault

}

Now compile your program with `go build -tags production` to include this code.  The `KeyProvider` will be set to use Vault.

*/
package superdog
