## Superdog - the Crypto library for Vault from Hashicorp
[![GoDoc](https://godoc.org/github.com/xordataexchange/superdog?status.svg)](http://godoc.org/github.com/xordataexchange/superdog)


Superdog is a library for managing strong cryptography in both development and test environments.  Superdog provides an elegant wrapper to the [Vault](https://www.vaultproject.io) API that allows you to manage your cryptographic keys in Vault using any code that implements the `KeyProvider` interface.  An implemention of the `KeyProvider` interface is provided for Vault, but others could be supported.

### Features

-  Versioned Keys - Key version is stored as the first few bytes of the encrypted text
-  Key Rotation - Rotate your keys safely, knowing that you'll always be able to decrypt older versionss
-  Development implementation for tests and local development
-  Versioned and Rotated IV/Salt - `SaltProvider` interface works the same as `KeyProvider` to allow development and testing access to the crypto libraries without requiring a live Key (Vault) server
-  `Reencrypt` function to simplify key rotation, decrypts with given key, reencrypts with latest key

### Performance

On Go version 1.5.2 / Linux x86_64 kernel 4.2.5 on a quad-core i7:

```
BenchmarkKeyEncryptCFB-8	 1000000	      2024 ns/op
BenchmarkKeyEncryptCTR-8	  500000	      2748 ns/op
BenchmarkKeyEncryptGCM-8	 1000000	      2381 ns/op
BenchmarkKeyEncryptOFB-8	  500000	      2665 ns/op
BenchmarkKeyDecryptCFB-8	10000000	       215 ns/op
BenchmarkKeyDecryptCTR-8	 2000000	       898 ns/op
BenchmarkKeyDecryptGCM-8	 3000000	       520 ns/op
BenchmarkKeyDecryptOFB-8	 2000000	       817 ns/op
```

### Usage

`go get -u github.com/xordataexchange/superdog/...`

#### Encryption
```go
val := []byte("encrypt me!")

// use a key prefix to delineate different crypto keys
// allowing you to use different keys for different parts of your application
// or different fields of a database table, for example
b, err := Encrypt("mykeyprefix", val, val)
if err != nil {
	// handle error
}
```
#### Decryption
```go
	b := []byte["some crypt cypher text here"]
	decrypted, err := Decrypt([]byte("mykeyprefix", b, b)
	if err != nil {
		// handle error
	}

```
