package superdog_test

import "github.com/xordataexchange/superdog"

func ExampleEncrypt(prefix string, val []byte) []byte {
	encrypted, err := superdog.Encrypt(prefix, val, val)
	if err != nil {
		panic(err)
	}
	return encrypted
}

func ExampleDecrypt(prefix string, val []byte) []byte {

	decrypted, err := superdog.Decrypt(prefix, val, val)
	if err != nil {
		panic(err)
	}
	return decrypted
}
