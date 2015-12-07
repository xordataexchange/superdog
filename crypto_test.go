package superdog

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"testing"
)

func TestEncrypt(t *testing.T) {
	DefaultKeyProvider = &DevKeyProvider{DisableWarn: true}
	val := []byte("Test Value...")
	ln := len(val) + 36
	b, err := Encrypt("test", val, val)
	if err != nil {
		t.Fatal(err)
	}

	if len(b) != ln {
		t.Fatal("Encrypted value should be proper length")
	}
}

func TestDecrypt(t *testing.T) {
	DefaultKeyProvider = &DevKeyProvider{DisableWarn: true}
	val := []byte("Test Value")
	b, err := Encrypt("test", val, val)
	if err != nil {
		t.Fatal(err)
	}

	decrypted, err := Decrypt("test", b, b)
	if err != nil {
		t.Fatal("Error decrypting value", err)
	}

	if !bytes.Equal(val, decrypted) {
		t.Fatal("Expected decrypted value to match original value", string(val), string(decrypted))
	}
}

func TestReencrypt(t *testing.T) {
	DefaultKeyProvider = &DevKeyProvider{DisableWarn: true, KeyVersion: 2}
	original := "Test Value"
	val := []byte(original)
	b, err := EncryptWithVersion("test", 1, val, val)
	if err != nil {
		t.Fatal(err)
	}

	b, err = Reencrypt("test", b, b)
	if err != nil {
		t.Fatal("Error reencrypt key.", err)
	}

	key, err := DefaultKeyProvider.GetKey("test", 2)
	if err != nil {
		t.Fatal("Error retrieving key", err)
	}
	decrypted, err := key.Decrypt(b, b[8:])
	if err != nil {
		t.Fatal("Error decrypting value", err)
	}

	if !bytes.Equal([]byte(original), decrypted) {
		t.Fatal("Expected decrypted value to match original value", original, string(decrypted))
	}
}

func TestHash(t *testing.T) {
	DefaultSaltProvider = &DevSaltProvider{DisableWarn: true, SaltVersion: 2}
	val := []byte("Test")
	h, err := Hash("fields/test", val)
	if err != nil {
		t.Fatal("Error hashing value", err)
	}

	expected := sha256.Sum256(append([]byte("DEV SALT fields/test 2"), val...))
	if !bytes.Equal([]byte(base64.StdEncoding.EncodeToString(expected[:])), h) {
		t.Fatal("Value failed to hash properly")
	}
}

func TestHashString(t *testing.T) {
	DefaultSaltProvider = &DevSaltProvider{DisableWarn: true, SaltVersion: 3}
	val := "Test"
	h, err := HashString("fields/test", val)
	if err != nil {
		t.Fatal("Error hashing value", err)
	}

	expected := sha256.Sum256(append([]byte("DEV SALT fields/test 3"), []byte(val)...))
	if base64.StdEncoding.EncodeToString(expected[:]) != h {
		t.Fatal("Value failed to hash properly")
	}
}

func TestHashWithVersion(t *testing.T) {
	DefaultSaltProvider = &DevSaltProvider{DisableWarn: true, SaltVersion: 1}
	val := []byte("Test")
	h, err := HashWithVersion("fields/test", 2, val)
	if err != nil {
		t.Fatal("Error hashing value", err)
	}

	expected := sha256.Sum256(append([]byte("DEV SALT fields/test 2"), val...))
	if !bytes.Equal([]byte(base64.StdEncoding.EncodeToString(expected[:])), h) {
		t.Fatal("Value failed to hash properly")
	}
}

func TestCurrentHashes(t *testing.T) {
	DefaultSaltProvider = &DevSaltProvider{DisableWarn: true, SaltVersion: 1}
	val := []byte("Test")
	hashes, err := CurrentHashes("fields/test", val)
	if err != nil {
		t.Fatal("Error hashing value", err)
	}

	if len(hashes) != 3 {
		t.Fatal("Expected 3 hashes to be returned")
	}

	expected := sha256.Sum256(append([]byte("DEV SALT fields/test 1"), val...))
	expected2 := sha256.Sum256(append([]byte("DEV SALT fields/test 2"), val...))
	expected3 := sha256.Sum256(append([]byte("DEV SALT fields/test 3"), val...))

	if !bytes.Equal([]byte(base64.StdEncoding.EncodeToString(expected[:])), hashes[0]) {
		t.Fatal("Value failed to hash properly")
	}

	if !bytes.Equal([]byte(base64.StdEncoding.EncodeToString(expected2[:])), hashes[1]) {
		t.Fatal("Value failed to hash properly")
	}

	if !bytes.Equal([]byte(base64.StdEncoding.EncodeToString(expected3[:])), hashes[2]) {
		t.Fatal("Value failed to hash properly")
	}
}

func TestCurrentHashesString(t *testing.T) {
	DefaultSaltProvider = &DevSaltProvider{DisableWarn: true, SaltVersion: 1}
	val := "Test"
	valBytes := "Test"
	hashes, err := CurrentHashesString("fields/test", val)
	if err != nil {
		t.Fatal("Error hashing value", err)
	}

	if len(hashes) != 3 {
		t.Fatal("Expected 3 hashes to be returned")
	}

	expected := sha256.Sum256(append([]byte("DEV SALT fields/test 1"), valBytes...))
	expected2 := sha256.Sum256(append([]byte("DEV SALT fields/test 2"), valBytes...))
	expected3 := sha256.Sum256(append([]byte("DEV SALT fields/test 3"), valBytes...))

	if base64.StdEncoding.EncodeToString(expected[:]) != hashes[0] {
		t.Fatal("Value failed to hash properly")
	}

	if base64.StdEncoding.EncodeToString(expected2[:]) != hashes[1] {
		t.Fatal("Value failed to hash properly")
	}

	if base64.StdEncoding.EncodeToString(expected3[:]) != hashes[2] {
		t.Fatal("Value failed to hash properly")
	}
}
