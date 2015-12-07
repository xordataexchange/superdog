package superdog

import (
	"bytes"
	"crypto/aes"
	"crypto/rand"
	"io"
	"testing"
)

func TestKeyEncrypt(t *testing.T) {
	val := "Test Value"
	ptext := []byte(val)
	k, err := NewKey(1, AES, GCM, []byte("Default Key XOR "))
	if err != nil {
		t.Fatal(err)
	}

	b, err := k.Encrypt(ptext, ptext)
	if err != nil {
		t.Fatal(err)
	}

	if len(b) != len(val)+36 {
		t.Fatal("Encrypted value should be proper length")
	}

	k2, err := NewKey(1, AES, CFB, []byte("Default Key XOR "))
	if err != nil {
		t.Fatal(err)
	}
	b, err = k2.Encrypt(ptext, ptext)
	if err != nil {
		t.Fatal(err)
	}

	if len(b) != len(val)+8+aes.BlockSize {
		t.Fatal("Encrypted value should be proper length")
	}
}

func TestKeyDecrypt(t *testing.T) {
	val := "Test Value"
	ptext := []byte(val)
	k, err := NewKey(1, AES, GCM, []byte("Default Key XOR "))
	b, err := k.Encrypt(ptext, ptext)
	if err != nil {
		t.Fatal(err)
	}

	decrypted, err := k.Decrypt(b, b[8:])
	if err != nil {
		t.Fatal("Error decrypting value", err)
	}

	if !bytes.Equal([]byte(val), decrypted) {
		t.Fatal("Expected decrypted value to match original value", val, string(decrypted))
	}

	ptext = []byte(val)
	k2, err := NewKey(1, AES, CFB, []byte("Default Key XOR "))
	b, err = k2.Encrypt(ptext, ptext)
	if err != nil {
		t.Fatal(err)
	}

	decrypted, err = k2.Decrypt(b, b[8:])
	if err != nil {
		t.Fatal("Error decrypting value", err)
	}

	if !bytes.Equal([]byte(val), decrypted) {
		t.Fatal("Expected decrypted value to match original value", val, string(decrypted))
	}
}

func BenchmarkKeyEncryptCFB(b *testing.B) {
	val := []byte("Test Value")

	var key [16]byte
	if _, err := io.ReadFull(rand.Reader, key[:]); err != nil {
		b.Fatal(err)
	}
	k, err := NewKey(1, AES, CFB, key[:])
	if err != nil {
		b.Fatal(err)
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		k.Encrypt(val, val)
	}
}

func BenchmarkKeyEncryptCTR(b *testing.B) {
	val := []byte("Test Value")
	var key [16]byte
	if _, err := io.ReadFull(rand.Reader, key[:]); err != nil {
		b.Fatal(err)
	}
	k, err := NewKey(1, AES, CTR, key[:])
	if err != nil {
		b.Fatal(err)
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		k.Encrypt(val, val)
	}
}

func BenchmarkKeyEncryptGCM(b *testing.B) {
	val := []byte("Test Value")
	var key [16]byte
	if _, err := io.ReadFull(rand.Reader, key[:]); err != nil {
		b.Fatal(err)
	}
	k, err := NewKey(1, AES, GCM, key[:])
	if err != nil {
		b.Fatal(err)
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		k.Encrypt(val, val)
	}
}

func BenchmarkKeyEncryptOFB(b *testing.B) {
	val := []byte("Test Value")
	var key [16]byte
	if _, err := io.ReadFull(rand.Reader, key[:]); err != nil {
		b.Fatal(err)
	}
	k, err := NewKey(1, AES, OFB, key[:])
	if err != nil {
		b.Fatal(err)
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		k.Encrypt(val, val)
	}
}

func BenchmarkKeyDecryptCFB(b *testing.B) {
	val := []byte("Test Value")
	var key [16]byte
	if _, err := io.ReadFull(rand.Reader, key[:]); err != nil {
		b.Fatal(err)
	}
	k, err := NewKey(1, AES, CFB, key[:])
	if err != nil {
		b.Fatal(err)
	}
	val, err = k.Encrypt(val, val)
	if err != nil {
		b.Fatal(err)
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		k.Decrypt(val, val)
	}
}

func BenchmarkKeyDecryptCTR(b *testing.B) {
	val := []byte("Test Value")
	var key [16]byte
	if _, err := io.ReadFull(rand.Reader, key[:]); err != nil {
		b.Fatal(err)
	}
	k, err := NewKey(1, AES, CTR, key[:])
	if err != nil {
		b.Fatal(err)
	}
	val, err = k.Encrypt(val, val)
	if err != nil {
		b.Fatal(err)
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		k.Decrypt(val, val)
	}
}

func BenchmarkKeyDecryptGCM(b *testing.B) {
	val := []byte("Test Value")
	var key [16]byte
	if _, err := io.ReadFull(rand.Reader, key[:]); err != nil {
		b.Fatal(err)
	}
	k, err := NewKey(1, AES, GCM, key[:])
	if err != nil {
		b.Fatal(err)
	}
	val, err = k.Encrypt(val, val)
	if err != nil {
		b.Fatal(err)
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		k.Decrypt(val, val)
	}
}

func BenchmarkKeyDecryptOFB(b *testing.B) {
	val := []byte("Test Value")
	var key [16]byte
	if _, err := io.ReadFull(rand.Reader, key[:]); err != nil {
		b.Fatal(err)
	}
	k, _ := NewKey(1, AES, OFB, key[:])
	val, err := k.Encrypt(val, val)
	if err != nil {
		b.Fatal(err)
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		k.Decrypt(val, val)
	}
}
