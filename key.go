package superdog

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"io"
)

type CipherBlockMode uint8
type Cipher uint8

const (
	CFB CipherBlockMode = iota
	CTR
	OFB
	GCM
)

const (
	AES Cipher = iota
)

type Key struct {
	Cipher          Cipher
	CipherBlockMode CipherBlockMode
	block           cipher.Block
	ivlen           int
	Version         uint64
}

func NewKey(version uint64, c Cipher, bm CipherBlockMode, key []byte) (*Key, error) {
	k := &Key{
		Cipher:          c,
		CipherBlockMode: bm,
		Version:         version,
	}

	switch c {
	case AES:
		var err error
		k.block, err = aes.NewCipher(key)
		if err != nil {
			return k, err
		}
	}

	k.ivlen = k.block.BlockSize()
	if k.CipherBlockMode == GCM {
		k.ivlen = 12
	}

	return k, nil
}

func (k *Key) Encrypt(dst, src []byte) ([]byte, error) {
	if len(dst) != len(src)+8+k.ivlen {
		dst = make([]byte, len(src)+8+k.ivlen)
	}

	// Place encryption KeyID at the beginning of cipher text
	binary.PutUvarint(dst[:8], k.Version)

	// Followed by the IV
	iv := dst[8 : k.ivlen+8]
	if _, err := io.ReadAtLeast(rand.Reader, iv, k.ivlen); err != nil {
		return src, err
	}

	switch k.CipherBlockMode {
	case CFB:
		stream := cipher.NewCFBEncrypter(k.block, iv)
		stream.XORKeyStream(dst[8+k.ivlen:], src)
	case CTR:
		stream := cipher.NewCTR(k.block, iv)
		stream.XORKeyStream(dst[8+k.ivlen:], src)
	case OFB:
		stream := cipher.NewOFB(k.block, iv)
		stream.XORKeyStream(dst[8+k.ivlen:], src)
	case GCM:
		aead, err := cipher.NewGCM(k.block)
		if err != nil {
			return dst, err
		}

		dst = aead.Seal(dst[:8+k.ivlen], iv, src, nil)
	}

	return dst, nil
}

func (k *Key) Decrypt(dst, src []byte) ([]byte, error) {
	if len(src) == 0 {
		return []byte{}, nil
	}

	if len(src) < k.block.BlockSize() {
		return nil, errors.New("Insufficient length")
	}

	iv := src[:k.ivlen]

	text := src[k.ivlen:]
	switch k.CipherBlockMode {
	case CFB:
		stream := cipher.NewCFBDecrypter(k.block, iv)
		dst = dst[:len(text)]
		stream.XORKeyStream(dst, text)
	case CTR:
		stream := cipher.NewCTR(k.block, iv)
		dst = dst[:len(text)]
		stream.XORKeyStream(dst, text)
	case OFB:
		stream := cipher.NewOFB(k.block, iv)
		dst = dst[:len(text)]
		stream.XORKeyStream(dst, text)
	case GCM:
		aead, err := cipher.NewGCM(k.block)
		if err != nil {
			return dst, err
		}
		return aead.Open(dst[:0], iv, text, nil)
	}
	return dst, nil
}
