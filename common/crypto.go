package common

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/rand"
	"io"
)

func Encrypt(plaintext []byte, key []byte) ([]byte, []byte) {
	block, err := aes.NewCipher(key)
	if err != nil {
		panic(err)
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		panic(err)
	}

	nonce := make([]byte, gcm.NonceSize())
	_, err = io.ReadFull(rand.Reader, nonce)
	if err != nil {
		panic(err)
	}

	return nonce, gcm.Seal(nil, nonce, plaintext, nil)
}

func Decrypt(nonce []byte, ciphertext []byte, key []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, err
	}

	return plaintext, nil
}

func GeneratePubPrivKeys() (*ecdh.PrivateKey, *ecdh.PublicKey) {
	curve := ecdh.X25519()
	privKey, err := curve.GenerateKey(rand.Reader)
	if err != nil {
		panic(err)
	}
	return privKey, privKey.PublicKey()
}
