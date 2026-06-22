package oast

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
)

// ensureKey lazily generates RSA.
func (c *interactshClient) ensureKey() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.privKey != nil {
		return nil
	}
	key, err := rsa.GenerateKey(rand.Reader, interactshKeyBits)
	if err != nil {
		return fmt.Errorf("oast: keygen: %w", err)
	}
	c.privKey = key
	return nil
}

// decryptAESKey decrypts session key.
func (c *interactshClient) decryptAESKey(encrypted string) ([]byte, error) {
	ciphertext, err := base64.StdEncoding.DecodeString(encrypted)
	if err != nil {
		return nil, err
	}
	return rsa.DecryptOAEP(sha256.New(), rand.Reader, c.privKey, ciphertext, nil)
}

// decryptPayload decrypts payload data.
func decryptPayload(key []byte, b64data string) ([]byte, error) {
	data, err := base64.StdEncoding.DecodeString(b64data)
	if err != nil {
		return nil, err
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	if len(data) < aes.BlockSize {
		return nil, errors.New("ciphertext too short")
	}
	iv := data[:aes.BlockSize]
	ciphertext := data[aes.BlockSize:]
	stream := cipher.NewCFBDecrypter(block, iv) //nolint:staticcheck // Interactsh CFB
	stream.XORKeyStream(ciphertext, ciphertext)
	return ciphertext, nil
}

// randomCorrelationID returns hex.
func randomCorrelationID() (string, error) {
	b, err := randomBytes(correlationIDLength / 2)
	if err != nil {
		return "", err
	}
	return fmt.Sprintf("%x", b), nil
}

// randomBytes returns n crypto-random bytes.
func randomBytes(n int) ([]byte, error) {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return nil, err
	}
	return b, nil
}
