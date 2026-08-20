package passwordreset

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"io"
)

const TokenEntropyBytes = 32

var ErrMalformedToken = errors.New("malformed password reset token")

// GenerateToken returns a URL-safe raw token and the SHA-256 digest that may
// be persisted. The raw token must never be stored.
func GenerateToken() (string, string, error) {
	return generateToken(rand.Reader)
}

func generateToken(random io.Reader) (string, string, error) {
	bytes := make([]byte, TokenEntropyBytes)
	if _, err := io.ReadFull(random, bytes); err != nil {
		return "", "", err
	}
	rawToken := base64.RawURLEncoding.EncodeToString(bytes)
	return rawToken, digestBytes(bytes), nil
}

// DigestToken validates a generated token's URL-safe encoding and entropy
// length before returning its storage lookup digest.
func DigestToken(rawToken string) (string, error) {
	bytes, err := base64.RawURLEncoding.Strict().DecodeString(rawToken)
	if err != nil || len(bytes) != TokenEntropyBytes {
		return "", ErrMalformedToken
	}
	return digestBytes(bytes), nil
}

func digestBytes(bytes []byte) string {
	digest := sha256.Sum256(bytes)
	return hex.EncodeToString(digest[:])
}
