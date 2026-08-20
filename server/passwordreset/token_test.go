package passwordreset

import (
	"encoding/base64"
	"errors"
	"strings"
	"testing"
)

func TestGenerateTokenUsesURLSafeThirtyTwoByteEntropy(t *testing.T) {
	rawToken, digest, err := GenerateToken()
	if err != nil {
		t.Fatalf("GenerateToken() error = %v", err)
	}
	decoded, err := base64.RawURLEncoding.Strict().DecodeString(rawToken)
	if err != nil || len(decoded) != TokenEntropyBytes {
		t.Fatalf("generated token = %q decoded length %d error %v", rawToken, len(decoded), err)
	}
	if len(digest) != 64 || strings.Contains(digest, rawToken) {
		t.Fatalf("digest = %q, want a separate SHA-256 hex digest", digest)
	}
	wantDigest, err := DigestToken(rawToken)
	if err != nil || wantDigest != digest {
		t.Fatalf("DigestToken() = %q, %v, want %q", wantDigest, err, digest)
	}
}

func TestGenerateTokenUsesFreshRandomness(t *testing.T) {
	first, firstDigest, err := GenerateToken()
	if err != nil {
		t.Fatalf("first GenerateToken() error = %v", err)
	}
	second, secondDigest, err := GenerateToken()
	if err != nil {
		t.Fatalf("second GenerateToken() error = %v", err)
	}
	if first == second || firstDigest == secondDigest {
		t.Fatal("independent reset tokens or digests unexpectedly match")
	}
}

func TestDigestTokenRejectsMalformedValues(t *testing.T) {
	for _, rawToken := range []string{"", "not+url/safe", "c2hvcnQ", strings.Repeat("a", 44)} {
		t.Run(rawToken, func(t *testing.T) {
			digest, err := DigestToken(rawToken)
			if digest != "" || !errors.Is(err, ErrMalformedToken) {
				t.Fatalf("DigestToken(%q) = %q, %v, want malformed", rawToken, digest, err)
			}
		})
	}
}
