package password

import (
	"errors"
	"strings"
	"testing"

	"golang.org/x/crypto/bcrypt"
)

const fakePassword = "correct horse battery staple!"

func TestDefaultParameters(t *testing.T) {
	parameters := DefaultParameters()
	if parameters.Memory != 64*1024 || parameters.Iterations != 3 || parameters.Parallelism != 4 || parameters.SaltLength != 16 || parameters.KeyLength != 32 {
		t.Fatalf("DefaultParameters() = %#v, want 64 MiB/3/4/16/32", parameters)
	}
}

func TestValidateRegistrationPassword(t *testing.T) {
	tests := []struct {
		name     string
		password string
		valid    bool
	}{
		{name: "minimum", password: strings.Repeat("a", RegistrationMinimumLength), valid: true},
		{name: "existing frontend password", password: "hola", valid: true},
		{name: "long passphrase", password: strings.Repeat("word ", 20), valid: true},
		{name: "unicode counts as characters", password: strings.Repeat("ñ", RegistrationMinimumLength), valid: true},
		{name: "invalid utf8", password: string([]byte{0xff, 0xfe, 0xfd})},
		{name: "empty", password: ""},
		{name: "too long", password: strings.Repeat("a", RegistrationMaximumLength+1)},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			err := ValidateRegistrationPassword(test.password)
			if test.valid && err != nil {
				t.Fatalf("ValidateRegistrationPassword() error = %v, want nil", err)
			}
			if !test.valid && !errors.Is(err, ErrInvalidLength) {
				t.Fatalf("ValidateRegistrationPassword() error = %v, want %v", err, ErrInvalidLength)
			}
		})
	}
}

func TestValidateResetPasswordUsesExistingFrontendMinimum(t *testing.T) {
	if err := ValidateResetPassword("hola"); err != nil {
		t.Fatalf("ValidateResetPassword(hola) = %v, want nil", err)
	}
	if err := ValidateResetPassword(""); !errors.Is(err, ErrInvalidLength) {
		t.Fatalf("ValidateResetPassword(empty) = %v, want %v", err, ErrInvalidLength)
	}
}

func TestArgon2IDHashAndVerification(t *testing.T) {
	manager := newTestManager()
	encodedHash, err := manager.HashPassword(fakePassword)
	if err != nil {
		t.Fatalf("HashPassword() error = %v", err)
	}
	if !strings.HasPrefix(encodedHash, "$argon2id$v=19$m=8192,t=1,p=1$") {
		t.Fatalf("HashPassword() encoding = %q, want PHC-style Argon2id encoding", encodedHash)
	}

	valid, err := manager.VerifyPassword(fakePassword, encodedHash)
	if err != nil || !valid {
		t.Fatalf("VerifyPassword(correct) = %v, %v, want true, nil", valid, err)
	}
	valid, err = manager.VerifyPassword("obviously-wrong-password", encodedHash)
	if err != nil || valid {
		t.Fatalf("VerifyPassword(wrong) = %v, %v, want false, nil", valid, err)
	}
}

func TestArgon2IDUsesDifferentRandomSalts(t *testing.T) {
	manager := newTestManager()
	first, err := manager.HashPassword(fakePassword)
	if err != nil {
		t.Fatalf("first HashPassword() error = %v", err)
	}
	second, err := manager.HashPassword(fakePassword)
	if err != nil {
		t.Fatalf("second HashPassword() error = %v", err)
	}
	if first == second {
		t.Fatal("HashPassword() returned identical encodings for independently salted hashes")
	}
}

func TestArgon2IDVerifierReadsStoredParameters(t *testing.T) {
	writer := NewManager(Parameters{Memory: 12 * 1024, Iterations: 2, Parallelism: 2, SaltLength: 24, KeyLength: 48})
	encodedHash, err := writer.HashPassword(fakePassword)
	if err != nil {
		t.Fatalf("HashPassword() error = %v", err)
	}

	reader := newTestManager()
	valid, err := reader.VerifyPassword(fakePassword, encodedHash)
	if err != nil || !valid {
		t.Fatalf("VerifyPassword() = %v, %v, want parameters read from encoding", valid, err)
	}
}

func TestMalformedAndUnsupportedHashesAreRejected(t *testing.T) {
	manager := newTestManager()
	tests := []struct {
		name string
		hash string
		err  error
	}{
		{name: "truncated argon", hash: "$argon2id$v=19$m=8192,t=1,p=1$bad", err: ErrInvalidHash},
		{name: "bad base64", hash: "$argon2id$v=19$m=8192,t=1,p=1$%%%$%%%", err: ErrInvalidHash},
		{name: "trailing version data", hash: "$argon2id$v=19x$m=8192,t=1,p=1$c2FsdA$aGFzaA", err: ErrInvalidHash},
		{name: "trailing parameter data", hash: "$argon2id$v=19$m=8192,t=1,p=1x$c2FsdA$aGFzaA", err: ErrInvalidHash},
		{name: "excessive memory", hash: "$argon2id$v=19$m=262145,t=1,p=1$c2FsdA$aGFzaA", err: ErrInvalidHash},
		{name: "unsupported", hash: "$scrypt$not-supported", err: ErrUnsupportedHash},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			valid, err := manager.VerifyPassword(fakePassword, test.hash)
			if valid || !errors.Is(err, test.err) {
				t.Fatalf("VerifyPassword() = %v, %v, want false, %v", valid, err, test.err)
			}
		})
	}
}

func TestBcryptVerification(t *testing.T) {
	manager := newTestManager()
	legacyHash, err := bcrypt.GenerateFromPassword([]byte(fakePassword), bcrypt.MinCost)
	if err != nil {
		t.Fatalf("GenerateFromPassword() error = %v", err)
	}
	if !manager.IsBcryptHash(string(legacyHash)) {
		t.Fatalf("IsBcryptHash(%q) = false, want true", legacyHash)
	}

	valid, err := manager.VerifyPassword(fakePassword, string(legacyHash))
	if err != nil || !valid {
		t.Fatalf("VerifyPassword(correct bcrypt) = %v, %v, want true, nil", valid, err)
	}
	valid, err = manager.VerifyPassword("obviously-wrong-password", string(legacyHash))
	if err != nil || valid {
		t.Fatalf("VerifyPassword(wrong bcrypt) = %v, %v, want false, nil", valid, err)
	}
}

func newTestManager() Manager {
	return NewManager(Parameters{Memory: 8 * 1024, Iterations: 1, Parallelism: 1, SaltLength: 16, KeyLength: 32})
}
