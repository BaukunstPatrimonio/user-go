package password

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"strings"
	"unicode/utf8"

	"golang.org/x/crypto/argon2"
	"golang.org/x/crypto/bcrypt"
)

const (
	argon2IDPrefix      = "$argon2id$"
	bcryptPrefix        = "$2"
	maxArgon2Memory     = 256 * 1024
	maxArgon2Iterations = 20
	maxArgon2SaltLength = 1024
	maxArgon2KeyLength  = 1024

	RegistrationMinimumLength = 8
	RegistrationMaximumLength = 128
)

var (
	ErrInvalidHash     = errors.New("invalid password hash encoding")
	ErrUnsupportedHash = errors.New("unsupported password hash encoding")
	ErrInvalidLength   = errors.New("password length is outside registration limits")
)

// ValidateRegistrationPassword applies the deliberately modest password
// policy used for new accounts. Lengths are measured in Unicode characters.
func ValidateRegistrationPassword(password string) error {
	if !utf8.ValidString(password) {
		return ErrInvalidLength
	}
	length := utf8.RuneCountInString(password)
	if length < RegistrationMinimumLength || length > RegistrationMaximumLength {
		return ErrInvalidLength
	}
	return nil
}

// Parameters defines the values encoded into newly generated Argon2id hashes.
type Parameters struct {
	Memory      uint32
	Iterations  uint32
	Parallelism uint8
	SaltLength  uint32
	KeyLength   uint32
}

// DefaultParameters returns the production parameters for newly generated
// password hashes. Verification reads parameters from each stored hash.
func DefaultParameters() Parameters {
	return Parameters{
		Memory:      64 * 1024,
		Iterations:  3,
		Parallelism: 4,
		SaltLength:  16,
		KeyLength:   32,
	}
}

// Manager hashes and verifies passwords without exposing persistence concerns.
type Manager interface {
	HashPassword(password string) (string, error)
	VerifyPassword(password, encodedHash string) (bool, error)
	IsBcryptHash(encodedHash string) bool
}

type manager struct {
	parameters Parameters
	random     io.Reader
}

func NewManager(parameters Parameters) Manager {
	return &manager{parameters: parameters, random: rand.Reader}
}

func NewDefaultManager() Manager {
	return NewManager(DefaultParameters())
}

func (m *manager) HashPassword(password string) (string, error) {
	if err := validateParameters(m.parameters); err != nil {
		return "", err
	}

	salt := make([]byte, m.parameters.SaltLength)
	if _, err := io.ReadFull(m.random, salt); err != nil {
		return "", fmt.Errorf("generate password salt: %w", err)
	}

	hash := argon2.IDKey(
		[]byte(password),
		salt,
		m.parameters.Iterations,
		m.parameters.Memory,
		m.parameters.Parallelism,
		m.parameters.KeyLength,
	)

	return fmt.Sprintf(
		"$argon2id$v=%d$m=%d,t=%d,p=%d$%s$%s",
		argon2.Version,
		m.parameters.Memory,
		m.parameters.Iterations,
		m.parameters.Parallelism,
		base64.RawStdEncoding.EncodeToString(salt),
		base64.RawStdEncoding.EncodeToString(hash),
	), nil
}

func (m *manager) VerifyPassword(password, encodedHash string) (bool, error) {
	switch {
	case strings.HasPrefix(encodedHash, argon2IDPrefix):
		return verifyArgon2ID(password, encodedHash)
	case m.IsBcryptHash(encodedHash):
		err := bcrypt.CompareHashAndPassword([]byte(encodedHash), []byte(password))
		if errors.Is(err, bcrypt.ErrMismatchedHashAndPassword) {
			return false, nil
		}
		if err != nil {
			return false, fmt.Errorf("verify bcrypt password: %w", ErrInvalidHash)
		}
		return true, nil
	default:
		return false, ErrUnsupportedHash
	}
}

func (*manager) IsBcryptHash(encodedHash string) bool {
	return strings.HasPrefix(encodedHash, bcryptPrefix)
}

func verifyArgon2ID(password, encodedHash string) (bool, error) {
	parameters, salt, expectedHash, err := decodeArgon2ID(encodedHash)
	if err != nil {
		return false, err
	}

	actualHash := argon2.IDKey(
		[]byte(password),
		salt,
		parameters.Iterations,
		parameters.Memory,
		parameters.Parallelism,
		uint32(len(expectedHash)),
	)
	return subtle.ConstantTimeCompare(actualHash, expectedHash) == 1, nil
}

func decodeArgon2ID(encodedHash string) (Parameters, []byte, []byte, error) {
	parts := strings.Split(encodedHash, "$")
	if len(parts) != 6 || parts[0] != "" || parts[1] != "argon2id" {
		return Parameters{}, nil, nil, ErrInvalidHash
	}

	var version int
	if count, err := fmt.Sscanf(parts[2], "v=%d", &version); err != nil || count != 1 || parts[2] != fmt.Sprintf("v=%d", version) || version != argon2.Version {
		return Parameters{}, nil, nil, ErrInvalidHash
	}

	parameters := Parameters{}
	var parallelism uint32
	if count, err := fmt.Sscanf(parts[3], "m=%d,t=%d,p=%d", &parameters.Memory, &parameters.Iterations, &parallelism); err != nil || count != 3 || parts[3] != fmt.Sprintf("m=%d,t=%d,p=%d", parameters.Memory, parameters.Iterations, parallelism) || parallelism > 255 {
		return Parameters{}, nil, nil, ErrInvalidHash
	}
	parameters.Parallelism = uint8(parallelism)

	salt, err := base64.RawStdEncoding.Strict().DecodeString(parts[4])
	if err != nil {
		return Parameters{}, nil, nil, ErrInvalidHash
	}
	expectedHash, err := base64.RawStdEncoding.Strict().DecodeString(parts[5])
	if err != nil {
		return Parameters{}, nil, nil, ErrInvalidHash
	}
	parameters.SaltLength = uint32(len(salt))
	parameters.KeyLength = uint32(len(expectedHash))
	if err := validateParameters(parameters); err != nil {
		return Parameters{}, nil, nil, ErrInvalidHash
	}

	return parameters, salt, expectedHash, nil
}

func validateParameters(parameters Parameters) error {
	if parameters.Memory == 0 || parameters.Iterations == 0 || parameters.Parallelism == 0 || parameters.SaltLength == 0 || parameters.KeyLength == 0 {
		return errors.New("argon2id parameters must be greater than zero")
	}
	if parameters.Memory > maxArgon2Memory || parameters.Iterations > maxArgon2Iterations || parameters.SaltLength > maxArgon2SaltLength || parameters.KeyLength > maxArgon2KeyLength {
		return errors.New("argon2id parameters exceed supported limits")
	}
	return nil
}
