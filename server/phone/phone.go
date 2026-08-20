package phone

import (
	"errors"
	"strings"
)

const (
	MinimumDigits = 8
	MaximumDigits = 15
)

var ErrInvalidE164 = errors.New("invalid E.164 phone number")

// NormalizeE164 trims surrounding whitespace and requires an already complete
// international E.164 number. It never infers a country code.
func NormalizeE164(value string) (string, error) {
	canonical := strings.TrimSpace(value)
	if len(canonical) < 2 || canonical[0] != '+' {
		return "", ErrInvalidE164
	}
	digits := canonical[1:]
	if len(digits) < MinimumDigits || len(digits) > MaximumDigits || digits[0] == '0' {
		return "", ErrInvalidE164
	}
	for _, character := range digits {
		if character < '0' || character > '9' {
			return "", ErrInvalidE164
		}
	}
	return canonical, nil
}
