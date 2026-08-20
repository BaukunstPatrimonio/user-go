package phone

import (
	"errors"
	"testing"
)

func TestNormalizeE164(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  string
	}{
		{name: "Spain", input: "+34600111222", want: "+34600111222"},
		{name: "UK", input: "+447700900123", want: "+447700900123"},
		{name: "surrounding whitespace", input: "  +34600111222\t", want: "+34600111222"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			got, err := NormalizeE164(test.input)
			if err != nil || got != test.want {
				t.Fatalf("NormalizeE164(%q) = %q, %v, want %q", test.input, got, err, test.want)
			}
		})
	}
}

func TestNormalizeE164RejectsNonCanonicalAndMalformedNumbers(t *testing.T) {
	tests := map[string]string{
		"missing plus":          "34600111222",
		"zero country code":     "+04600111222",
		"letters":               "+34600ABC222",
		"too many digits":       "+1234567890123456",
		"obviously too short":   "+1234567",
		"local Spanish number":  "600111222",
		"spaces inside number":  "+34 600111222",
		"hyphens inside number": "+34-600111222",
	}
	for name, input := range tests {
		t.Run(name, func(t *testing.T) {
			got, err := NormalizeE164(input)
			if got != "" || !errors.Is(err, ErrInvalidE164) {
				t.Fatalf("NormalizeE164(%q) = %q, %v, want invalid", input, got, err)
			}
		})
	}
}
