package models

import "time"

// PasswordRegistration is the internal result of creating an unvalidated
// password account. It deliberately contains neither credentials nor tokens.
type PasswordRegistration struct {
	UserID           uint
	VerificationCode string
	CodeExpires      time.Time
}

// EmailChange is the trusted-boundary result required to deliver a fresh
// verification link after an authenticated identity-email change.
type EmailChange struct {
	VerificationCode string
	CodeExpires      time.Time
}
