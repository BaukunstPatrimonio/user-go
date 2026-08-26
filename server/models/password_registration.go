package models

import "time"

// PasswordRegistration is the internal result of creating an unvalidated
// password account. It deliberately contains neither credentials nor tokens.
type PasswordRegistration struct {
	UserID           uint
	VerificationCode string
	CodeExpires      time.Time
}

// PasswordInvitation is the trusted-boundary result of an administrative
// invitation. Empty token data means a validated identity with an existing
// password credential was reused and needs no password setup.
type PasswordInvitation struct {
	UserID             uint
	InvitationToken    string
	ExpiresAt          time.Time
	ExistingIdentity   bool
	PasswordConfigured bool
}

// EmailChange is the trusted-boundary result required to deliver a fresh
// verification link after an authenticated identity-email change.
type EmailChange struct {
	VerificationCode string
	CodeExpires      time.Time
}
