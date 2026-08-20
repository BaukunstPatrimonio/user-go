package models

import "time"

// PasswordRegistration is the internal result of creating an unvalidated
// password account. It deliberately contains neither credentials nor tokens.
type PasswordRegistration struct {
	UserID           uint
	VerificationCode string
	CodeExpires      time.Time
}
