package models

import "time"

// PasswordResetRequest is returned only across the trusted internal boundary.
// Empty token data represents the same accepted result for an ineligible email.
type PasswordResetRequest struct {
	ResetToken string `json:"-"`
	ExpiresAt  time.Time
}
