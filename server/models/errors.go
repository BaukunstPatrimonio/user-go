package models

import "errors"

var (
	ErrUserNotFound          = errors.New("user not found")
	ErrUserNotAuthenticated  = errors.New("user not authenticated")
	ErrInvalidCode           = errors.New("code is invalid")
	ErrExpiredCode           = errors.New("code is expired")
	ErrUserNotLogged         = errors.New("user not logged")
	ErrInvalidUser           = errors.New("invalid user")
	ErrSecurityMismatch      = errors.New("security data user's token don't match")
	ErrInvalidSignature      = errors.New("invalid signature token")
	ErrTokenExpired          = errors.New("token expired")
	ErrParsingToken          = errors.New("error parsing token")
	ErrInvalidToken          = errors.New("invalid token")
	ErrSessionDeviceMismatch = errors.New("session device mismatch")
)
