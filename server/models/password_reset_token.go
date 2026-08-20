package models

import "time"

// PasswordResetToken stores only a digest of a single-use reset token. UserID
// is unique so a new request atomically supersedes the user's previous token.
type PasswordResetToken struct {
	ID          uint       `gorm:"primaryKey"`
	UserID      uint       `gorm:"not null;uniqueIndex"`
	TokenDigest string     `gorm:"size:64;not null;uniqueIndex" json:"-"`
	ExpiresAt   time.Time  `gorm:"not null;index"`
	UsedAt      *time.Time `gorm:"index"`
	CreatedAt   time.Time
	User        User `gorm:"foreignKey:UserID;references:ID;constraint:OnUpdate:CASCADE,OnDelete:CASCADE;" json:"-"`
}
