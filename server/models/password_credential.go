package models

import "time"

// PasswordCredential stores the password hash for a user that supports
// password authentication. It is kept separate from public user responses.
type PasswordCredential struct {
	UserID       uint   `gorm:"primaryKey;autoIncrement:false"`
	PasswordHash string `gorm:"type:text;not null" json:"-"`
	CreatedAt    time.Time
	UpdatedAt    time.Time
	User         User `gorm:"foreignKey:UserID;references:ID;constraint:OnUpdate:CASCADE,OnDelete:CASCADE;" json:"-"`
}
