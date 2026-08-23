package models

import (
	"time"

	"gorm.io/gorm"
)

type DeviceInfo struct {
	Browser                string `json:"browser"`
	BrowserVersion         string `json:"browser_version"`
	OperatingSystem        string `json:"operating_system"`
	OperatingSystemVersion string `json:"operating_system_version"`
	Cpu                    string `json:"cpu"`
	Language               string `json:"language"`
	Timezone               string `json:"timezone"`
	CookiesEnabled         bool   `json:"cookies_enabled"`
}

type User struct {
	//user data
	gorm.Model
	DeviceInfo
	Email        string  `gorm:"uniqueIndex:idx_email;not null" validate:"email,required"`
	PendingEmail string  `gorm:"type:varchar(320)"`
	PhoneE164    *string `gorm:"type:varchar(16);uniqueIndex:idx_phone_e164" json:"phone_e164,omitempty"`
	Name         string  `gorm:"not null" validate:"required"`
	ProfilePic   string  `gorm:"not null"`
	// server data
	Admin       bool `gorm:"not null;default:false"`
	SuperAdmin  bool `gorm:"not null;default:false"`
	Validated   bool `gorm:"not null;default:false" validate:"boolean"`
	Code        string
	CodeRefresh string
	CodeExpire  time.Time `gorm:"default:CURRENT_TIMESTAMP"`
	Bucket      string
}
