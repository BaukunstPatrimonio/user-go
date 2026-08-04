package services

import (
	"context"

	"github.com/BaukunstPatrimonio/user-go/server/models"
	"gorm.io/gorm"
)

func (s *userService) UpdateRefreshSession(ctx context.Context, id uint, device models.DeviceInfo, oldCodeRefresh, newCodeRefresh string) error {
	return s.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		result := tx.Model(&models.User{}).
			Where("id = ? AND code_refresh = ?", id, oldCodeRefresh).
			Updates(map[string]any{
				"browser":                  device.Browser,
				"browser_version":          device.BrowserVersion,
				"operating_system":         device.OperatingSystem,
				"operating_system_version": device.OperatingSystemVersion,
				"language":                 device.Language,
				"timezone":                 device.Timezone,
				"cpu":                      device.Cpu,
				"code_refresh":             newCodeRefresh,
			})
		if result.Error != nil {
			return result.Error
		}
		if result.RowsAffected == 0 {
			return models.ErrInvalidCode
		}
		return nil
	})
}
