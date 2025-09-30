package db

import (
	"errors"
	"fmt"
	"log"
	"log/slog"

	"github.com/BaukunstPatrimonio/user-go/server/models"
	"gorm.io/driver/postgres"
	"gorm.io/gorm"
)

func GetDB_PG(cfg *models.Config, l *slog.Logger) *gorm.DB {

	dsn := fmt.Sprintf("host=%s port=%s user=%s password=%s dbname=%s sslmode=disable",
		cfg.POSTGRES_HOST, cfg.POSTGRES_PORT, cfg.POSTGRES_USER, cfg.POSTGRES_PASSWORD, cfg.POSTGRES_DB)

	db, err := gorm.Open(postgres.Open(dsn), &gorm.Config{
		TranslateError: true,
	})
	if err != nil {
		l.Error("failed to connect database PostGres")
		log.Fatal("failed to connect database PostGres")
	}

	l.Info("DB PostGres Connection established!")

	if err = db.AutoMigrate(&models.User{}); err != nil {
		log.Fatal("failed to AutoMigrate database PostGres")
		if db.Migrator().HasTable(&models.User{}) {
			if err := db.First(&models.User{}).Error; errors.Is(err, gorm.ErrRecordNotFound) {
				db.Create(&models.User{
					Email:      "goodbytes23@gmail.com",
					Name:       "Alvaro",
					Admin:      true,
					SuperAdmin: true,
				})
			}
		}
	}

	return db
}
