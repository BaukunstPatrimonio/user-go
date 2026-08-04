package services

import (
	"github.com/BaukunstPatrimonio/user-go/server/models"
	"github.com/alvarotor/entitier-go/repository"
	"gorm.io/gorm"
)

type userService struct {
	repository.IGenericRepo[models.User, uint]
	db *gorm.DB
}

func NewUserService(
	db *gorm.DB,
) IUserService {
	repo := repository.NewGenericRepository[models.User, uint](db)
	return &userService{
		IGenericRepo: repo,
		db:           db,
	}
}
