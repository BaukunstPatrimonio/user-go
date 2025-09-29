package server

import (
	"log/slog"

	"github.com/baukunstpatrimonio/user-go/server/controllers"
	pb "github.com/baukunstpatrimonio/user-go/server/user-pb"
)

type UserServer struct {
	pb.UnimplementedUserServer
	// users map[uint32]*pb.UserResponse
	UserController controllers.IControllerUser
	Log        *slog.Logger
}

func NewServer(
	userController controllers.IControllerUser,
	log *slog.Logger,
) *UserServer {
	return &UserServer{
		UserController: userController,
		Log:            log,
	}
}
