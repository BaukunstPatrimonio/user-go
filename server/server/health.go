package server

import (
	"context"
	"errors"
	"net/http"

	pb "github.com/BaukunstPatrimonio/user-go/server/user-pb"
)

func (s *UserServer) Health(ctx context.Context, req *pb.UserIDRequest) (*pb.UserStatusResponse, error) {
	status := s.UserController.Health(ctx, req.GetId())
	if status != http.StatusOK {
		errMsg := "unhealthy"
		s.Log.Error(errMsg)
		return &pb.UserStatusResponse{}, errors.New(errMsg)
	}

	s.Log.Info("healthy")

	return &pb.UserStatusResponse{
		Status: http.StatusOK,
	}, nil
}
