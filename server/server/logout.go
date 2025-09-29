package server

import (
	"context"

	pb "github.com/baukunstpatrimonio/user-go/server/user-pb"
)

func (s *UserServer) LogOut(ctx context.Context, req *pb.UserMailRequest) (*pb.UserStatusResponse, error) {
	status, err := s.UserController.LogOut(ctx, req.GetEmail())
	if err != nil {
		s.Log.Error(err.Error())
		return &pb.UserStatusResponse{}, err
	}

	return &pb.UserStatusResponse{
		Status: uint32(status),
	}, nil
}
