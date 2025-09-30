package server

import (
	"context"

	pb "github.com/BaukunstPatrimonio/user-go/server/user-pb"
)

func (s *UserServer) UpdateUserAdminStatus(ctx context.Context, req *pb.UpdateUserAdminRequest) (*pb.UserStatusResponse, error) {
	err := s.UserController.UpdateUserAdminStatus(ctx, req.Email, req.Admin)
	if err != nil {
		return nil, err
	}

	return &pb.UserStatusResponse{
		Status: 1,
	}, nil
}
