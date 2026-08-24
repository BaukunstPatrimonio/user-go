package server

import (
	"context"

	pb "github.com/BaukunstPatrimonio/user-go/server/user-pb"
)

func (s *UserServer) LogOut(ctx context.Context, req *pb.UserMailRequest) (response *pb.UserStatusResponse, err error) {
	defer func() { s.logApplicationOutcome(ctx, "logout", err) }()
	status, err := s.UserController.LogOut(ctx, req.GetEmail())
	if err != nil {
		return &pb.UserStatusResponse{}, err
	}

	return &pb.UserStatusResponse{
		Status: uint32(status),
	}, nil
}
