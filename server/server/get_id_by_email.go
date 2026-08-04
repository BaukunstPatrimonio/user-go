package server

import (
	"context"

	pb "github.com/BaukunstPatrimonio/user-go/server/user-pb"
)

func (s *UserServer) GetIDByEmail(ctx context.Context, req *pb.UserMailRequest) (*pb.UserIDResponse, error) {
	user, err := s.UserController.GetByEmail(ctx, req.GetEmail())
	if err != nil {
		s.Log.Error(err.Error())
		return &pb.UserIDResponse{}, err
	}

	return &pb.UserIDResponse{
		Id: uint32(user.ID),
	}, nil
}
