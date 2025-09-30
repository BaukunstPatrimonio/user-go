package server

import (
	"context"
	"errors"

	pb "github.com/BaukunstPatrimonio/user-go/server/user-pb"
)

func (s *UserServer) Delete(ctx context.Context, req *pb.UserDeleteRequest) (*pb.UserStatusResponse, error) {

	if req.GetEmail() == "" {
		errMsg:="email is required"
		s.Log.Error(errMsg)
		return &pb.UserStatusResponse{}, errors.New(errMsg)
	}

	userMailRequest := pb.UserMailRequest{
		Email: req.GetEmail(),
	}
	user, err := s.GetIDByEmail(ctx, &userMailRequest)
	if err != nil {
		s.Log.Error(err.Error())
		return &pb.UserStatusResponse{}, err
	}

	err = s.UserController.Delete(ctx, uint(user.GetId()), req.Permanently)
	if err != nil {
		s.Log.Error(err.Error())
		return &pb.UserStatusResponse{}, err
	}

	return &pb.UserStatusResponse{
		Status: 1,
	}, nil
}
