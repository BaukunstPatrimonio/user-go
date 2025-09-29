package server

import (
	"context"

	pb "github.com/baukunstpatrimonio/user-go/server/user-pb"

	"google.golang.org/protobuf/types/known/timestamppb"
)

func (s *UserServer) GetByEmail(ctx context.Context, req *pb.UserMailRequest) (*pb.UserResponse, error) {
	user, err := s.UserController.GetByEmail(ctx, req.GetEmail())
	if err != nil {
		s.Log.Error(err.Error())
		return &pb.UserResponse{}, err
	}

	return &pb.UserResponse{
		Email:           user.Email,
		Name:            user.Name,
		ProfilePic:      user.ProfilePic,
		Validated:       user.Validated,
		Admin:           user.Admin,
		SuperAdmin:      user.SuperAdmin,
		Code:            user.Code,
		CodeExpire:      timestamppb.New(user.CodeExpire),
		Bucket:          user.Bucket,
	}, nil
}
