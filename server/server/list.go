package server

import (
	"context"

	pb "github.com/BaukunstPatrimonio/user-go/server/user-pb"
	"google.golang.org/protobuf/types/known/emptypb"
	"google.golang.org/protobuf/types/known/timestamppb"
)

func (s *UserServer) List(ctx context.Context, _ *emptypb.Empty) (*pb.ListUsersResponse, error) {
	users, err := s.UserController.GetAll(ctx)
	if err != nil {
		s.Log.Error(err.Error())
		return &pb.ListUsersResponse{}, err
	}

	pbUsers := []*pb.UserResponse{}

	for _, user := range users {
		pbUser := pb.UserResponse{
			Email:           user.Email,
			Name:            user.Name,
			ProfilePic:      user.ProfilePic,
			Validated:       user.Validated,
			Admin:           user.Admin,
			SuperAdmin:      user.SuperAdmin,
			Code:            user.Code,
			CodeExpire:      timestamppb.New(user.CodeExpire),
			Bucket:          user.Bucket,
		}
		pbUsers = append(pbUsers, &pbUser)
	}

	return &pb.ListUsersResponse{
		Users: pbUsers,
	}, nil
}
