package server

import (
	"context"

	pb "github.com/BaukunstPatrimonio/user-go/server/user-pb"

	"google.golang.org/protobuf/types/known/timestamppb"
)

func (s *UserServer) TokenToUser(ctx context.Context, req *pb.UserTokenRequest) (*pb.UserResponse, error) {
	user, err := s.UserController.TokenToUser(
		ctx,
		req.GetToken(),
		req.GetBrowser(),
		req.GetBrowserVersion(),
		req.GetOperatingSystem(),
		req.GetOperatingSystemVersion(),
		req.GetCpu(),
		req.GetLanguage(),
		req.GetTimezone(),
		req.GetCookiesEnabled(),
	)
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
