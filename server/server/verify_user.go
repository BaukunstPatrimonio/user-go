package server

import (
	"context"

	pb "github.com/BaukunstPatrimonio/user-go/server/user-pb"
)

// VerifyUser manually marks an existing user identity as validated. Callers
// must have already applied their own authorization policy.
func (s *UserServer) VerifyUser(ctx context.Context, req *pb.UserIDRequest) (*pb.UserStatusResponse, error) {
	if err := s.UserController.VerifyUserSvc(ctx, uint(req.GetId())); err != nil {
		s.Log.Error(err.Error())
		return &pb.UserStatusResponse{}, err
	}
	return &pb.UserStatusResponse{Status: 1}, nil
}
