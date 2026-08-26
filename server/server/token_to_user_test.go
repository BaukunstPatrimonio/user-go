package server

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"testing"

	"github.com/BaukunstPatrimonio/user-go/server/controllers"
	"github.com/BaukunstPatrimonio/user-go/server/models"
	pb "github.com/BaukunstPatrimonio/user-go/server/user-pb"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

type tokenToUserControllerStub struct {
	controllers.IControllerUser
	err error
}

func (s tokenToUserControllerStub) TokenToUser(context.Context, string, string, string, string, string, string, string, string, bool) (*models.User, error) {
	return &models.User{}, s.err
}

func TestTokenToUserMapsCredentialFailuresToUnauthenticated(t *testing.T) {
	tests := []struct {
		name string
		err  error
	}{
		{name: "expired token", err: models.ErrTokenExpired},
		{name: "invalid token", err: models.ErrInvalidToken},
		{name: "malformed token", err: models.ErrParsingToken},
		{name: "invalid signature", err: errors.Join(errors.New("jwt validation"), models.ErrInvalidSignature)},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			server := NewServer(tokenToUserControllerStub{err: test.err}, slog.New(slog.NewTextHandler(io.Discard, nil)))
			response, err := server.TokenToUser(context.Background(), &pb.UserTokenRequest{Token: "bad-token"})

			if got := status.Code(err); got != codes.Unauthenticated {
				t.Fatalf("TokenToUser() code = %v, want %v", got, codes.Unauthenticated)
			}
			if response == nil {
				t.Fatal("TokenToUser() response = nil, want empty response")
			}
		})
	}
}

func TestTokenToUserDoesNotMapInternalFailureToUnauthenticated(t *testing.T) {
	server := NewServer(
		tokenToUserControllerStub{err: errors.New("database unavailable")},
		slog.New(slog.NewTextHandler(io.Discard, nil)),
	)

	response, err := server.TokenToUser(context.Background(), &pb.UserTokenRequest{Token: "access-token"})
	if got := status.Code(err); got != codes.Internal {
		t.Fatalf("TokenToUser() code = %v, want %v", got, codes.Internal)
	}
	if response == nil {
		t.Fatal("TokenToUser() response = nil, want empty response")
	}
}
