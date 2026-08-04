package server

import (
	"context"
	"io"
	"log/slog"
	"testing"

	"github.com/BaukunstPatrimonio/user-go/server/controllers"
	"github.com/BaukunstPatrimonio/user-go/server/models"
	pb "github.com/BaukunstPatrimonio/user-go/server/user-pb"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

type refreshControllerStub struct {
	controllers.IControllerUser
}

func (refreshControllerStub) Refresh(context.Context, string, *pb.UserTokenRequest) (int, *models.Token, error) {
	return 0, &models.Token{}, models.ErrSessionDeviceMismatch
}

func TestRefreshMapsDeviceMismatchToUnauthenticated(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	server := NewServer(refreshControllerStub{}, logger)

	response, err := server.Refresh(context.Background(), &pb.UserTokenRequest{})
	if got, want := status.Code(err), codes.Unauthenticated; got != want {
		t.Fatalf("Refresh() error code = %v, want %v", got, want)
	}
	if got, want := status.Convert(err).Message(), "session_device_mismatch"; got != want {
		t.Fatalf("Refresh() error message = %q, want %q", got, want)
	}
	if response == nil {
		t.Fatal("Refresh() response = nil, want empty response")
	}
}
