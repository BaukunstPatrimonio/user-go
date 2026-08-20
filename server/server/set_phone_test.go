package server

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"testing"

	"github.com/BaukunstPatrimonio/user-go/server/controllers"
	"github.com/BaukunstPatrimonio/user-go/server/dto"
	"github.com/BaukunstPatrimonio/user-go/server/models"
	pb "github.com/BaukunstPatrimonio/user-go/server/user-pb"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

type setPhoneControllerStub struct {
	controllers.IControllerUser
	statusCode int
	user       *models.User
	err        error
	request    dto.UserSetPhone
}

func (s *setPhoneControllerStub) SetPhone(_ context.Context, request dto.UserSetPhone) (int, *models.User, error) {
	s.request = request
	return s.statusCode, s.user, s.err
}

func TestSetPhoneRequiresAuthenticationEnvelopeAndPhone(t *testing.T) {
	for _, req := range []*pb.UserSetPhoneRequest{
		{},
		{PhoneE164: "+34600111222"},
		{Auth: &pb.UserTokenRequest{Token: "access-token"}},
	} {
		controller := &setPhoneControllerStub{}
		server := NewServer(controller, slog.New(slog.NewTextHandler(io.Discard, nil)))
		response, err := server.SetPhone(context.Background(), req)
		if status.Code(err) != codes.InvalidArgument || response == nil || controller.request.Token != "" {
			t.Fatalf("SetPhone(%#v) = %#v, %v, request %#v; want handler rejection", req, response, err, controller.request)
		}
	}
}

func TestSetPhoneMapsSecurityAndPersistenceErrors(t *testing.T) {
	for _, test := range []struct {
		name string
		err  error
		code codes.Code
	}{
		{name: "invalid phone", err: models.ErrInvalidPhone, code: codes.InvalidArgument},
		{name: "duplicate", err: models.ErrPhoneAlreadyExists, code: codes.AlreadyExists},
		{name: "device mismatch", err: models.ErrSecurityMismatch, code: codes.PermissionDenied},
		{name: "invalid token", err: models.ErrInvalidToken, code: codes.Unauthenticated},
		{name: "wrapped invalid token", err: errors.Join(errors.New("auth"), models.ErrInvalidSignature), code: codes.Unauthenticated},
		{name: "internal", err: errors.New("database unavailable"), code: codes.Internal},
	} {
		t.Run(test.name, func(t *testing.T) {
			controller := &setPhoneControllerStub{err: test.err}
			server := NewServer(controller, slog.New(slog.NewTextHandler(io.Discard, nil)))
			response, err := server.SetPhone(context.Background(), validSetPhoneRequest())
			if status.Code(err) != test.code || response == nil {
				t.Fatalf("SetPhone() = %#v, %v, want %v", response, err, test.code)
			}
		})
	}
}

func TestSetPhoneMapsAuthenticatedRequestAndReturnsExistingUserResponse(t *testing.T) {
	user := mappedUserResponseFixture()
	controller := &setPhoneControllerStub{statusCode: http.StatusOK, user: user}
	server := NewServer(controller, slog.New(slog.NewTextHandler(io.Discard, nil)))
	req := validSetPhoneRequest()

	response, err := server.SetPhone(context.Background(), req)
	if err != nil {
		t.Fatalf("SetPhone() error = %v", err)
	}
	assertMappedUserResponse(t, response, user)
	if controller.request.Token != req.Auth.Token || controller.request.PhoneE164 != req.PhoneE164 || controller.request.DeviceInfo != (models.DeviceInfo{
		Browser: req.Auth.Browser, BrowserVersion: req.Auth.BrowserVersion,
		OperatingSystem: req.Auth.OperatingSystem, OperatingSystemVersion: req.Auth.OperatingSystemVersion,
		Cpu: req.Auth.Cpu, Language: req.Auth.Language, Timezone: req.Auth.Timezone,
		CookiesEnabled: req.Auth.CookiesEnabled,
	}) {
		t.Fatalf("controller request = %#v, want authenticated nested request mapping", controller.request)
	}
}

func validSetPhoneRequest() *pb.UserSetPhoneRequest {
	return &pb.UserSetPhoneRequest{
		PhoneE164: "+34600111222",
		Auth: &pb.UserTokenRequest{
			Token: "access-token", Browser: "Firefox", BrowserVersion: "128",
			OperatingSystem: "Linux", OperatingSystemVersion: "6.10", Cpu: "x86_64",
			Language: "en-US", Timezone: "Europe/Madrid", CookiesEnabled: true,
		},
	}
}
