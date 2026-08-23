package server

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/BaukunstPatrimonio/user-go/server/controllers"
	"github.com/BaukunstPatrimonio/user-go/server/dto"
	"github.com/BaukunstPatrimonio/user-go/server/models"
	pb "github.com/BaukunstPatrimonio/user-go/server/user-pb"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

type passwordRegistrationControllerStub struct {
	controllers.IControllerUser
	statusCode   int
	result       *models.PasswordRegistration
	err          error
	registration dto.UserRegisterWithPassword
}

func (s *passwordRegistrationControllerStub) RegisterWithPassword(_ context.Context, registration dto.UserRegisterWithPassword) (int, *models.PasswordRegistration, error) {
	s.registration = registration
	return s.statusCode, s.result, s.err
}

func TestRegisterWithPasswordRejectsInvalidRequests(t *testing.T) {
	tests := []struct {
		name string
		req  *pb.UserRegisterWithPasswordRequest
	}{
		{name: "missing email", req: &pb.UserRegisterWithPasswordRequest{Name: "Person", Password: "fake-password"}},
		{name: "malformed email", req: &pb.UserRegisterWithPasswordRequest{Email: "not-an-email", Name: "Person", Password: "fake-password"}},
		{name: "missing name", req: &pb.UserRegisterWithPasswordRequest{Email: "person@example.com", Password: "fake-password"}},
		{name: "missing password", req: &pb.UserRegisterWithPasswordRequest{Email: "person@example.com", Name: "Person"}},
		{name: "long password", req: &pb.UserRegisterWithPasswordRequest{Email: "person@example.com", Name: "Person", Password: strings.Repeat("a", 129)}},
		{name: "invalid phone", req: &pb.UserRegisterWithPasswordRequest{Email: "person@example.com", Name: "Person", Password: "phase-three-fake-password!", PhoneE164: "600111222"}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			controller := &passwordRegistrationControllerStub{}
			server := NewServer(controller, slog.New(slog.NewTextHandler(io.Discard, nil)))

			response, err := server.RegisterWithPassword(context.Background(), test.req)
			if status.Code(err) != codes.InvalidArgument {
				t.Fatalf("RegisterWithPassword() error = %v, want InvalidArgument", err)
			}
			if response == nil || controller.registration.Email != "" || controller.registration.Password != "" {
				t.Fatalf("invalid request reached controller or returned nil response: registration %#v response %#v", controller.registration, response)
			}
		})
	}
}

func TestRegisterWithPasswordAcceptsExistingHortaTechPassword(t *testing.T) {
	controller := &passwordRegistrationControllerStub{
		statusCode: http.StatusCreated,
		result:     &models.PasswordRegistration{UserID: 583},
	}
	server := NewServer(controller, slog.New(slog.NewTextHandler(io.Discard, nil)))
	req := validPasswordRegistrationRequest()
	req.Password = "hola"

	response, err := server.RegisterWithPassword(context.Background(), req)
	if err != nil || response.GetStatus() != http.StatusCreated || controller.registration.Password != "hola" {
		t.Fatalf("RegisterWithPassword() = %#v, %v registration=%#v", response, err, controller.registration)
	}
}

func TestRegisterWithPasswordMapsErrors(t *testing.T) {
	tests := []struct {
		name string
		err  error
		code codes.Code
		msg  string
	}{
		{name: "invalid password", err: models.ErrInvalidPassword, code: codes.InvalidArgument, msg: models.ErrInvalidPassword.Error()},
		{name: "invalid phone", err: models.ErrInvalidPhone, code: codes.InvalidArgument, msg: models.ErrInvalidPhone.Error()},
		{name: "existing user", err: models.ErrUserAlreadyExists, code: codes.AlreadyExists, msg: models.ErrUserAlreadyExists.Error()},
		{name: "existing phone", err: models.ErrPhoneAlreadyExists, code: codes.AlreadyExists, msg: models.ErrPhoneAlreadyExists.Error()},
		{name: "wrapped existing user", err: errors.Join(errors.New("registration"), models.ErrUserAlreadyExists), code: codes.AlreadyExists, msg: models.ErrUserAlreadyExists.Error()},
		{name: "deadline", err: context.DeadlineExceeded, code: codes.DeadlineExceeded, msg: context.DeadlineExceeded.Error()},
		{name: "internal", err: errors.New("database unavailable"), code: codes.Internal, msg: "internal server error"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			controller := &passwordRegistrationControllerStub{err: test.err}
			server := NewServer(controller, slog.New(slog.NewTextHandler(io.Discard, nil)))

			response, err := server.RegisterWithPassword(context.Background(), validPasswordRegistrationRequest())
			if got := status.Code(err); got != test.code {
				t.Fatalf("RegisterWithPassword() code = %v, want %v", got, test.code)
			}
			if got := status.Convert(err).Message(); got != test.msg {
				t.Fatalf("RegisterWithPassword() message = %q, want %q", got, test.msg)
			}
			if response == nil {
				t.Fatal("RegisterWithPassword() response = nil, want empty response")
			}
		})
	}
}

func TestRegisterWithPasswordReturnsRegistrationResponseWithoutTokens(t *testing.T) {
	expires := time.Date(2026, time.August, 20, 12, 10, 0, 0, time.UTC)
	controller := &passwordRegistrationControllerStub{
		statusCode: http.StatusCreated,
		result: &models.PasswordRegistration{
			UserID: 583, VerificationCode: "verification-code", CodeExpires: expires,
		},
	}
	server := NewServer(controller, slog.New(slog.NewTextHandler(io.Discard, nil)))
	req := validPasswordRegistrationRequest()
	req.Email = "  Person@Example.COM "
	req.Name = "  Person  "
	req.PhoneE164 = "  +34600111222  "

	response, err := server.RegisterWithPassword(context.Background(), req)
	if err != nil {
		t.Fatalf("RegisterWithPassword() error = %v", err)
	}
	if response.GetUserId() != 583 || response.GetVerificationCode() != "verification-code" || response.GetStatus() != http.StatusCreated || !response.GetCodeExpires().AsTime().Equal(expires) {
		t.Fatalf("RegisterWithPassword() response = %#v", response)
	}
	fields := response.ProtoReflect().Descriptor().Fields()
	if fields.ByName("token") != nil || fields.ByName("token_refresh") != nil {
		t.Fatal("registration response unexpectedly exposes JWT fields")
	}
	if controller.registration.Email != "person@example.com" || controller.registration.PhoneE164 != "+34600111222" || controller.registration.Name != "Person" || controller.registration.Password != req.Password || controller.registration.DeviceInfo.Browser != req.Browser || controller.registration.CookiesEnabled != req.CookiesEnabled {
		t.Fatalf("controller registration = %#v, want request mapping", controller.registration)
	}
}

func validPasswordRegistrationRequest() *pb.UserRegisterWithPasswordRequest {
	return &pb.UserRegisterWithPasswordRequest{
		Email:                  "person@example.com",
		Name:                   "Person",
		Password:               "phase-three-fake-password!",
		Browser:                "Firefox",
		BrowserVersion:         "128",
		OperatingSystem:        "Linux",
		OperatingSystemVersion: "6.10",
		Cpu:                    "x86_64",
		Language:               "en-US",
		Timezone:               "Europe/Madrid",
		CookiesEnabled:         true,
	}
}
