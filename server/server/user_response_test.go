package server

import (
	"context"
	"io"
	"log/slog"
	"testing"
	"time"

	"github.com/BaukunstPatrimonio/user-go/server/controllers"
	"github.com/BaukunstPatrimonio/user-go/server/models"
	pb "github.com/BaukunstPatrimonio/user-go/server/user-pb"
	"google.golang.org/protobuf/types/known/emptypb"
	"gorm.io/gorm"
)

type userResponseControllerStub struct {
	controllers.IControllerUser
	user *models.User
}

func (s userResponseControllerStub) Get(context.Context, uint, string) (*models.User, error) {
	return s.user, nil
}

func (s userResponseControllerStub) GetByEmail(context.Context, string) (*models.User, error) {
	return s.user, nil
}

func (s userResponseControllerStub) GetAll(context.Context) ([]*models.User, error) {
	return []*models.User{s.user}, nil
}

func (s userResponseControllerStub) TokenToUser(context.Context, string, string, string, string, string, string, string, string, bool) (*models.User, error) {
	return s.user, nil
}

func TestUserResponseMappingsExposeCanonicalIDAndPreserveExistingFields(t *testing.T) {
	user := mappedUserResponseFixture()
	server := NewServer(
		userResponseControllerStub{user: user},
		slog.New(slog.NewTextHandler(io.Discard, nil)),
	)

	tests := []struct {
		name string
		call func() (*pb.UserResponse, error)
	}{
		{
			name: "Get",
			call: func() (*pb.UserResponse, error) {
				return server.Get(context.Background(), &pb.UserIDRequest{Id: uint32(user.ID)})
			},
		},
		{
			name: "GetByEmail",
			call: func() (*pb.UserResponse, error) {
				return server.GetByEmail(context.Background(), &pb.UserMailRequest{Email: user.Email})
			},
		},
		{
			name: "TokenToUser",
			call: func() (*pb.UserResponse, error) {
				return server.TokenToUser(context.Background(), &pb.UserTokenRequest{})
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			response, err := test.call()
			if err != nil {
				t.Fatalf("%s() error = %v", test.name, err)
			}
			assertMappedUserResponse(t, response, user)
		})
	}

	list, err := server.List(context.Background(), &emptypb.Empty{})
	if err != nil {
		t.Fatalf("List() error = %v", err)
	}
	if len(list.Users) != 1 {
		t.Fatalf("List() users = %d, want 1", len(list.Users))
	}
	assertMappedUserResponse(t, list.Users[0], user)
}

func assertMappedUserResponse(t *testing.T, response *pb.UserResponse, user *models.User) {
	t.Helper()
	if response.GetId() != uint64(user.ID) {
		t.Fatalf("UserResponse.id = %d, want canonical user ID %d", response.GetId(), user.ID)
	}
	if response.GetEmail() != user.Email ||
		response.GetPhoneE164() != *user.PhoneE164 ||
		response.GetName() != user.Name ||
		response.GetProfilePic() != user.ProfilePic ||
		response.GetValidated() != user.Validated ||
		response.GetAdmin() != user.Admin ||
		response.GetSuperAdmin() != user.SuperAdmin ||
		response.GetCode() != user.Code ||
		response.GetBucket() != user.Bucket {
		t.Fatalf("UserResponse = %#v, want all existing fields from %#v", response, user)
	}
	if !response.GetCodeExpire().AsTime().Equal(user.CodeExpire) {
		t.Fatalf("UserResponse.code_expire = %v, want %v", response.GetCodeExpire().AsTime(), user.CodeExpire)
	}
}

func mappedUserResponseFixture() *models.User {
	phone := "+34600111222"
	return &models.User{
		Model:      gorm.Model{ID: 583},
		Email:      "person@example.com",
		PhoneE164:  &phone,
		Name:       "Existing Person",
		ProfilePic: "profile.png",
		Validated:  true,
		Admin:      true,
		SuperAdmin: false,
		Code:       "validation-code",
		CodeExpire: time.Date(2026, time.August, 20, 12, 0, 0, 0, time.UTC),
		Bucket:     "profile-bucket",
	}
}

func TestUserResponseMapsAbsentPhoneToEmptyProtoValue(t *testing.T) {
	user := mappedUserResponseFixture()
	user.PhoneE164 = nil
	server := NewServer(userResponseControllerStub{user: user}, slog.New(slog.NewTextHandler(io.Discard, nil)))
	response, err := server.Get(context.Background(), &pb.UserIDRequest{Id: uint32(user.ID)})
	if err != nil || response.GetPhoneE164() != "" {
		t.Fatalf("Get() absent phone = %q, %v, want empty proto value", response.GetPhoneE164(), err)
	}
}
