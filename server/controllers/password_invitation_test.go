package controllers

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/BaukunstPatrimonio/user-go/server/dto"
	"github.com/BaukunstPatrimonio/user-go/server/models"
	passwordService "github.com/BaukunstPatrimonio/user-go/server/password"
	"github.com/BaukunstPatrimonio/user-go/server/passwordreset"
	"github.com/BaukunstPatrimonio/user-go/server/services"
	entModels "github.com/alvarotor/entitier-go/models"
)

type invitationLifecycleService struct {
	services.IUserService
	mu         sync.Mutex
	user       *models.User
	credential *models.PasswordCredential
	token      *models.PasswordResetToken
}

func (s *invitationLifecycleService) InvitePasswordUser(_ context.Context, candidate models.User, token models.PasswordResetToken) (*models.User, bool, bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	existing := s.user != nil
	if !existing {
		candidate.ID = 583
		s.user = &candidate
	}
	configured := s.credential != nil
	if !configured {
		token.ID = 901
		token.UserID = s.user.ID
		s.token = &token
	}
	copy := *s.user
	return &copy, existing, configured, nil
}

func (s *invitationLifecycleService) GetByEmail(_ context.Context, email string) (*models.User, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.user == nil || !strings.EqualFold(s.user.Email, email) {
		return nil, entModels.ErrNotFound
	}
	copy := *s.user
	return &copy, nil
}

func (s *invitationLifecycleService) GetPasswordCredential(_ context.Context, userID uint) (*models.PasswordCredential, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.credential == nil || s.credential.UserID != userID {
		return nil, models.ErrCredentialNotFound
	}
	copy := *s.credential
	return &copy, nil
}

func (s *invitationLifecycleService) ResetPasswordWithToken(_ context.Context, digest, hash string, now time.Time) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.token == nil || s.token.TokenDigest != digest || s.token.UsedAt != nil || !s.token.ExpiresAt.After(now) {
		return models.ErrInvalidPasswordResetToken
	}
	s.credential = &models.PasswordCredential{UserID: s.user.ID, PasswordHash: hash}
	used := now
	s.token.UsedAt = &used
	s.user.Validated = true
	s.user.CodeRefresh = "OUT"
	return nil
}

func (s *invitationLifecycleService) StartPasswordSession(_ context.Context, userID uint, device models.DeviceInfo, code string, expires time.Time, refresh string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.user == nil || s.user.ID != userID {
		return models.ErrUserNotFound
	}
	s.user.DeviceInfo, s.user.Code, s.user.CodeExpire, s.user.CodeRefresh = device, code, expires, refresh
	return nil
}

func TestInvitationCreatesNoPasswordUntilOneTimeSetupThenLoginSucceeds(t *testing.T) {
	controller, storage := newInvitationController()
	statusCode, invitation, err := controller.InviteWithPasswordSetup(context.Background(), dto.UserInvitation{Email: " Invited@Example.com ", Name: "Invited User"})
	if err != nil || statusCode != http.StatusCreated || invitation.UserID != 583 || invitation.InvitationToken == "" || storage.credential != nil {
		t.Fatalf("InviteWithPasswordSetup() = %d, %#v, %v state:%#v", statusCode, invitation, err, storage.credential)
	}
	digest, err := passwordreset.DigestToken(invitation.InvitationToken)
	if err != nil || storage.token.TokenDigest != digest || storage.token.TokenDigest == invitation.InvitationToken {
		t.Fatalf("stored token = %#v, digest error = %v", storage.token, err)
	}

	login := dto.UserLoginWithPassword{Email: "invited@example.com", Password: "chosen-password"}
	loginStatus, _, loginErr := controller.LoginWithPassword(context.Background(), login)
	if loginStatus != http.StatusUnauthorized || !errors.Is(loginErr, models.ErrInvalidCredentials) {
		t.Fatalf("login before setup = %d, %v", loginStatus, loginErr)
	}
	resetStatus, err := controller.ResetPassword(context.Background(), dto.UserResetPassword{ResetToken: invitation.InvitationToken, NewPassword: "chosen-password"})
	if err != nil || resetStatus != http.StatusOK || storage.credential == nil || !strings.HasPrefix(storage.credential.PasswordHash, "$argon2id$") || !storage.user.Validated {
		t.Fatalf("password setup = %d, %v state:%#v/%#v", resetStatus, err, storage.user, storage.credential)
	}
	loginStatus, tokens, loginErr := controller.LoginWithPassword(context.Background(), login)
	if loginErr != nil || loginStatus != http.StatusOK || tokens.Token == "" || tokens.TokenRefresh == "" {
		t.Fatalf("login after setup = %d, %#v, %v", loginStatus, tokens, loginErr)
	}
	if statusCode, err := controller.ResetPassword(context.Background(), dto.UserResetPassword{ResetToken: invitation.InvitationToken, NewPassword: "another-password"}); statusCode != http.StatusUnauthorized || !errors.Is(err, models.ErrInvalidPasswordResetToken) {
		t.Fatalf("reused invitation token = %d, %v", statusCode, err)
	}
}

func TestInvitationDuplicateEmailReusesIdentityWithoutDuplicateCredential(t *testing.T) {
	controller, storage := newInvitationController()
	storage.user = &models.User{Email: "existing@example.com", Name: "Existing", Validated: false}
	storage.user.ID = 584

	statusCode, first, err := controller.InviteWithPasswordSetup(context.Background(), dto.UserInvitation{Email: "existing@example.com", Name: "Ignored"})
	if err != nil || statusCode != http.StatusAccepted || !first.ExistingIdentity || first.PasswordConfigured || first.InvitationToken == "" || storage.user.Name != "Existing" {
		t.Fatalf("passwordless duplicate = %d, %#v, %v user:%#v", statusCode, first, err, storage.user)
	}
	firstToken := first.InvitationToken
	_, second, err := controller.InviteWithPasswordSetup(context.Background(), dto.UserInvitation{Email: "existing@example.com", Name: "Ignored again"})
	if err != nil || second.UserID != first.UserID || second.InvitationToken == firstToken {
		t.Fatalf("reissued invitation = %#v, %v", second, err)
	}

	storage.user.Validated = true
	storage.credential = &models.PasswordCredential{UserID: storage.user.ID, PasswordHash: "$argon2id$existing"}
	statusCode, existing, err := controller.InviteWithPasswordSetup(context.Background(), dto.UserInvitation{Email: "existing@example.com", Name: "Ignored"})
	if err != nil || statusCode != http.StatusOK || !existing.PasswordConfigured || existing.InvitationToken != "" {
		t.Fatalf("configured duplicate = %d, %#v, %v", statusCode, existing, err)
	}
}

func newInvitationController() (*controllerUser, *invitationLifecycleService) {
	storage := &invitationLifecycleService{}
	configuration := &models.Config{
		RandomStringValidation: "abcdef0123456789", RandomStringValidationRefresh: "abcdef0123456789",
		SizeRandomStringValidation: 16, SizeRandomStringValidationRefresh: 16,
		Issuer: "invitation-test", JWTKey: []byte("invitation-test-secret"), TokenExpirationTime: 300, TokenExpirationTimeRefresh: 600,
	}
	return &controllerUser{
		IUserService: storage, conf: configuration,
		log:       slog.New(slog.NewTextHandler(io.Discard, nil)),
		passwords: passwordService.NewManager(passwordService.Parameters{Memory: 8 * 1024, Iterations: 1, Parallelism: 1, SaltLength: 16, KeyLength: 32}),
	}, storage
}
