package controllers

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/BaukunstPatrimonio/user-go/server/dto"
	"github.com/BaukunstPatrimonio/user-go/server/models"
	passwordService "github.com/BaukunstPatrimonio/user-go/server/password"
	"github.com/BaukunstPatrimonio/user-go/server/passwordreset"
	"github.com/BaukunstPatrimonio/user-go/server/services"
	pb "github.com/BaukunstPatrimonio/user-go/server/user-pb"
	entModels "github.com/alvarotor/entitier-go/models"
)

const (
	resetOldFakePassword = "phase-four-old-password!"
	resetNewFakePassword = "phase-four-new-password!"
)

type passwordResetLifecycleService struct {
	services.IUserService
	mu             sync.Mutex
	user           *models.User
	credential     *models.PasswordCredential
	resetToken     *models.PasswordResetToken
	storeCount     int
	sessionUpdates int
	resetFailure   error
}

func (s *passwordResetLifecycleService) FindPasswordResetUser(_ context.Context, email string) (*models.User, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.user == nil || s.credential == nil || !strings.EqualFold(s.user.Email, email) {
		return nil, models.ErrPasswordResetUnavailable
	}
	copy := *s.user
	return &copy, nil
}

func (s *passwordResetLifecycleService) StorePasswordResetToken(_ context.Context, resetToken models.PasswordResetToken) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	resetToken.ID = 901
	copy := resetToken
	s.resetToken = &copy
	s.storeCount++
	return nil
}

func (s *passwordResetLifecycleService) ResetPasswordWithToken(_ context.Context, digest, passwordHash string, now time.Time) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.resetToken == nil || s.credential == nil || s.user == nil || s.resetToken.TokenDigest != digest || s.resetToken.UsedAt != nil || !s.resetToken.ExpiresAt.After(now) {
		return models.ErrInvalidPasswordResetToken
	}
	oldHash := s.credential.PasswordHash
	oldRefresh := s.user.CodeRefresh
	s.credential.PasswordHash = passwordHash
	if s.resetFailure != nil {
		s.credential.PasswordHash = oldHash
		s.user.CodeRefresh = oldRefresh
		return s.resetFailure
	}
	usedAt := now
	s.resetToken.UsedAt = &usedAt
	s.user.CodeRefresh = "OUT"
	return nil
}

func (s *passwordResetLifecycleService) GetByEmail(_ context.Context, email string) (*models.User, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.user == nil || s.user.Email != email {
		return nil, entModels.ErrNotFound
	}
	return s.user, nil
}

func (s *passwordResetLifecycleService) GetPasswordCredential(_ context.Context, userID uint) (*models.PasswordCredential, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.credential == nil || s.credential.UserID != userID {
		return nil, models.ErrCredentialNotFound
	}
	return s.credential, nil
}

func (s *passwordResetLifecycleService) GetByCodeRefresh(_ context.Context, codeRefresh string) (*models.User, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.user == nil || s.user.CodeRefresh != codeRefresh {
		return nil, models.ErrUserNotFound
	}
	return s.user, nil
}

func (s *passwordResetLifecycleService) UpdatePasswordCredentialHash(_ context.Context, userID uint, passwordHash string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.credential == nil || s.credential.UserID != userID {
		return models.ErrCredentialNotFound
	}
	s.credential.PasswordHash = passwordHash
	return nil
}

func (s *passwordResetLifecycleService) StartPasswordSession(_ context.Context, userID uint, device models.DeviceInfo, code string, codeExpire time.Time, codeRefresh string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.user == nil || s.user.ID != userID {
		return models.ErrUserNotFound
	}
	s.sessionUpdates++
	s.user.DeviceInfo = device
	s.user.Code = code
	s.user.CodeExpire = codeExpire
	s.user.CodeRefresh = codeRefresh
	return nil
}

func TestRequestPasswordResetStoresOnlyDigestAndReplacesPreviousToken(t *testing.T) {
	controller, service := newPasswordResetController(t)
	before := time.Now().UTC()

	statusCode, first, err := controller.RequestPasswordReset(context.Background(), dto.UserRequestPasswordReset{Email: "  RESET.USER@EXAMPLE.COM "})
	if err != nil || statusCode != http.StatusAccepted || first.ResetToken == "" {
		t.Fatalf("first RequestPasswordReset() = %d, %#v, %v", statusCode, first, err)
	}
	firstDigest, err := passwordreset.DigestToken(first.ResetToken)
	if err != nil {
		t.Fatalf("DigestToken(first) error = %v", err)
	}
	if service.resetToken == nil || service.resetToken.TokenDigest != firstDigest || service.resetToken.TokenDigest == first.ResetToken {
		t.Fatalf("stored reset = %#v, want digest only", service.resetToken)
	}
	if !first.ExpiresAt.Equal(service.resetToken.ExpiresAt) || first.ExpiresAt.Before(before.Add(29*time.Minute+59*time.Second)) || first.ExpiresAt.After(time.Now().UTC().Add(30*time.Minute+time.Second)) {
		t.Fatalf("reset expiry = %v, want approximately thirty minutes", first.ExpiresAt)
	}

	_, second, err := controller.RequestPasswordReset(context.Background(), dto.UserRequestPasswordReset{Email: "reset.user@example.com"})
	if err != nil || second.ResetToken == "" || second.ResetToken == first.ResetToken || service.storeCount != 2 {
		t.Fatalf("second RequestPasswordReset() = %#v, %v stores:%d", second, err, service.storeCount)
	}
	secondDigest, _ := passwordreset.DigestToken(second.ResetToken)
	if service.resetToken.TokenDigest != secondDigest || service.resetToken.TokenDigest == firstDigest {
		t.Fatalf("replacement digest = %q, want second token digest", service.resetToken.TokenDigest)
	}
	statusCode, err = controller.ResetPassword(context.Background(), dto.UserResetPassword{ResetToken: first.ResetToken, NewPassword: resetNewFakePassword})
	if statusCode != http.StatusUnauthorized || !errors.Is(err, models.ErrInvalidPasswordResetToken) {
		t.Fatalf("superseded token reset = %d, %v, want unauthorized", statusCode, err)
	}
}

func TestRequestPasswordResetIsGenericForUnknownAndPasswordlessAccounts(t *testing.T) {
	tests := []struct {
		name    string
		prepare func(*passwordResetLifecycleService)
	}{
		{name: "unknown", prepare: func(s *passwordResetLifecycleService) { s.user = nil; s.credential = nil }},
		{name: "passwordless", prepare: func(s *passwordResetLifecycleService) { s.credential = nil }},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			controller, service := newPasswordResetController(t)
			test.prepare(service)
			statusCode, result, err := controller.RequestPasswordReset(context.Background(), dto.UserRequestPasswordReset{Email: "reset.user@example.com"})
			if err != nil || statusCode != http.StatusAccepted || result.ResetToken != "" || !result.ExpiresAt.IsZero() || service.resetToken != nil {
				t.Fatalf("RequestPasswordReset() = %d, %#v, %v stored:%#v", statusCode, result, err, service.resetToken)
			}
		})
	}
}

func TestResetPasswordRejectsMalformedTokenAndRegistrationPolicyViolation(t *testing.T) {
	tests := []struct {
		name       string
		reset      dto.UserResetPassword
		statusCode int
		err        error
	}{
		{name: "malformed token", reset: dto.UserResetPassword{ResetToken: "not-a-generated-token", NewPassword: resetNewFakePassword}, statusCode: http.StatusUnauthorized, err: models.ErrInvalidPasswordResetToken},
		{name: "empty password", reset: dto.UserResetPassword{ResetToken: "not-used", NewPassword: ""}, statusCode: http.StatusBadRequest, err: models.ErrInvalidPassword},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			controller, service := newPasswordResetController(t)
			oldHash, oldRefresh := service.credential.PasswordHash, service.user.CodeRefresh
			statusCode, err := controller.ResetPassword(context.Background(), test.reset)
			if statusCode != test.statusCode || !errors.Is(err, test.err) {
				t.Fatalf("ResetPassword() = %d, %v, want %d/%v", statusCode, err, test.statusCode, test.err)
			}
			if service.credential.PasswordHash != oldHash || service.user.CodeRefresh != oldRefresh || service.resetToken != nil {
				t.Fatal("invalid reset changed persistence")
			}
		})
	}
}

func TestPasswordResetRevokesRefreshAndChangesLoginPassword(t *testing.T) {
	controller, service := newPasswordResetController(t)
	oldRefresh := service.user.CodeRefresh
	device := authRegressionDevice()
	oldTokens, err := controller.issueTokenPair(service.user, device, oldRefresh)
	if err != nil {
		t.Fatalf("issueTokenPair() error = %v", err)
	}
	_, request, err := controller.RequestPasswordReset(context.Background(), dto.UserRequestPasswordReset{Email: service.user.Email})
	if err != nil {
		t.Fatalf("RequestPasswordReset() error = %v", err)
	}
	statusCode, err := controller.ResetPassword(context.Background(), dto.UserResetPassword{ResetToken: request.ResetToken, NewPassword: resetNewFakePassword})
	if err != nil || statusCode != http.StatusOK {
		t.Fatalf("ResetPassword() = %d, %v", statusCode, err)
	}
	if service.resetToken.UsedAt == nil || service.user.CodeRefresh != "OUT" || service.user.CodeRefresh == oldRefresh || !strings.HasPrefix(service.credential.PasswordHash, "$argon2id$") {
		t.Fatalf("reset state = token:%#v refresh:%q hash:%q", service.resetToken, service.user.CodeRefresh, service.credential.PasswordHash)
	}
	oldValid, _ := controller.passwords.VerifyPassword(resetOldFakePassword, service.credential.PasswordHash)
	newValid, verifyErr := controller.passwords.VerifyPassword(resetNewFakePassword, service.credential.PasswordHash)
	if oldValid || verifyErr != nil || !newValid {
		t.Fatalf("reset hash verification = old:%v new:%v error:%v", oldValid, newValid, verifyErr)
	}
	refreshStatus, refreshed, refreshErr := controller.Refresh(context.Background(), oldTokens.TokenRefresh, &pb.UserTokenRequest{
		Browser: device.Browser, BrowserVersion: device.BrowserVersion,
		OperatingSystem: device.OperatingSystem, OperatingSystemVersion: device.OperatingSystemVersion,
		Cpu: device.Cpu, Language: device.Language, Timezone: device.Timezone, CookiesEnabled: device.CookiesEnabled,
	})
	if refreshStatus != http.StatusNotFound || !errors.Is(refreshErr, models.ErrInvalidCode) || refreshed.Token != "" {
		t.Fatalf("old refresh after reset = %d, %#v, %v, want revoked", refreshStatus, refreshed, refreshErr)
	}
	accessUser, accessErr := controller.TokenToUser(
		context.Background(), oldTokens.Token,
		device.Browser, device.BrowserVersion, device.OperatingSystem, device.OperatingSystemVersion,
		device.Cpu, device.Language, device.Timezone, device.CookiesEnabled,
	)
	if accessErr != nil || accessUser.ID != service.user.ID {
		t.Fatalf("existing access token after reset = %#v, %v, want current stateless-access limitation", accessUser, accessErr)
	}

	login := dto.UserLoginWithPassword{Email: service.user.Email, Password: resetOldFakePassword, DeviceInfo: device}
	loginStatus, tokens, err := controller.LoginWithPassword(context.Background(), login)
	if loginStatus != http.StatusUnauthorized || !errors.Is(err, models.ErrInvalidCredentials) || tokens.Token != "" {
		t.Fatalf("old-password LoginWithPassword() = %d, %#v, %v", loginStatus, tokens, err)
	}
	login.Password = resetNewFakePassword
	loginStatus, tokens, err = controller.LoginWithPassword(context.Background(), login)
	if err != nil || loginStatus != http.StatusOK || tokens.Token == "" || tokens.TokenRefresh == "" || service.sessionUpdates != 1 {
		t.Fatalf("new-password LoginWithPassword() = %d, %#v, %v sessions:%d", loginStatus, tokens, err, service.sessionUpdates)
	}
}

func TestResetPasswordRejectsExpiredAndUsedTokensWithoutChangingState(t *testing.T) {
	tests := []struct {
		name    string
		prepare func(*models.PasswordResetToken)
	}{
		{name: "expired", prepare: func(token *models.PasswordResetToken) { token.ExpiresAt = time.Now().UTC().Add(-time.Minute) }},
		{name: "used", prepare: func(token *models.PasswordResetToken) { used := time.Now().UTC(); token.UsedAt = &used }},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			controller, service := newPasswordResetController(t)
			_, request, err := controller.RequestPasswordReset(context.Background(), dto.UserRequestPasswordReset{Email: service.user.Email})
			if err != nil {
				t.Fatalf("RequestPasswordReset() error = %v", err)
			}
			test.prepare(service.resetToken)
			oldHash, oldRefresh := service.credential.PasswordHash, service.user.CodeRefresh
			statusCode, err := controller.ResetPassword(context.Background(), dto.UserResetPassword{ResetToken: request.ResetToken, NewPassword: resetNewFakePassword})
			if statusCode != http.StatusUnauthorized || !errors.Is(err, models.ErrInvalidPasswordResetToken) {
				t.Fatalf("ResetPassword() = %d, %v, want unauthorized", statusCode, err)
			}
			if service.credential.PasswordHash != oldHash || service.user.CodeRefresh != oldRefresh {
				t.Fatalf("failed reset changed hash/session: %q/%q", service.credential.PasswordHash, service.user.CodeRefresh)
			}
		})
	}
}

func TestResetPasswordTokenCannotBeReused(t *testing.T) {
	controller, service := newPasswordResetController(t)
	_, request, _ := controller.RequestPasswordReset(context.Background(), dto.UserRequestPasswordReset{Email: service.user.Email})
	if _, err := controller.ResetPassword(context.Background(), dto.UserResetPassword{ResetToken: request.ResetToken, NewPassword: resetNewFakePassword}); err != nil {
		t.Fatalf("first ResetPassword() error = %v", err)
	}
	hashAfterFirst, refreshAfterFirst, usedAfterFirst := service.credential.PasswordHash, service.user.CodeRefresh, *service.resetToken.UsedAt
	statusCode, err := controller.ResetPassword(context.Background(), dto.UserResetPassword{ResetToken: request.ResetToken, NewPassword: "another-fake-password!"})
	if statusCode != http.StatusUnauthorized || !errors.Is(err, models.ErrInvalidPasswordResetToken) {
		t.Fatalf("second ResetPassword() = %d, %v, want unauthorized", statusCode, err)
	}
	if service.credential.PasswordHash != hashAfterFirst || service.user.CodeRefresh != refreshAfterFirst || !service.resetToken.UsedAt.Equal(usedAfterFirst) {
		t.Fatal("token reuse changed password, session, or used timestamp")
	}
}

func TestConcurrentResetPasswordAllowsExactlyOneSuccess(t *testing.T) {
	controller, service := newPasswordResetController(t)
	_, request, _ := controller.RequestPasswordReset(context.Background(), dto.UserRequestPasswordReset{Email: service.user.Email})
	var successes atomic.Int32
	var rejected atomic.Int32
	var wait sync.WaitGroup
	start := make(chan struct{})
	for index := 0; index < 2; index++ {
		wait.Add(1)
		go func() {
			defer wait.Done()
			<-start
			statusCode, err := controller.ResetPassword(context.Background(), dto.UserResetPassword{ResetToken: request.ResetToken, NewPassword: resetNewFakePassword})
			switch {
			case err == nil && statusCode == http.StatusOK:
				successes.Add(1)
			case errors.Is(err, models.ErrInvalidPasswordResetToken) && statusCode == http.StatusUnauthorized:
				rejected.Add(1)
			}
		}()
	}
	close(start)
	wait.Wait()
	if successes.Load() != 1 || rejected.Load() != 1 || service.resetToken.UsedAt == nil {
		t.Fatalf("concurrent resets = successes:%d rejected:%d token:%#v", successes.Load(), rejected.Load(), service.resetToken)
	}
}

func TestResetPasswordTransactionFailureRollsBackPasswordAndSession(t *testing.T) {
	controller, service := newPasswordResetController(t)
	_, request, _ := controller.RequestPasswordReset(context.Background(), dto.UserRequestPasswordReset{Email: service.user.Email})
	oldHash, oldRefresh := service.credential.PasswordHash, service.user.CodeRefresh
	service.resetFailure = errors.New("mark token used failed")

	statusCode, err := controller.ResetPassword(context.Background(), dto.UserResetPassword{ResetToken: request.ResetToken, NewPassword: resetNewFakePassword})
	if statusCode != http.StatusInternalServerError || err == nil {
		t.Fatalf("ResetPassword() = %d, %v, want internal failure", statusCode, err)
	}
	if service.credential.PasswordHash != oldHash || service.user.CodeRefresh != oldRefresh || service.resetToken.UsedAt != nil {
		t.Fatalf("failed transaction left partial state: hash:%q refresh:%q token:%#v", service.credential.PasswordHash, service.user.CodeRefresh, service.resetToken)
	}
}

func newPasswordResetController(t *testing.T) (*controllerUser, *passwordResetLifecycleService) {
	t.Helper()
	passwords := passwordService.NewManager(passwordService.Parameters{Memory: 8 * 1024, Iterations: 1, Parallelism: 1, SaltLength: 16, KeyLength: 32})
	hash, err := passwords.HashPassword(resetOldFakePassword)
	if err != nil {
		t.Fatalf("HashPassword() error = %v", err)
	}
	user := authRegressionUser()
	user.Email = "reset.user@example.com"
	user.Validated = true
	service := &passwordResetLifecycleService{
		user:       user,
		credential: &models.PasswordCredential{UserID: user.ID, PasswordHash: hash},
	}
	conf := &models.Config{
		RandomStringValidation:            "abcdef0123456789",
		RandomStringValidationRefresh:     "abcdef0123456789",
		SizeRandomStringValidation:        16,
		SizeRandomStringValidationRefresh: 8,
		Issuer:                            "password-reset-test",
		JWTKey:                            []byte("password-reset-test-secret"),
		TokenExpirationTime:               300,
		TokenExpirationTimeRefresh:        600,
	}
	return &controllerUser{
		IUserService: service,
		log:          slog.New(slog.NewTextHandler(io.Discard, nil)),
		conf:         conf,
		passwords:    passwords,
	}, service
}
