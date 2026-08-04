package controllers

import (
	"bytes"
	"context"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/BaukunstPatrimonio/user-go/server/dto"
	"github.com/BaukunstPatrimonio/user-go/server/models"
	"github.com/BaukunstPatrimonio/user-go/server/services"
	pb "github.com/BaukunstPatrimonio/user-go/server/user-pb"
	"github.com/golang-jwt/jwt/v5"
	"gorm.io/gorm"
)

const oldRefreshCode = "oooooooo"

type refreshTestService struct {
	services.IUserService
	user                *models.User
	getByCodeCalls      int
	refreshUpdateCalls  int
	refreshUpdateErr    error
	lastRefreshDevice   models.DeviceInfo
	lastRefreshCode     string
	beforeRefreshUpdate func()
}

func (s *refreshTestService) GetByCodeRefresh(_ context.Context, code string) (*models.User, error) {
	if s.user == nil || s.user.CodeRefresh != code {
		return nil, models.ErrUserNotFound
	}
	return s.user, nil
}

func (s *refreshTestService) GetByCode(_ context.Context, _ string) (*models.User, error) {
	s.getByCodeCalls++
	return s.user, nil
}

func (s *refreshTestService) UpdateRefreshSession(_ context.Context, _ uint, device models.DeviceInfo, oldCodeRefresh, newCodeRefresh string) error {
	s.refreshUpdateCalls++
	s.lastRefreshDevice = device
	s.lastRefreshCode = newCodeRefresh
	if s.beforeRefreshUpdate != nil {
		s.beforeRefreshUpdate()
		s.beforeRefreshUpdate = nil
	}
	if s.user.CodeRefresh != oldCodeRefresh {
		return models.ErrInvalidCode
	}
	if s.refreshUpdateErr != nil {
		return s.refreshUpdateErr
	}
	s.user.DeviceInfo = device
	s.user.CodeRefresh = newCodeRefresh
	return nil
}

func TestRefreshMatchingDeviceIgnoresExpiredLoginCode(t *testing.T) {
	device := storedRefreshDevice()
	controller, svc, conf := newRefreshTestController(device, slog.New(slog.NewTextHandler(io.Discard, nil)))
	svc.user.Code = "expired-login-code"
	svc.user.CodeExpire = time.Now().UTC().Add(-time.Hour)

	statusCode, tokens, err := controller.Refresh(
		context.Background(),
		signedRefreshToken(t, conf, oldRefreshCode),
		refreshRequest(device),
	)
	if err != nil {
		t.Fatalf("Refresh() error = %v", err)
	}
	if statusCode != http.StatusOK {
		t.Fatalf("Refresh() status = %d, want %d", statusCode, http.StatusOK)
	}
	if tokens.Token == "" || tokens.TokenRefresh == "" {
		t.Fatalf("Refresh() tokens = %#v, want both access and refresh tokens", tokens)
	}
	if svc.getByCodeCalls != 0 {
		t.Fatalf("GetByCode() calls = %d, want 0", svc.getByCodeCalls)
	}
	if svc.refreshUpdateCalls != 1 {
		t.Fatalf("UpdateRefreshSession() calls = %d, want 1", svc.refreshUpdateCalls)
	}
	if svc.lastRefreshDevice != device || svc.lastRefreshCode != "nnnnnnnn" {
		t.Fatalf("atomic update = %#v/%q, want %#v/%q", svc.lastRefreshDevice, svc.lastRefreshCode, device, "nnnnnnnn")
	}
	assertReturnedDevice(t, tokens, conf.JWTKey, device)
}

func TestRefreshOldTokenCannotBeUsedTwice(t *testing.T) {
	device := storedRefreshDevice()
	controller, svc, conf := newRefreshTestController(device, slog.New(slog.NewTextHandler(io.Discard, nil)))
	oldToken := signedRefreshToken(t, conf, oldRefreshCode)

	statusCode, firstTokens, err := controller.Refresh(context.Background(), oldToken, refreshRequest(device))
	if err != nil || statusCode != http.StatusOK {
		t.Fatalf("first Refresh() = status %d, error %v", statusCode, err)
	}
	if firstTokens.Token == "" || firstTokens.TokenRefresh == "" {
		t.Fatalf("first Refresh() tokens = %#v, want both tokens", firstTokens)
	}
	if svc.user.CodeRefresh != "nnnnnnnn" {
		t.Fatalf("first Refresh() code_refresh = %q, want rotated", svc.user.CodeRefresh)
	}

	statusCode, secondTokens, err := controller.Refresh(context.Background(), oldToken, refreshRequest(device))
	if !errors.Is(err, models.ErrInvalidCode) {
		t.Fatalf("second Refresh() error = %v, want %v", err, models.ErrInvalidCode)
	}
	if statusCode != http.StatusNotFound {
		t.Fatalf("second Refresh() status = %d, want %d", statusCode, http.StatusNotFound)
	}
	if secondTokens.Token != "" || secondTokens.TokenRefresh != "" {
		t.Fatalf("second Refresh() tokens = %#v, want none", secondTokens)
	}
	if svc.user.CodeRefresh != "nnnnnnnn" || svc.refreshUpdateCalls != 1 {
		t.Fatalf("second Refresh() modified rotated session: code=%q updates=%d", svc.user.CodeRefresh, svc.refreshUpdateCalls)
	}
}

func TestRefreshConcurrentRotationCannotOverwriteNewSession(t *testing.T) {
	stored := storedRefreshDevice()
	incoming := stored
	incoming.Language = "es-ES"
	controller, svc, conf := newRefreshTestController(stored, slog.New(slog.NewTextHandler(io.Discard, nil)))
	svc.beforeRefreshUpdate = func() {
		svc.user.CodeRefresh = "concurrent-new-code"
	}

	statusCode, tokens, err := controller.Refresh(
		context.Background(),
		signedRefreshToken(t, conf, oldRefreshCode),
		refreshRequest(incoming),
	)
	if !errors.Is(err, models.ErrInvalidCode) {
		t.Fatalf("Refresh() error = %v, want %v", err, models.ErrInvalidCode)
	}
	if statusCode != http.StatusBadRequest {
		t.Fatalf("Refresh() status = %d, want %d", statusCode, http.StatusBadRequest)
	}
	if tokens.Token != "" || tokens.TokenRefresh != "" {
		t.Fatalf("Refresh() tokens = %#v, want none", tokens)
	}
	if svc.user.CodeRefresh != "concurrent-new-code" {
		t.Fatalf("stored code_refresh = %q, want concurrent value preserved", svc.user.CodeRefresh)
	}
	if svc.user.DeviceInfo != stored {
		t.Fatalf("stored device = %#v, want unchanged %#v", svc.user.DeviceInfo, stored)
	}
}

func TestRefreshMissingDeviceFieldsUseStoredFallbacks(t *testing.T) {
	stored := storedRefreshDevice()
	incoming := models.DeviceInfo{
		Browser:                "  ",
		BrowserVersion:         "\t",
		OperatingSystem:        " ",
		OperatingSystemVersion: "\r\n",
		Cpu:                    " ",
		Language:               "\t",
		Timezone:               " ",
		CookiesEnabled:         false,
	}
	var logs bytes.Buffer
	controller, svc, conf := newRefreshTestController(stored, slog.New(slog.NewTextHandler(&logs, nil)))

	statusCode, tokens, err := controller.Refresh(
		context.Background(),
		signedRefreshToken(t, conf, oldRefreshCode),
		refreshRequest(incoming),
	)
	if err != nil {
		t.Fatalf("Refresh() error = %v", err)
	}
	if statusCode != http.StatusOK {
		t.Fatalf("Refresh() status = %d, want %d", statusCode, http.StatusOK)
	}
	if svc.refreshUpdateCalls != 1 {
		t.Fatalf("UpdateRefreshSession() calls = %d, want 1", svc.refreshUpdateCalls)
	}
	if svc.user.DeviceInfo != stored {
		t.Fatalf("stored device = %#v, want unchanged %#v", svc.user.DeviceInfo, stored)
	}
	if !svc.user.CookiesEnabled {
		t.Fatal("stored cookies_enabled = false, want preserved true")
	}
	for _, field := range []string{"browser", "browser_version", "operating_system", "operating_system_version", "cpu", "language", "timezone"} {
		if !strings.Contains(logs.String(), "field="+field) {
			t.Fatalf("refresh log = %q, want missing-field entry for %q", logs.String(), field)
		}
	}
	assertReturnedDevice(t, tokens, conf.JWTKey, stored)
}

func TestRefreshSoftDriftUpdatesApprovedFieldsAndTokenClaims(t *testing.T) {
	stored := storedRefreshDevice()
	incoming := models.DeviceInfo{
		Browser:                " firefox ",
		BrowserVersion:         "129",
		OperatingSystem:        "LINUX",
		OperatingSystemVersion: "6.11",
		Cpu:                    "arm64",
		Language:               "es-ES",
		Timezone:               "Europe/Lisbon",
		CookiesEnabled:         false,
	}
	controller, svc, conf := newRefreshTestController(stored, slog.New(slog.NewTextHandler(io.Discard, nil)))

	statusCode, tokens, err := controller.Refresh(
		context.Background(),
		signedRefreshToken(t, conf, oldRefreshCode),
		refreshRequest(incoming),
	)
	if err != nil {
		t.Fatalf("Refresh() error = %v", err)
	}
	if statusCode != http.StatusOK {
		t.Fatalf("Refresh() status = %d, want %d", statusCode, http.StatusOK)
	}

	wantAccepted := incoming
	wantAccepted.Browser = "firefox"
	wantAccepted.OperatingSystem = "LINUX"
	wantAccepted.CookiesEnabled = stored.CookiesEnabled
	wantStored := wantAccepted
	wantStored.Browser = stored.Browser
	wantStored.OperatingSystem = stored.OperatingSystem
	if got := svc.user.DeviceInfo; got != wantStored {
		t.Fatalf("stored device = %#v, want %#v", got, wantStored)
	}
	if svc.refreshUpdateCalls != 1 {
		t.Fatalf("UpdateRefreshSession() calls = %d, want 1", svc.refreshUpdateCalls)
	}
	assertReturnedDevice(t, tokens, conf.JWTKey, wantAccepted)
}

func TestRefreshOneHardTierMismatchIsLoggedAndTolerated(t *testing.T) {
	stored := storedRefreshDevice()
	incoming := models.DeviceInfo{
		Browser:                "Chrome",
		BrowserVersion:         "130",
		OperatingSystem:        " linux ",
		OperatingSystemVersion: "6.12",
		Cpu:                    "arm64",
		Language:               "es-ES",
		Timezone:               "UTC",
		CookiesEnabled:         false,
	}
	var logs bytes.Buffer
	logger := slog.New(slog.NewTextHandler(&logs, nil))
	controller, svc, conf := newRefreshTestController(stored, logger)

	statusCode, tokens, err := controller.Refresh(
		context.Background(),
		signedRefreshToken(t, conf, oldRefreshCode),
		refreshRequest(incoming),
	)
	if err != nil {
		t.Fatalf("Refresh() error = %v", err)
	}
	if statusCode != http.StatusOK {
		t.Fatalf("Refresh() status = %d, want %d", statusCode, http.StatusOK)
	}
	if !strings.Contains(logs.String(), "refresh device medium risk") {
		t.Fatalf("refresh log = %q, want medium-risk entry", logs.String())
	}
	if svc.user.Browser != stored.Browser || svc.user.BrowserVersion != stored.BrowserVersion {
		t.Fatalf("browser baseline = %q/%q, want unchanged %q/%q", svc.user.Browser, svc.user.BrowserVersion, stored.Browser, stored.BrowserVersion)
	}
	if svc.user.OperatingSystemVersion != incoming.OperatingSystemVersion {
		t.Fatalf("OS version = %q, want %q", svc.user.OperatingSystemVersion, incoming.OperatingSystemVersion)
	}
	if svc.user.BrowserVersion != stored.BrowserVersion {
		t.Fatalf("browser version = %q, want unchanged %q", svc.user.BrowserVersion, stored.BrowserVersion)
	}
	wantAccepted := incoming
	wantAccepted.OperatingSystem = "linux"
	wantAccepted.CookiesEnabled = stored.CookiesEnabled
	assertReturnedDevice(t, tokens, conf.JWTKey, wantAccepted)
}

func TestRefreshAdoptsMissingStoredBrowserAndOperatingSystemBaselines(t *testing.T) {
	stored := storedRefreshDevice()
	stored.Browser = ""
	stored.OperatingSystem = "  "
	incoming := storedRefreshDevice()
	incoming.Browser = " Chrome "
	incoming.OperatingSystem = " Windows "
	controller, svc, conf := newRefreshTestController(stored, slog.New(slog.NewTextHandler(io.Discard, nil)))

	statusCode, tokens, err := controller.Refresh(
		context.Background(),
		signedRefreshToken(t, conf, oldRefreshCode),
		refreshRequest(incoming),
	)
	if err != nil {
		t.Fatalf("Refresh() error = %v", err)
	}
	if statusCode != http.StatusOK {
		t.Fatalf("Refresh() status = %d, want %d", statusCode, http.StatusOK)
	}
	if svc.refreshUpdateCalls != 1 {
		t.Fatalf("UpdateRefreshSession() calls = %d, want 1", svc.refreshUpdateCalls)
	}
	wantAccepted := incoming
	wantAccepted.Browser = "Chrome"
	wantAccepted.OperatingSystem = "Windows"
	wantAccepted.CookiesEnabled = stored.CookiesEnabled
	if svc.user.DeviceInfo != wantAccepted {
		t.Fatalf("stored device = %#v, want adopted baselines %#v", svc.user.DeviceInfo, wantAccepted)
	}
	assertReturnedDevice(t, tokens, conf.JWTKey, wantAccepted)
}

func TestRefreshHardDeviceMismatchRevokesSessionWithoutSigning(t *testing.T) {
	stored := storedRefreshDevice()
	incoming := stored
	incoming.Browser = "Chrome"
	incoming.OperatingSystem = "Windows"
	controller, svc, conf := newRefreshTestController(stored, slog.New(slog.NewTextHandler(io.Discard, nil)))
	signingCalls := 0
	signer := func(token *jwt.Token, key []byte) (string, error) {
		signingCalls++
		return signRefreshToken(token, key)
	}

	statusCode, tokens, err := controller.refresh(
		context.Background(),
		signedRefreshToken(t, conf, oldRefreshCode),
		refreshRequest(incoming),
		signer,
	)
	if !errors.Is(err, models.ErrSessionDeviceMismatch) {
		t.Fatalf("Refresh() error = %v, want %v", err, models.ErrSessionDeviceMismatch)
	}
	if statusCode != http.StatusUnauthorized {
		t.Fatalf("Refresh() status = %d, want %d", statusCode, http.StatusUnauthorized)
	}
	if tokens.Token != "" || tokens.TokenRefresh != "" {
		t.Fatalf("Refresh() tokens = %#v, want none", tokens)
	}
	if signingCalls != 0 {
		t.Fatalf("token signing calls = %d, want 0", signingCalls)
	}
	if svc.refreshUpdateCalls != 1 {
		t.Fatalf("UpdateRefreshSession() calls = %d, want 1 revocation", svc.refreshUpdateCalls)
	}
	if svc.user.CodeRefresh != "" {
		t.Fatalf("stored code_refresh = %q, want revoked", svc.user.CodeRefresh)
	}
	if svc.user.DeviceInfo != stored {
		t.Fatalf("stored device changed on hard mismatch: %#v", svc.user.DeviceInfo)
	}
}

func TestRefreshSigningFailureChangesNeitherDeviceNorRefreshCode(t *testing.T) {
	stored := storedRefreshDevice()
	incoming := stored
	incoming.BrowserVersion = "129"
	incoming.Language = "es-ES"
	incoming.CookiesEnabled = false
	controller, svc, conf := newRefreshTestController(stored, slog.New(slog.NewTextHandler(io.Discard, nil)))
	signingErr := errors.New("refresh token signing failed")
	signingCalls := 0
	signer := func(token *jwt.Token, key []byte) (string, error) {
		signingCalls++
		if signingCalls == 2 {
			return "", signingErr
		}
		return signRefreshToken(token, key)
	}

	statusCode, tokens, err := controller.refresh(
		context.Background(),
		signedRefreshToken(t, conf, oldRefreshCode),
		refreshRequest(incoming),
		signer,
	)
	if !errors.Is(err, signingErr) {
		t.Fatalf("Refresh() error = %v, want %v", err, signingErr)
	}
	if statusCode != http.StatusInternalServerError {
		t.Fatalf("Refresh() status = %d, want %d", statusCode, http.StatusInternalServerError)
	}
	if tokens.Token != "" || tokens.TokenRefresh != "" {
		t.Fatalf("Refresh() tokens = %#v, want none", tokens)
	}
	if signingCalls != 2 {
		t.Fatalf("token signing calls = %d, want 2", signingCalls)
	}
	if svc.refreshUpdateCalls != 0 {
		t.Fatalf("UpdateRefreshSession() calls = %d, want 0", svc.refreshUpdateCalls)
	}
	if svc.user.CodeRefresh != oldRefreshCode || svc.user.DeviceInfo != stored {
		t.Fatalf("stored session changed after signing failure: %#v", svc.user)
	}
}

func TestRefreshAtomicUpdateErrorLeavesDeviceAndRefreshCodeUnchanged(t *testing.T) {
	stored := storedRefreshDevice()
	incoming := stored
	incoming.BrowserVersion = "129"
	incoming.OperatingSystemVersion = "6.11"
	incoming.Cpu = "arm64"
	incoming.Language = "es-ES"
	incoming.Timezone = "UTC"
	controller, svc, conf := newRefreshTestController(stored, slog.New(slog.NewTextHandler(io.Discard, nil)))
	databaseErr := errors.New("database update failed")
	svc.refreshUpdateErr = databaseErr

	statusCode, tokens, err := controller.Refresh(
		context.Background(),
		signedRefreshToken(t, conf, oldRefreshCode),
		refreshRequest(incoming),
	)
	if !errors.Is(err, databaseErr) {
		t.Fatalf("Refresh() error = %v, want %v", err, databaseErr)
	}
	if statusCode != http.StatusInternalServerError {
		t.Fatalf("Refresh() status = %d, want %d", statusCode, http.StatusInternalServerError)
	}
	if tokens.Token != "" || tokens.TokenRefresh != "" {
		t.Fatalf("Refresh() tokens = %#v, want none", tokens)
	}
	if svc.refreshUpdateCalls != 1 {
		t.Fatalf("UpdateRefreshSession() calls = %d, want 1", svc.refreshUpdateCalls)
	}
	if svc.user.DeviceInfo != stored || svc.user.CodeRefresh != oldRefreshCode {
		t.Fatalf("stored session changed after transaction error: %#v", svc.user)
	}
}

func newRefreshTestController(device models.DeviceInfo, logger *slog.Logger) (*controllerUser, *refreshTestService, *models.Config) {
	user := &models.User{
		Model:       gorm.Model{ID: 42},
		DeviceInfo:  device,
		Email:       "person@example.com",
		CodeRefresh: oldRefreshCode,
	}
	svc := &refreshTestService{user: user}
	conf := refreshTestConfig()
	return &controllerUser{IUserService: svc, log: logger, conf: conf}, svc, conf
}

func storedRefreshDevice() models.DeviceInfo {
	return models.DeviceInfo{
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

func refreshRequest(device models.DeviceInfo) *pb.UserTokenRequest {
	return &pb.UserTokenRequest{
		Browser:                device.Browser,
		BrowserVersion:         device.BrowserVersion,
		OperatingSystem:        device.OperatingSystem,
		OperatingSystemVersion: device.OperatingSystemVersion,
		Cpu:                    device.Cpu,
		Language:               device.Language,
		Timezone:               device.Timezone,
		CookiesEnabled:         device.CookiesEnabled,
	}
}

func assertReturnedDevice(t *testing.T, tokens *models.Token, key []byte, want models.DeviceInfo) {
	t.Helper()
	accessClaims := &dto.ClaimsResponse{}
	parseRefreshTestToken(t, tokens.Token, key, accessClaims)
	if accessClaims.DeviceInfo != want {
		t.Fatalf("access token device = %#v, want %#v", accessClaims.DeviceInfo, want)
	}
	refreshClaims := &dto.ClaimsRefreshResponse{}
	parseRefreshTestToken(t, tokens.TokenRefresh, key, refreshClaims)
	if refreshClaims.DeviceInfo != want {
		t.Fatalf("refresh token device = %#v, want %#v", refreshClaims.DeviceInfo, want)
	}
	if refreshClaims.CodeRefresh != "nnnnnnnn" {
		t.Fatalf("refresh token code = %q, want %q", refreshClaims.CodeRefresh, "nnnnnnnn")
	}
}

func refreshTestConfig() *models.Config {
	return &models.Config{
		RandomStringValidation:            "n",
		RandomStringValidationRefresh:     "n",
		SizeRandomStringValidationRefresh: 8,
		Issuer:                            "refresh-test",
		JWTKey:                            []byte("refresh-test-secret"),
		TokenExpirationTime:               300,
		TokenExpirationTimeRefresh:        600,
	}
}

func signedRefreshToken(t *testing.T, conf *models.Config, codeRefresh string) string {
	t.Helper()
	claims := &dto.ClaimsRefreshResponse{
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(time.Now().UTC().Add(time.Hour)),
			Issuer:    conf.Issuer,
		},
		CodeRefresh: codeRefresh,
	}
	token, err := jwt.NewWithClaims(jwt.SigningMethodHS256, claims).SignedString(conf.JWTKey)
	if err != nil {
		t.Fatalf("sign refresh token: %v", err)
	}
	return token
}

func parseRefreshTestToken(t *testing.T, tokenString string, key []byte, claims jwt.Claims) {
	t.Helper()
	token, err := jwt.ParseWithClaims(tokenString, claims, func(_ *jwt.Token) (interface{}, error) {
		return key, nil
	})
	if err != nil {
		t.Fatalf("parse returned token: %v", err)
	}
	if !token.Valid {
		t.Fatal("returned token is invalid")
	}
}
