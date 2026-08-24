package server

import (
	"bytes"
	"context"
	"encoding/json"
	"log/slog"
	"strings"
	"testing"

	"github.com/BaukunstPatrimonio/user-go/server/models"
	pb "github.com/BaukunstPatrimonio/user-go/server/user-pb"
	"google.golang.org/grpc"
	"google.golang.org/grpc/metadata"
)

func TestApplicationAndRPCLogsShareRequestIDWithoutSecrets(t *testing.T) {
	var logs bytes.Buffer
	logger := slog.New(slog.NewJSONHandler(&logs, nil))
	controller := &passwordLoginControllerStub{err: models.ErrAccountNotValidated}
	server := NewServer(controller, logger)
	interceptor := UnaryLoggingInterceptor(logger)
	ctx := metadata.NewIncomingContext(context.Background(), metadata.Pairs(RequestIDMetadataKey, "shared-request-123"))
	request := validPasswordLoginRequest()
	request.Password = "password-secret"

	_, _ = interceptor(ctx, request, &grpc.UnaryServerInfo{FullMethod: "/user.User/LoginWithPassword"}, func(ctx context.Context, request any) (any, error) {
		return server.LoginWithPassword(ctx, request.(*pb.UserLoginWithPasswordRequest))
	})

	entries := decodeApplicationLogs(t, logs.Bytes())
	assertApplicationLogFields(t, entries, "application_operation", map[string]any{
		"request_id":     "shared-request-123",
		"event":          "login",
		"outcome":        "rejected",
		"error_category": "account_not_validated",
	})
	assertApplicationLogFields(t, entries, "grpc_request_completed", map[string]any{
		"request_id":  "shared-request-123",
		"grpc_method": "/user.User/LoginWithPassword",
		"grpc_code":   "FailedPrecondition",
	})
	output := logs.String()
	for _, secret := range []string{"password-secret", request.GetEmail(), "authorization", "refresh_token"} {
		if strings.Contains(strings.ToLower(output), strings.ToLower(secret)) {
			t.Fatalf("logs exposed %q: %s", secret, output)
		}
	}
}

func decodeApplicationLogs(t *testing.T, contents []byte) []map[string]any {
	t.Helper()
	decoder := json.NewDecoder(bytes.NewReader(contents))
	var entries []map[string]any
	for decoder.More() {
		var entry map[string]any
		if err := decoder.Decode(&entry); err != nil {
			t.Fatalf("decode log: %v", err)
		}
		entries = append(entries, entry)
	}
	return entries
}

func assertApplicationLogFields(t *testing.T, entries []map[string]any, message string, fields map[string]any) {
	t.Helper()
	for _, entry := range entries {
		if entry["msg"] != message {
			continue
		}
		for key, want := range fields {
			if got := entry[key]; got != want {
				t.Fatalf("%s field %s = %#v, want %#v; entry=%#v", message, key, got, want, entry)
			}
		}
		return
	}
	t.Fatalf("log message %q not found in %#v", message, entries)
}
