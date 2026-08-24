package server

import (
	"bytes"
	"context"
	"errors"
	"log/slog"
	"strings"
	"testing"

	pb "github.com/BaukunstPatrimonio/user-go/server/user-pb"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
)

func TestUnaryLoggingInterceptorLogsMethodStatusAndPropagatedRequestID(t *testing.T) {
	var logs bytes.Buffer
	interceptor := UnaryLoggingInterceptor(slog.New(slog.NewJSONHandler(&logs, nil)))
	ctx := metadata.NewIncomingContext(context.Background(), metadata.Pairs(RequestIDMetadataKey, "integration-123"))
	wantResponse := &pb.UserTokenResponse{Status: 200}
	response, err := interceptor(ctx, &pb.UserLoginWithPasswordRequest{Password: "credential-secret"}, &grpc.UnaryServerInfo{FullMethod: "/user.User/LoginWithPassword"}, func(ctx context.Context, _ any) (any, error) {
		if RequestIDFromContext(ctx) != "integration-123" {
			t.Fatalf("request ID was not attached to RPC context")
		}
		return wantResponse, nil
	})
	if err != nil || response != wantResponse {
		t.Fatalf("interceptor changed successful result: %#v %v", response, err)
	}
	output := logs.String()
	for _, expected := range []string{`"request_id":"integration-123"`, `"grpc_method":"/user.User/LoginWithPassword"`, `"grpc_code":"OK"`} {
		if !strings.Contains(output, expected) {
			t.Fatalf("log %q missing %q", output, expected)
		}
	}
	if strings.Contains(output, "credential-secret") || strings.Contains(output, "password") {
		t.Fatalf("credential request was logged: %s", output)
	}
}

func TestUnaryLoggingInterceptorPreservesFailureAndLogsSafeCategory(t *testing.T) {
	var logs bytes.Buffer
	interceptor := UnaryLoggingInterceptor(slog.New(slog.NewJSONHandler(&logs, nil)))
	wantErr := status.Error(codes.FailedPrecondition, "account_not_validated")
	response, err := interceptor(context.Background(), "token-secret", &grpc.UnaryServerInfo{FullMethod: "/user.User/LoginWithPassword"}, func(ctx context.Context, _ any) (any, error) {
		if RequestIDFromContext(ctx) == "" {
			t.Fatal("generated request ID missing")
		}
		return "unchanged-response", wantErr
	})
	if response != "unchanged-response" || !errors.Is(err, wantErr) {
		t.Fatalf("interceptor changed failure: %#v %v", response, err)
	}
	output := logs.String()
	if !strings.Contains(output, `"grpc_code":"FailedPrecondition"`) || !strings.Contains(output, `"error":"account_not_validated"`) || !strings.Contains(output, `"request_id":`) {
		t.Fatalf("failure was not logged safely: %s", output)
	}
	if strings.Contains(output, "token-secret") {
		t.Fatalf("token was logged: %s", output)
	}
}

func TestUnaryLoggingInterceptorOmitsSuccessfulStandardHealthCheck(t *testing.T) {
	var logs bytes.Buffer
	interceptor := UnaryLoggingInterceptor(slog.New(slog.NewJSONHandler(&logs, nil)))
	ctx := metadata.NewIncomingContext(context.Background(), metadata.Pairs(RequestIDMetadataKey, "health-probe-123"))

	response, err := interceptor(ctx, "health-request", &grpc.UnaryServerInfo{FullMethod: "/grpc.health.v1.Health/Check"}, func(ctx context.Context, _ any) (any, error) {
		if RequestIDFromContext(ctx) != "health-probe-123" {
			t.Fatal("request ID was not attached to health-check context")
		}
		return "serving", nil
	})

	if err != nil || response != "serving" {
		t.Fatalf("interceptor changed successful health result: %#v %v", response, err)
	}
	if logs.Len() != 0 {
		t.Fatalf("successful health check polluted INFO logs: %s", logs.String())
	}
}

func TestUnaryLoggingInterceptorLogsFailedStandardHealthCheckSafely(t *testing.T) {
	var logs bytes.Buffer
	interceptor := UnaryLoggingInterceptor(slog.New(slog.NewJSONHandler(&logs, nil)))
	wantErr := status.Error(codes.Unavailable, "database credential-secret")

	response, err := interceptor(context.Background(), "health-request-secret", &grpc.UnaryServerInfo{FullMethod: "/grpc.health.v1.Health/Check"}, func(context.Context, any) (any, error) {
		return nil, wantErr
	})

	if response != nil || !errors.Is(err, wantErr) {
		t.Fatalf("interceptor changed failed health result: %#v %v", response, err)
	}
	output := logs.String()
	for _, expected := range []string{`"grpc_method":"/grpc.health.v1.Health/Check"`, `"grpc_code":"Unavailable"`, `"error":"unavailable"`, `"request_id":`} {
		if !strings.Contains(output, expected) {
			t.Fatalf("failed health-check log %q missing %q", output, expected)
		}
	}
	for _, secret := range []string{"credential-secret", "health-request-secret"} {
		if strings.Contains(output, secret) {
			t.Fatalf("failed health-check log exposed %q: %s", secret, output)
		}
	}
}
