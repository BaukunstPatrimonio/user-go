package server

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"log/slog"
	"regexp"
	"strings"
	"time"

	"github.com/BaukunstPatrimonio/user-go/server/models"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	healthgrpc "google.golang.org/grpc/health/grpc_health_v1"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
)

const RequestIDMetadataKey = "x-request-id"

var validRequestID = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$`)
var safeCategory = regexp.MustCompile(`^[a-z][a-z0-9_]{0,63}$`)

type requestIDContextKey struct{}

func RequestIDFromContext(ctx context.Context) string {
	value, _ := ctx.Value(requestIDContextKey{}).(string)
	return value
}

func UnaryLoggingInterceptor(logger *slog.Logger) grpc.UnaryServerInterceptor {
	return func(ctx context.Context, request any, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (any, error) {
		started := time.Now()
		requestID := incomingRequestID(ctx)
		ctx = context.WithValue(ctx, requestIDContextKey{}, requestID)
		_ = grpc.SetHeader(ctx, metadata.Pairs(RequestIDMetadataKey, requestID))

		response, err := handler(ctx, request)
		grpcCode := status.Code(err)
		if info.FullMethod == healthgrpc.Health_Check_FullMethodName && grpcCode == codes.OK {
			return response, err
		}
		attributes := []slog.Attr{
			slog.String("request_id", requestID),
			slog.String("grpc_method", info.FullMethod),
			slog.String("grpc_code", grpcCode.String()),
			slog.Duration("latency", time.Since(started)),
		}
		level := slog.LevelInfo
		if err != nil {
			level = slog.LevelWarn
			if grpcCode == codes.Internal || grpcCode == codes.Unknown || grpcCode == codes.DataLoss {
				level = slog.LevelError
			}
			attributes = append(attributes, slog.String("error", errorCategory(err)))
		}
		logger.LogAttrs(ctx, level, "grpc_request_completed", attributes...)
		return response, err
	}
}

func incomingRequestID(ctx context.Context) string {
	if incoming, ok := metadata.FromIncomingContext(ctx); ok {
		values := incoming.Get(RequestIDMetadataKey)
		if len(values) > 0 && validRequestID.MatchString(values[0]) {
			return values[0]
		}
	}
	bytes := make([]byte, 16)
	if _, err := rand.Read(bytes); err == nil {
		return hex.EncodeToString(bytes)
	}
	return hex.EncodeToString([]byte(time.Now().UTC().Format(time.RFC3339Nano)))
}

func errorCategory(err error) string {
	switch {
	case errors.Is(err, models.ErrAccountNotValidated):
		return "account_not_validated"
	case errors.Is(err, models.ErrInvalidCode):
		return "invalid_verification_code"
	case errors.Is(err, models.ErrExpiredCode):
		return "expired_verification_code"
	case errors.Is(err, models.ErrInvalidCredentials):
		return "invalid_credentials"
	}
	grpcStatus := status.Convert(err)
	if safeCategory.MatchString(grpcStatus.Message()) {
		return grpcStatus.Message()
	}
	return strings.ToLower(grpcStatus.Code().String())
}
