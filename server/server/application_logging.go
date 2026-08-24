package server

import (
	"context"
	"log/slog"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

func (s *UserServer) logApplicationOutcome(ctx context.Context, event string, err error) {
	if s.Log == nil {
		return
	}
	attributes := []slog.Attr{
		slog.String("event", event),
		slog.String("outcome", "succeeded"),
	}
	if requestID := RequestIDFromContext(ctx); requestID != "" {
		attributes = append(attributes, slog.String("request_id", requestID))
	}
	level := slog.LevelInfo
	if err != nil {
		attributes[1] = slog.String("outcome", "rejected")
		attributes = append(attributes, slog.String("error_category", errorCategory(err)))
		switch status.Code(err) {
		case codes.Internal, codes.Unknown, codes.DataLoss:
			level = slog.LevelError
		}
	}
	s.Log.LogAttrs(ctx, level, "application_operation", attributes...)
}
