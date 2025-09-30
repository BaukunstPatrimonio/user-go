FROM golang:1.23.2-alpine3.20 AS base
RUN apk update && apk add --no-cache git ca-certificates
WORKDIR /app
COPY go.mod go.sum ./
RUN go mod download

FROM base AS test-stage
WORKDIR /app
COPY . .
RUN go test -v ./...

FROM test-stage AS build-stage
WORKDIR /app/server
COPY . .
RUN CGO_ENABLED=0 GOOS=linux go build -o /server main.go config.go

# Add a new stage to download grpc-health-probe
FROM build-stage AS grpc-probe-stage
RUN wget -qO/bin/grpc_health_probe https://github.com/grpc-ecosystem/grpc-health-probe/releases/download/v0.4.35/grpc_health_probe-linux-amd64
RUN chmod +x /bin/grpc_health_probe

FROM alpine:3.21.3 AS build-release-stage
RUN apk update && apk upgrade && apk add --no-cache curl && rm -rf /var/cache/apk/*
COPY --from=build-stage /server /server
COPY --from=grpc-probe-stage /bin/grpc_health_probe /bin/grpc_health_probe

ENTRYPOINT ["/server"]