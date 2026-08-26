# user-go

A gRPC-based user management system implemented in Go that provides authentication, user CRUD operations, and session management.

## Features

- Passwordless validation-code and password authentication
- User CRUD operations
- Session management with JWT tokens
- Email validation
- Role-based access (Admin/SuperAdmin)
- Health check endpoint
- PostgreSQL database integration

## Prerequisites

- Go 1.21 or higher
- PostgreSQL database
- Protocol Buffers compiler (protoc)

## Installation

### 1. Install Protocol Buffers Compiler

Linux (using apt):

```bash
apt install -y protobuf-compiler
protoc --version  # Ensure compiler version is 3+
```

MacOS (using Homebrew):

```bash
brew install protobuf
protoc --version  # Ensure compiler version is 3+
go install google.golang.org/protobuf/cmd/protoc-gen-go@latest
go install google.golang.org/grpc/cmd/protoc-gen-go-grpc@latest
```

### 2. Environment Variables

Create a `.env` file in the root directory with the following variables:

```env
PROJECT_PORT_USER=50051
POSTGRES_HOST_USER=localhost
POSTGRES_DB_USER=your_db_name
POSTGRES_USER_USER=your_db_user
POSTGRES_PASSWORD_USER=your_db_password
POSTGRES_PORT_USER=5432
RandomStringValidation=your_random_string
SizeRandomStringValidation=32
RandomStringValidationRefresh=your_random_string_refresh
SizeRandomStringValidationRefresh=10
Issuer=your_app_name
JWT_KEY=your_jwt_secret
TOKEN_EXPIRATION_TIME=600 #ten minutes
TOKEN_EXPIRATION_TIME_REFRESH=604800 #seven days
ENV=local
```

Set ENV local to run the project in your machine, set it DEV when run it in docker and our a server.

### 3. Running the Server

```bash
go run server/*.go
```

### 4. Running the Client

```bash
go run client/client.go
```

## API Overview

The service provides the following gRPC endpoints:

- `Create`: Register a new user
- `Get`: Retrieve user by ID
- `Update`: Update user profile
- `Delete`: Delete user account
- `List`: List all users
- `Login`: Start the existing passwordless validation-code flow; preserves ePlace-compatible account creation behaviour
- `LoginWithPassword`: Verify an existing validated user's password using exactly one of email or an account-bound E.164 phone, then return the normal access/refresh token response; it does not create accounts
- `RegisterWithPassword`: Create a new unvalidated password account with an optional E.164 phone and return its verification code to a trusted internal gRPC caller; existing identities are rejected and no JWTs are returned
- `InviteWithPasswordSetup`: Create or reuse an administrator-invited identity. New/passwordless identities receive a 24-hour one-time setup token; validated identities with an existing credential are reused without changing their password
- `RequestPasswordReset`: Create a short-lived reset token for an existing password account; the raw token is returned only to the trusted internal caller for email delivery
- `ResetPassword`: Consume a reset token once, replace the Argon2id credential, and revoke the current refresh session without returning JWTs
- `SetPhone`: Authenticate with the current access token and device claims, then associate or change that user's phone login identity
- `LogOut`: End user session
- `Validate`: Validate user email
- `GetByEmail`: Retrieve user by email
- `TokenToUser`: Convert JWT token to user information
- `Refresh`: Refresh JWT token

Authentication flows remain distinct:

- Existing passwordless authentication: `Login` → `Validate`
- Password registration: `RegisterWithPassword` → `Validate`
- Later password sessions: `LoginWithPassword`
- Password reset: `RequestPasswordReset` → email delivery by the consuming application → `ResetPassword` → `LoginWithPassword`

New registration passwords must contain 8–128 Unicode characters and are stored only as Argon2id hashes. The registration verification code is intended for a trusted backend or notification service and must not be echoed by a public browser-facing API. Password registration does not authenticate immediately, cannot claim an existing email, and stores no Hortatech-specific roles or profile data.

Administrator invitations deliberately create no `password_credentials` row. Their cryptographically random token is stored only as a SHA-256 digest in the existing `password_reset_tokens` lifecycle table, expires after 24 hours, is replaced on resend, and is consumed once. `ResetPassword` creates the Argon2id credential for a passwordless invited identity and validates it atomically; before that operation normal password login cannot succeed. Project membership and email delivery remain responsibilities of the calling HortaTech backend.

Password reset tokens contain 32 random bytes, expire after 30 minutes, and are persisted only as SHA-256 digests. A new request supersedes the user's previous token. Unknown and passwordless accounts receive the same accepted status without creating reset state; a future public REST facade must keep that response generic. `user-go` does not send reset email, reset does not authenticate automatically, and existing access JWTs remain valid until expiry because only the current refresh session can be revoked by the present session architecture.

Phone login identities must be supplied in canonical international E.164 form (for example, `+34600111222`). `user-go` trims surrounding whitespace but does not infer Spain, `+34`, or any other country code. `phone_e164` is an account-bound login identifier attached during password registration or by an already authenticated user through `SetPhone`; it is not independently SMS/OTP-verified. `SetPhone` does not create a password credential, so attaching a phone to a passwordless ePlace account does not enable password login. Phone removal is not supported in this phase, and password reset remains email-only.

## Client Usage Example

```go
// Create a new gRPC client connection
conn, err := grpc.Dial("localhost:50051", grpc.WithTransportCredentials(insecure.NewCredentials()))
if err != nil {
    log.Fatalf("Failed to connect: %v", err)
}
defer conn.Close()

// Create a new user client
client := pb.NewUserClient(conn)

// Example: Create a new user
user := &pb.UserRequest{
    Email:    "test@example.com",
    Name:     "Test User",
}

response, err := client.Create(context.Background(), user)
if err != nil {
    log.Fatalf("Failed to create user: %v", err)
}
```

## Project Structure

- `/server`: Server-side implementation
  - `/server`: Server implementation
  - `/controllers`: Business logic
  - `/db`: Database interactions
  - `/models`: Data models
  - `/services`: Service layer
  - `/user-pb`: Protocol buffer definitions and generated code
- `/client`: Client implementation and examples

## Contributing

1. Fork the repository
2. Create your feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add some amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

## License

This project is licensed under the MIT License - see the LICENSE file for details.

Docker image:

```bash
docker pull ghcr.io/baukunstpatrimonio/user-go:dev-latest
```

## Health Checking

The service includes a gRPC health checking mechanism that allows clients to monitor the server's health status.

### Using the Health Check

The health check provides a simple way to verify if the server is running and ready to handle requests. This can be useful for:

- Load balancers to determine service availability
- Monitoring systems to track service health
- Client applications to check server status before making requests
