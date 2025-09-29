# user-go

A gRPC-based user management system implemented in Go that provides authentication, user CRUD operations, and session management.

## Features

- User authentication (login/logout)
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
- `Login`: Authenticate user
- `LogOut`: End user session
- `Validate`: Validate user email
- `GetByEmail`: Retrieve user by email
- `TokenToUser`: Convert JWT token to user information
- `Refresh`: Refresh JWT token

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
