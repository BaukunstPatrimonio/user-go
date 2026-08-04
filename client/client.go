package main

import (
	"context"
	"log"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"

	"github.com/BaukunstPatrimonio/user-go/client/health"
	pb "github.com/BaukunstPatrimonio/user-go/server/user-pb"
)

func main() {
	addr := "localhost:50051"

	// Set up a connection to the server.
	conn, err := grpc.NewClient(addr, grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		log.Fatalf("did not connect: %v", err)
	}
	defer conn.Close()
	c := pb.NewUserClient(conn)

	// Create a new user
	user := &pb.UserRequest{
		Email:    "test@example.com",
		Name:     "Test User",
		// Set other fields as needed
	}
	r, err := c.Create(context.Background(), user)
	if err != nil {
		log.Fatalf("could not create user: %v", err)
	}
	log.Printf("Created user with ID: %d", r.Id)

	// Implement other operations (Get, Update, Delete, List) as needed

	// Add this to the main function after the addr declaration
	healthChecker, err := health.NewHealthChecker(addr)
	if err != nil {
		log.Fatalf("Failed to create health checker: %v", err)
	}
	defer healthChecker.Close()

	// Check server health
	if err := healthChecker.Check(5 * time.Second); err != nil {
		log.Printf("Server health check failed: %v", err)
	} else {
		log.Println("Server is healthy")
	}
}
