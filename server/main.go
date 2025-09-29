package main

import (
	"fmt"
	"log"
	"log/slog"
	"net"
	"os"

	"google.golang.org/grpc"

	"github.com/baukunstpatrimonio/user-go/server/controllers"
	"github.com/baukunstpatrimonio/user-go/server/db"
	"github.com/baukunstpatrimonio/user-go/server/models"
	"github.com/baukunstpatrimonio/user-go/server/server"
	"github.com/baukunstpatrimonio/user-go/server/services"
	pb "github.com/baukunstpatrimonio/user-go/server/user-pb"
	"github.com/joho/godotenv"
	"google.golang.org/grpc/health"
	healthgrpc "google.golang.org/grpc/health/grpc_health_v1"
)

func main() {
	var conf models.Config
	loadEnvFile(&conf)
	checkEnvVarsConf(&conf)

	l := initLogger()

	l.Info("User service starting in environment: ", "env", conf.ENV)

	dbUser := db.GetDB_PG(&conf, l)

	svc := services.NewUserService(dbUser)
	con := controllers.NewUserController(l, svc, &conf)
	userServer := server.UserServer{
		UserController: con,
		Log:            l,
	}

	lis, err := net.Listen("tcp", fmt.Sprintf(":%d", conf.PROJECT_PORT_USER))
	if err != nil {
		log.Fatalf("failed to listen: %v", err)
	}

	s := grpc.NewServer()
	healthcheck := health.NewServer()
	healthgrpc.RegisterHealthServer(s, healthcheck)
	pb.RegisterUserServer(s, &userServer)

	healthcheck.SetServingStatus("system", healthgrpc.HealthCheckResponse_SERVING)

	log.Printf("server listening at %v", lis.Addr())
	if err := s.Serve(lis); err != nil {
		log.Fatalf("failed to serve: %v", err)
	}
}

func loadEnvFile(conf *models.Config) {
	if conf.IsLocalENV() {
		log.Println("Loading .env file")
		if err := godotenv.Load(); err != nil {
			log.Fatal("error loading .env file")
		}
	}
}

func initLogger() *slog.Logger {
	opts := &slog.HandlerOptions{
		Level: slog.LevelDebug,
	}
	return slog.New(slog.NewJSONHandler(os.Stdout, opts))
}
