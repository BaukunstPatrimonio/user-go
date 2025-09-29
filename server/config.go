package main

import (
	"log"
	"os"
	"strconv"

	"github.com/baukunstpatrimonio/user-go/server/models"
)

func checkEnvVarsConf(conf *models.Config) {
	checkEnvVar("PROJECT_PORT_USER")
	checkEnvVar("POSTGRES_HOST_USER")
	checkEnvVar("POSTGRES_DB_USER")
	checkEnvVar("POSTGRES_USER_USER")
	checkEnvVar("POSTGRES_PASSWORD_USER")
	checkEnvVar("POSTGRES_PORT_USER")
	checkEnvVar("RandomStringValidation")
	checkEnvVar("RandomStringValidationRefresh")
	checkEnvVar("SizeRandomStringValidation")
	checkEnvVar("SizeRandomStringValidationRefresh")
	checkEnvVar("Issuer")
	checkEnvVar("JWT_KEY")
	checkEnvVar("TOKEN_EXPIRATION_TIME")
	checkEnvVar("TOKEN_EXPIRATION_TIME_REFRESH")
	checkEnvVar("ENV")

	project_port, err := strconv.Atoi(os.Getenv("PROJECT_PORT_USER"))
	if err != nil {
		log.Fatalf(`Missing PROJECT_PORT_USER env var`)
	}
	conf.PROJECT_PORT_USER = project_port
	conf.POSTGRES_HOST = os.Getenv("POSTGRES_HOST_USER")
	conf.POSTGRES_DB = os.Getenv("POSTGRES_DB_USER")
	conf.POSTGRES_USER = os.Getenv("POSTGRES_USER_USER")
	conf.POSTGRES_PASSWORD = os.Getenv("POSTGRES_PASSWORD_USER")
	conf.POSTGRES_PORT = os.Getenv("POSTGRES_PORT_USER")
	conf.RandomStringValidation = os.Getenv("RandomStringValidation")
	sizeRandomStringValidation, err := strconv.Atoi(os.Getenv("SizeRandomStringValidation"))
	if err != nil {
		log.Fatalf(`Missing SizeRandomStringValidation env var`)
	}
	conf.SizeRandomStringValidation = sizeRandomStringValidation
	conf.RandomStringValidationRefresh = os.Getenv("RandomStringValidationRefresh")
	sizeRandomStringValidationRefresh, err := strconv.Atoi(os.Getenv("SizeRandomStringValidationRefresh"))
	if err != nil {
		log.Fatalf(`Missing SizeRandomStringValidation env var`)
	}
	conf.SizeRandomStringValidationRefresh = sizeRandomStringValidationRefresh
	conf.Issuer = os.Getenv("Issuer")
	conf.JWTKey = []byte(os.Getenv("JWT_KEY"))
	tokenExpirationTime, err := strconv.Atoi(os.Getenv("TOKEN_EXPIRATION_TIME"))
	if err != nil {
		log.Fatalf(`Missing TOKEN_EXPIRATION_TIME env var`)
	}
	conf.TokenExpirationTime = tokenExpirationTime
	tokenExpirationTimeRefresh, err := strconv.Atoi(os.Getenv("TOKEN_EXPIRATION_TIME_REFRESH"))
	if err != nil {
		log.Fatalf(`Missing TOKEN_EXPIRATION_TIME_REFRESH env var`)
	}
	conf.TokenExpirationTimeRefresh = tokenExpirationTimeRefresh
	conf.ENV = os.Getenv("ENV")
}

func checkEnvVar(envVar string) {
	if len(os.Getenv(envVar)) == 0 {
		log.Fatalf(`Missing %s env var`, envVar)
	}
}
