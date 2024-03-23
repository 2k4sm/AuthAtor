package main

import (
	"log"
	"os"

	"github.com/2k4sm/AuthAtor/models"
	"github.com/2k4sm/AuthAtor/routes"
	"github.com/gin-gonic/gin"
	"github.com/joho/godotenv"
)

// main is the entry point of the application.
//
// It initializes the Gin framework, loads the environment variables, sets up the database configuration, initializes the database connection, sets up authentication routes, and starts the server.
func main() {
	r := gin.Default()
	gin.SetMode(gin.ReleaseMode)
	err := godotenv.Load()
	if err != nil {
		log.Fatal("Error loading .env file")
	}

	config := models.Config{
		Host:     os.Getenv("DB_HOST"),
		Port:     os.Getenv("DB_PORT"),
		User:     os.Getenv("DB_USER"),
		Password: os.Getenv("DB_PASSWORD"),
		DBName:   os.Getenv("DB_NAME"),
		SSLMode:  os.Getenv("DB_SSLMODE"),
	}

	models.InitDB(&config)

	routes.AuthRoutes(r)

	log.Fatal(r.Run(":6969"))

}
