package main

import (
	"github.com/KidalaZ/project1_GO/database"
	"github.com/KidalaZ/project1_GO/routes"
	"github.com/gofiber/fiber/v2"
	"github.com/gofiber/fiber/v2/middleware/cors"
)

func main() {
	database.Connect() // connect to database

	app := fiber.New() // create new app

	app.Use(cors.New(cors.Config{
		AllowCredentials: true,
	}))

	routes.Setup(app) // set up the routes

	app.Listen(":8000") // app is at localhost:8080
}
