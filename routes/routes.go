package routes

import (
	"github.com/KidalaZ/project1_GO/controllers"
	"github.com/gofiber/fiber/v2"
)

func Setup(app *fiber.App) {
	app.Post("/api/register", controllers.Register)
	app.Post("/api/login", controllers.Login)
	app.Post("/api/logout", controllers.Logout)
	app.Get("/api/user", controllers.User)
	app.Post("/api/finduser", controllers.FindUser)
	app.Get("/api/userimageTopright", controllers.UserImage_topright)
	app.Post("/api/changeuserimg", controllers.ChangeUserimg)
}
