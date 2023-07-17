package database

import (
	"github.com/KidalaZ/project1_GO/models"
	"gorm.io/driver/mysql"
	"gorm.io/gorm"
)

var DB *gorm.DB

func Connect() {
	connection, err := gorm.Open(mysql.Open("root:8Ku8z818!@/login_db"), &gorm.Config{}) // connect to database login_db, else return error

	if err != nil {
		panic("could not connect to the database") // print error if not connected to database
	}

	DB = connection

	connection.AutoMigrate(&models.User{})
	connection.AutoMigrate(&models.Channels{})
}
