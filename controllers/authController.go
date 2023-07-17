package controllers

import (
	"encoding/base64"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"strconv"
	"time"

	"github.com/KidalaZ/project1_GO/database"
	"github.com/KidalaZ/project1_GO/models"
	"github.com/gofiber/fiber/v2"
	"github.com/golang-jwt/jwt/v5"
	"golang.org/x/crypto/bcrypt"
)

const SecretKey = "chechevytsa"

// add user to login_db users table
func Register(c *fiber.Ctx) error {
	var data map[string]string

	if err := c.BodyParser(&data); err != nil {
		return err
	}

	password, _ := bcrypt.GenerateFromPassword([]byte(data["password"]), 14)

	user := models.User{
		Username:      data["username"],
		Email:         data["email"],
		Password_hash: string(password),
	}

	// fileToBeUploaded := "/home/kidala/Desktop/project1_GO/userImages/default_userimage.png"
	// file, err := os.Open(fileToBeUploaded)

	// if err != nil {
	// 	fmt.Println(err)
	// 	os.Exit(1)
	// }

	// defer file.Close()

	// fileInfo, _ := file.Stat()
	// var size int64 = fileInfo.Size()
	// bytes := make([]byte, size)

	// // read file into bytes
	// buffer := bufio.NewReader(file)
	// _, err = buffer.Read(bytes)    // <--------------- here!

	// // then we need to determine the file type
	// // see https://www.socketloop.com/tutorials/golang-how-to-verify-uploaded-file-is-image-or-allowed-file-types

	// filetype := http.DetectContentType(bytes)

	// err = bucket.Put(path, bytes, filetype, s3.ACL("public-read"))

	bytes, err := ioutil.ReadFile("/home/kidala/Desktop/project1_GO/userImages/default_userimage.png")
	if err != nil {
		log.Fatal(err)
	}

	var base64Encoding string
	base64Encoding += "data:image/png;base64,"
	base64Encoding += base64.StdEncoding.EncodeToString(bytes)
	mimeType := http.DetectContentType(bytes)
	fmt.Println(mimeType)
	channel := models.Channels{
		Username:  data["username"],
		Email:     data["email"],
		Userimage: base64Encoding,
	}

	database.DB.Create(&user)
	database.DB.Create(&channel)

	return c.JSON(channel)
}

// create jwt
func Login(c *fiber.Ctx) error {
	var data map[string]string

	if err := c.BodyParser(&data); err != nil {
		return err
	}

	var user models.User

	//check email
	database.DB.Where("email = ?", data["email"]).First(&user)

	//if email not found return error
	if user.Id == 0 {
		c.Status(fiber.StatusNotFound)
		return c.JSON(fiber.Map{
			"message": "user not found",
		})
	}

	//check password, if not found return error
	if err := bcrypt.CompareHashAndPassword([]byte(user.Password_hash), []byte(data["password"])); err != nil {
		c.Status(fiber.StatusBadRequest)
		return c.JSON(fiber.Map{
			"message": "incorrect password",
		})
	}

	claims := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.RegisteredClaims{
		Issuer:    strconv.Itoa(int(user.Id)),
		ExpiresAt: jwt.NewNumericDate(time.Now().Add(time.Hour * 24 * 30)), // 30 days
	})

	token, err := claims.SignedString([]byte(SecretKey))

	if err != nil {
		c.Status(fiber.StatusInternalServerError)
		return c.JSON(fiber.Map{
			"message": "could not login",
		})
	}

	tokenCookie := fiber.Cookie{
		Name:     "jwt",
		Value:    token,
		Expires:  time.Now().Add(time.Hour * 24 * 30), // 30 days,
		HTTPOnly: true,
	}

	c.Cookie(&tokenCookie)

	return c.JSON(fiber.Map{
		"message": "success",
	})
}

// delete jwt
func Logout(c *fiber.Ctx) error {
	tokenCookie := fiber.Cookie{
		Name:     "jwt",
		Value:    "",
		Expires:  time.Now().Add(-time.Hour), // 30 days,
		HTTPOnly: true,
	}
	c.Cookie(&tokenCookie)

	return c.JSON(fiber.Map{
		"message": "success",
	})
}

// get id, username and email
func User(c *fiber.Ctx) error {
	cookie := c.Cookies("jwt")
	token, err := jwt.ParseWithClaims(cookie, &jwt.RegisteredClaims{}, func(token *jwt.Token) (interface{}, error) {
		return []byte(SecretKey), nil
	})

	if err != nil {
		c.Status(fiber.StatusUnauthorized)
		return c.JSON(fiber.Map{
			"message": "unauthenticated",
		})
	}

	claims := token.Claims.(*jwt.RegisteredClaims)

	var user models.User

	database.DB.Where("id = ?", claims.Issuer).First(&user)

	return c.JSON(user)
}

// find whether channel exists from url
func FindUser(c *fiber.Ctx) error {
	var data map[string]string

	if err := c.BodyParser(&data); err != nil {
		return err
	}

	var user models.User

	database.DB.Where("username = ?", data["username"]).First(&user)

	//if email not found return error
	if user.Id == 0 {
		c.Status(fiber.StatusNotFound)
		return c.JSON(fiber.Map{
			"message": "user not found",
		})
	}

	return c.JSON(user.Username)
}

// update user's pfp in top right corner(only seen by one user ofc)
func UserImage_topright(c *fiber.Ctx) error {
	cookie := c.Cookies("jwt")
	token, err := jwt.ParseWithClaims(cookie, &jwt.RegisteredClaims{}, func(token *jwt.Token) (interface{}, error) {
		return []byte(SecretKey), nil
	})

	if err != nil {
		c.Status(fiber.StatusUnauthorized)
		return c.JSON(fiber.Map{
			"message": "unauthenticated",
		})
	}

	claims := token.Claims.(*jwt.RegisteredClaims)

	var userimg models.Channels

	database.DB.Where("id = ?", claims.Issuer).First(&userimg)

	return c.JSON(userimg.Userimage)
}

// change user image
func ChangeUserimg(c *fiber.Ctx) error {
	var data map[string]string

	if err := c.BodyParser(&data); err != nil {
		return err
	}

	cookie := c.Cookies("jwt")
	token, err := jwt.ParseWithClaims(cookie, &jwt.RegisteredClaims{}, func(token *jwt.Token) (interface{}, error) {
		return []byte(SecretKey), nil
	})

	if err != nil {
		c.Status(fiber.StatusUnauthorized)
		return c.JSON(fiber.Map{
			"message": "unauthenticated",
		})
	}

	claims := token.Claims.(*jwt.RegisteredClaims)

	var channel models.Channels
	database.DB.Where("id = ?", claims.Issuer).First(&channel).Update("Userimage", data["userimg"])
	return c.JSON(channel)

}
