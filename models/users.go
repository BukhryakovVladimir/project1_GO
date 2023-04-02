package models

type User struct {
	Id            uint   `json:"id"`
	Username      string `json:"username" gorm:"unique"`
	Email         string `json:"email" gorm:"unique"`
	Password_hash string `json:"-"`
}
