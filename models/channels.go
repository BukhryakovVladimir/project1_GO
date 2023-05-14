package models

type Channels struct {
	Id        uint   `json:"id"`
	Username  string `json:"username" gorm:"unique"`
	Email     string `json:"email" gorm:"unique"`
	Userimage string `json:"userimage" gorm:"type:mediumtext"`
}
