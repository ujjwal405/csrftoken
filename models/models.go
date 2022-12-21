package models

import (
	randomstring "csrftoken/randomstring"
)

type User struct {
	Username string `json:"username"`
	Password string `json:"password"`
	Role     string `json:"role"`
}

func Generatecsrfsecret() (string, error) {
	return randomstring.Generaterandomstring(32)
}
