package db

import (
	models "csrftoken/models"
	randomstring "csrftoken/randomstring"
	"errors"
	"log"

	"golang.org/x/crypto/bcrypt"
)

var users = map[string]models.User{}
var refreshtokens map[string]string

func Initdb() {
	refreshtokens = make(map[string]string)
}
func Storeuser(username string, password string, role string) (uuid string, err error) {
	uuid, err = randomstring.Generaterandomstring(32)
	if err != nil {
		return "", err
	}
	u := models.User{}
	for u != users[uuid] {
		uuid, err = randomstring.Generaterandomstring(32)
		if err != nil {
			return "", nil
		}
	}
	passwordhash, Hasherr := generateHash(password)
	if Hasherr != nil {
		err = Hasherr
		return
	}
	users[uuid] = models.User{Username: username, Password: passwordhash, Role: role}
	return uuid, err
}
func Deleteuser(uuid string) {
	delete(users, uuid)
}
func FetchUserById(uuid string) (models.User, error) {
	u := users[uuid]
	blankuser := models.User{}
	if u != blankuser {
		return u, nil
	} else {
		return u, errors.New("user doesn't match with given uuid")
	}
}
func FetchByUserName(username string) (models.User, string, error) {
	for k, v := range users {
		if v.Username == username {
			return v, k, nil
		}
	}
	return models.User{}, "", errors.New("couldn't find the user by this name")
}
func StoreRefreshToken() (jti string, err error) {
	jti, err = randomstring.Generaterandomstring(32)
	if err != nil {
		return jti, err
	}
	for refreshtokens[jti] != "" {
		jti, err = randomstring.Generaterandomstring(32)
		if err != nil {
			return jti, err
		}
	}
	refreshtokens[jti] = "valid"
	return jti, err
}
func DeleteRefreshToken(jti string) {
	delete(refreshtokens, jti)
}
func CheckRefreshToken(jti string) bool {
	return refreshtokens[jti] != ""
}
func LogUserIn(username string, password string) (models.User, string, error) {
	user, uuid, err := FetchByUserName(username)
	log.Println(user, uuid, err)
	if err != nil {
		return models.User{}, "", err
	}
	return user, uuid, checkpassword(user.Password, password)
}
func generateHash(password string) (string, error) {
	hash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	return string(hash[:]), err
}
func checkpassword(password string, providedPassword string) error {
	return bcrypt.CompareHashAndPassword([]byte(password), []byte(providedPassword))
}
