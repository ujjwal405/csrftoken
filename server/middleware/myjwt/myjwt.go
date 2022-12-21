package myjwt

import (
	"crypto/rsa"
	db "csrftoken/db"
	models "csrftoken/models"

	"errors"
	"io/ioutil"
	"log"
	"time"

	jwt "github.com/dgrijalva/jwt-go"
)

const (
	privatekeypath        = "keys/app.rsa"
	publickeypath         = "keys/app.rsa.pub"
	RefreshTokenValidTime = time.Hour * 72
	AuthTokenValidTime    = time.Minute * 15
)

type TokenClaims struct {
	Role string `json:"role"`
	Csrf string `json:"csrf"`
	jwt.StandardClaims
}

func Initjwt() (Signkey *rsa.PrivateKey, Verifykey *rsa.PublicKey, err error) {
	signbytes, err := ioutil.ReadFile(privatekeypath)
	if err != nil {
		return
	}
	Signkey, err = jwt.ParseRSAPrivateKeyFromPEM(signbytes)
	if err != nil {
		return
	}
	verifybytes, err := ioutil.ReadFile(publickeypath)
	if err != nil {
		return
	}
	Verifykey, err = jwt.ParseRSAPublicKeyFromPEM(verifybytes)
	if err != nil {
		return
	}
	return
}

func CreateNewTokens(uuid string, role string) (authToken, refreshToken, csrfSecret string, err error) {
	csrfSecret, err = models.Generatecsrfsecret()
	if err != nil {
		return
	}
	refreshToken, err = createRefreshTokenString(uuid, role, csrfSecret)
	if err != nil {
		return
	}
	authToken, err = createAuthTokenString(uuid, role, csrfSecret)
	if err != nil {
		return
	}
	return
}
func CheckAndRefreshTokens(oldAuthTokenString string, oldRefreshTokenString string, oldcsrfSecret string) (newAuthTokenString, newRefreshTokenString, newcsrfSecret string, err error) {
	if oldcsrfSecret == "" {
		log.Println("No csrf token")
		err = errors.New("Unauthorized")
		return
	}
	_, Verifykey, err := Initjwt()
	if err != nil {
		return
	}
	authtoken, _ := jwt.ParseWithClaims(oldAuthTokenString, &TokenClaims{}, func(token *jwt.Token) (interface{}, error) {
		return Verifykey, nil
	})
	authclaims, ok := authtoken.Claims.(*TokenClaims)
	if !ok {
		return
	}
	if oldcsrfSecret != authclaims.Csrf {
		log.Println("csrf token doesn't match with jwt")
		err = errors.New("Unauthorized")
		return
	}
	if authtoken.Valid {
		log.Println("Auth token is valid")
		newcsrfSecret = authclaims.Csrf
		newRefreshTokenString, err = updateRefreshTokenExp(oldRefreshTokenString)
		newAuthTokenString = oldAuthTokenString
		return
	} else if ve, ok := err.(*jwt.ValidationError); ok {
		log.Println("Auth token is not valid")
		if ve.Errors&(jwt.ValidationErrorExpired) != 0 {
			log.Println("Auth token is expired")
			newAuthTokenString, newcsrfSecret, err = updateAuthTokenString(oldRefreshTokenString, oldAuthTokenString)
			if err != nil {
				return
			}
			newRefreshTokenString, err = updateRefreshTokenExp(oldRefreshTokenString)
			if err != nil {
				return
			}
			newRefreshTokenString, err = updateRefreshTokenCsrf(newRefreshTokenString, newcsrfSecret)
			return
		} else {
			log.Println("error in auth token")
			err = errors.New("error in auth token")
			return
		}
	} else {
		log.Println("error in auth token")
		err = errors.New("error in auth token")
		return
	}
}

func createAuthTokenString(uuid string, role string, csrfsecret string) (authTokenString string, err error) {
	Signkey, _, err := Initjwt()
	if err != nil {
		return
	}

	authexp := time.Now().Add(AuthTokenValidTime).Unix()
	claims := &TokenClaims{
		role,
		csrfsecret,
		jwt.StandardClaims{
			Subject:   uuid,
			ExpiresAt: authexp,
		},
	}
	authjwt := jwt.NewWithClaims(jwt.GetSigningMethod("RS256"), claims)
	authTokenString, err = authjwt.SignedString(Signkey)
	return
}
func createRefreshTokenString(uuid string, role string, csrfsecret string) (refreshTokenString string, err error) {
	Signkey, _, err := Initjwt()
	if err != nil {
		return
	}
	refreshexp := time.Now().Add(RefreshTokenValidTime).Unix()
	refreshjti, err := db.StoreRefreshToken()
	if err != nil {
		return
	}

	refreshclaims := &TokenClaims{
		role,
		csrfsecret,
		jwt.StandardClaims{
			Id:        refreshjti,
			Subject:   uuid,
			ExpiresAt: refreshexp,
		},
	}
	refreshjwt := jwt.NewWithClaims(jwt.GetSigningMethod("RS256"), refreshclaims)
	refreshTokenString, err = refreshjwt.SignedString(Signkey)
	return
}
func updateRefreshTokenExp(oldRefreshTokenString string) (newRefreshTokenString string, err error) {
	Signkey, Verifykey, err := Initjwt()
	if err != nil {
		return
	}

	refreshtoken, _ := jwt.ParseWithClaims(oldRefreshTokenString, &TokenClaims{}, func(token *jwt.Token) (interface{}, error) {
		return Verifykey, nil
	})
	oldrefreshclaims, ok := refreshtoken.Claims.(*TokenClaims)
	if !ok {
		return
	}
	refreshtokenExp := time.Now().Add(RefreshTokenValidTime).Unix()
	newrefreshclaims := &TokenClaims{
		oldrefreshclaims.Role,
		oldrefreshclaims.Csrf,
		jwt.StandardClaims{
			Id:        oldrefreshclaims.StandardClaims.Id,
			Subject:   oldrefreshclaims.StandardClaims.Subject,
			ExpiresAt: refreshtokenExp,
		},
	}
	refreshjwt := jwt.NewWithClaims(jwt.GetSigningMethod("RS256"), newrefreshclaims)
	newRefreshTokenString, err = refreshjwt.SignedString(Signkey)
	if err != nil {
		return
	}
	return

}
func updateAuthTokenString(refreshtokenstring string, oldauthtokenstring string) (newAuthTokenString, newCsrfSecret string, err error) {
	_, Verifykey, err := Initjwt()
	if err != nil {
		return
	}
	refreshtoken, _ := jwt.ParseWithClaims(refreshtokenstring, &TokenClaims{}, func(token *jwt.Token) (interface{}, error) {
		return Verifykey, nil
	})
	refreshclaims, ok := refreshtoken.Claims.(*TokenClaims)
	if !ok {
		err = errors.New("error occurred while reading claims")
		return
	}
	if db.CheckRefreshToken(refreshclaims.StandardClaims.Id) {
		if refreshtoken.Valid {
			authtoken, _ := jwt.ParseWithClaims(oldauthtokenstring, &TokenClaims{}, func(token *jwt.Token) (interface{}, error) {
				return Verifykey, nil
			})
			authclaims, ok := authtoken.Claims.(*TokenClaims)
			if !ok {
				err = errors.New("error in reading jwt claims")
				return
			}
			newCsrfSecret, err = models.Generatecsrfsecret()
			if err != nil {
				return
			}
			newAuthTokenString, err = createAuthTokenString(authclaims.StandardClaims.Subject, authclaims.Role, newCsrfSecret)
			if err != nil {
				return
			}
			return
		} else {
			log.Println("refreshtoken has expired")
			db.DeleteRefreshToken(refreshclaims.StandardClaims.Id)
			err = errors.New("Unauthorized")
			return
		}
	} else {
		log.Println("refreshtoken is revoked")
		err = errors.New("Unauthorized")
		return
	}

}
func RevokeRefreshToken(refreshtoken string) error {
	_, Verifykey, err := Initjwt()
	if err != nil {
		return err
	}
	refreshToken, err := jwt.ParseWithClaims(refreshtoken, &TokenClaims{}, func(token *jwt.Token) (interface{}, error) {
		return Verifykey, nil
	})
	if err != nil {
		err = errors.New("couldn't parse refreshtoken claims")
		return err
	}
	refreshtokenclaims, ok := refreshToken.Claims.(*TokenClaims)
	if !ok {
		err = errors.New("error while reading refreshtokenclaims")
		return err
	}
	db.DeleteRefreshToken(refreshtokenclaims.StandardClaims.Id)
	return nil

}
func updateRefreshTokenCsrf(oldRefreshTokenString string, newCsrfString string) (newRefreshTokenString string, err error) {
	Signkey, Verifykey, err := Initjwt()
	if err != nil {
		return
	}
	refreshtoken, _ := jwt.ParseWithClaims(oldRefreshTokenString, &TokenClaims{}, func(token *jwt.Token) (interface{}, error) {
		return Verifykey, nil
	})
	refreshtokenclaims, ok := refreshtoken.Claims.(*TokenClaims)
	if !ok {
		return
	}
	refreshclaims := &TokenClaims{
		refreshtokenclaims.Role,
		newCsrfString,
		jwt.StandardClaims{
			Id:        refreshtokenclaims.StandardClaims.Id,
			Subject:   refreshtokenclaims.StandardClaims.Subject,
			ExpiresAt: refreshtokenclaims.StandardClaims.ExpiresAt,
		},
	}
	refreshjwt := jwt.NewWithClaims(jwt.GetSigningMethod("RS256"), refreshclaims)
	newRefreshTokenString, err = refreshjwt.SignedString(Signkey)
	return
}
func GrabUUID(authtoken string) (string, error) {
	_, Verifykey, err := Initjwt()
	if err != nil {
		return "", err
	}
	Authtoken, _ := jwt.ParseWithClaims(authtoken, &TokenClaims{}, func(token *jwt.Token) (interface{}, error) {
		return Verifykey, nil
	})
	Authclaims, ok := Authtoken.Claims.(*TokenClaims)
	if !ok {
		return "", errors.New("error while fetching authclaims")
	}
	return Authclaims.StandardClaims.Subject, nil
}
