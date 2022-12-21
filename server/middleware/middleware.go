package middleware

import (
	db "csrftoken/db"
	models "csrftoken/models"
	myjwt "csrftoken/server/middleware/myjwt"

	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"time"

	"github.com/justinas/alice"
)

func Myhandler() http.Handler {
	return alice.New(recoverHandler, authHandler).ThenFunc(logicHandler)
}
func recoverHandler(next http.Handler) http.Handler {
	fn := func(w http.ResponseWriter, r *http.Request) {
		defer func() {
			if err := recover(); err != nil {
				fmt.Printf("Recovered panic :%+v", err)
				nullifyTokenCookies(&w, r)
				http.Error(w, http.StatusText(500), 500)
			}
		}()
		next.ServeHTTP(w, r)
	}
	return http.HandlerFunc(fn)
}
func authHandler(next http.Handler) http.Handler {
	fn := func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/restricted", "/deleteuser", "/logout":
			authcookie, autherr := r.Cookie("AuthToken")
			if autherr == http.ErrNoCookie {
				log.Println("No authtoken Unauthorized attempt")
				nullifyTokenCookies(&w, r)
				http.Error(w, autherr.Error(), http.StatusUnauthorized)

				return
			} else if autherr != nil {
				panic("Panic:an error occurred")

			}
			refreshcookie, refresherr := r.Cookie("RefreshToken")
			if refresherr == http.ErrNoCookie {
				log.Println("Unauthorized attempt,no refreshcookie")
				nullifyTokenCookies(&w, r)
				http.Redirect(w, r, "/login", http.StatusFound)
				return
			} else if refresherr != nil {
				panic("panic:an error occurred")
			}
			csrfFromrequest := grabcsrf(r)
			authTokenString, refreshTokenString, csrfSecret, err := myjwt.CheckAndRefreshTokens(authcookie.Value, refreshcookie.Value, csrfFromrequest)
			if err != nil {
				if err.Error() == "Unauthorized" {
					log.Println("Unauthorized ! Your jwt is not valid")
					http.Error(w, err.Error(), http.StatusUnauthorized)
					return
				} else {
					panic("panic :an error occurred")
				}
			}
			log.Println("successfully created jwts")
			w.Header().Set("Access-Control-Allow-Origin", "*")
			setRefreshAndAuthCookies(&w, authTokenString, refreshTokenString)
			w.Header().Set("X-CSRF-Token", csrfSecret)
		default:
		}
		next.ServeHTTP(w, r)
	}
	return http.HandlerFunc(fn)
}
func logicHandler(w http.ResponseWriter, r *http.Request) {
	switch r.URL.Path {
	case "/restricted":

		w.Write([]byte("Welcome to restricted area"))

	case "/login":
		switch r.Method {
		case "GET":
			w.Write([]byte("Please login ."))
		case "POST":
			var usermodel models.User
			json.NewDecoder(r.Body).Decode(&usermodel)
			user, uuid, loginerr := db.LogUserIn(usermodel.Username, usermodel.Password)
			log.Println(user, uuid)
			if loginerr != nil {
				w.WriteHeader(http.StatusUnauthorized)
				return
			} else {
				authTokenString, refreshTokenString, csrfSecret, err := myjwt.CreateNewTokens(uuid, user.Role)
				if err != nil {
					http.Error(w, http.StatusText(500), 500)
					return
				}
				setRefreshAndAuthCookies(&w, authTokenString, refreshTokenString)
				w.Header().Set("X-CSRF-Token", csrfSecret)
				w.WriteHeader(http.StatusOK)
				w.Write([]byte("Logged in successfully"))
			}

		default:
			w.WriteHeader(http.StatusMethodNotAllowed)
		}
	case "/register":
		switch r.Method {
		case "GET":
			w.Write([]byte("Please register ."))
		case "POST":
			var userModel models.User
			json.NewDecoder(r.Body).Decode(&userModel)
			_, _, err := db.FetchByUserName(userModel.Username)
			if err == nil {
				w.WriteHeader(http.StatusUnauthorized)
				return
			} else {
				role := userModel.Role
				uuid, err := db.Storeuser(userModel.Username, userModel.Password, role)
				if err != nil {
					http.Error(w, http.StatusText(500), 500)
					return
				}
				authtokenstring, refreshtokenstring, csrfsecret, err := myjwt.CreateNewTokens(uuid, role)
				if err != nil {
					http.Error(w, http.StatusText(500), 500)
					return

				}
				setRefreshAndAuthCookies(&w, authtokenstring, refreshtokenstring)
				w.Header().Set("X-CSRF-Token", csrfsecret)
				w.WriteHeader(http.StatusOK)
				w.Write([]byte("successfully registered."))

			}
		default:
			w.WriteHeader(http.StatusMethodNotAllowed)
		}
	case "/logout":
		nullifyTokenCookies(&w, r)
		http.Redirect(w, r, "/login", http.StatusFound)
		return
	case "/deleteuser":
		log.Println("deleting the user")
		authcookie, autherr := r.Cookie("AuthToken")
		if autherr == http.ErrNoCookie {
			nullifyTokenCookies(&w, r)
			http.Redirect(w, r, "/login", http.StatusFound)
			return
		}
		uuid, uuiderr := myjwt.GrabUUID(authcookie.Value)
		if uuiderr != nil {
			nullifyTokenCookies(&w, r)
			http.Error(w, http.StatusText(500), 500)
			return
		}
		db.Deleteuser(uuid)
		nullifyTokenCookies(&w, r)
		http.Redirect(w, r, "/login", http.StatusFound)

	default:
		w.WriteHeader(http.StatusOK)

	}
}
func nullifyTokenCookies(w *http.ResponseWriter, r *http.Request) {
	authcookie := http.Cookie{
		Name:     "AuthToken",
		Value:    " ",
		Expires:  time.Now().Add(-1000 * time.Hour),
		HttpOnly: true,
	}
	http.SetCookie(*w, &authcookie)
	refreshcookie := http.Cookie{
		Name:     "RefreshToken",
		Value:    "",
		Expires:  time.Now().Add(-1000 * time.Hour),
		HttpOnly: true,
	}
	http.SetCookie(*w, &refreshcookie)
	RefreshCookie, RefreshErr := r.Cookie("RefreshToken")
	if RefreshErr == http.ErrNoCookie {
		return
	} else if RefreshErr != nil {
		fmt.Printf("Error occurred:%+v", RefreshErr)
		http.Error(*w, http.StatusText(500), 500)
		return
	}
	myjwt.RevokeRefreshToken(RefreshCookie.Value)

}
func setRefreshAndAuthCookies(w *http.ResponseWriter, authToken string, refreshToken string) {
	authcookie := http.Cookie{
		Name:     "AuthToken",
		Value:    authToken,
		HttpOnly: true,
	}
	http.SetCookie(*w, &authcookie)

	refreshcookie := http.Cookie{
		Name:     "RefreshToken",
		Value:    refreshToken,
		HttpOnly: true,
	}
	http.SetCookie(*w, &refreshcookie)

}
func grabcsrf(r *http.Request) string {
	csrftoken := r.Header.Get("X-CSRF-TOKEN")
	if csrftoken == " " {
		return csrftoken
	} else {
		return csrftoken
	}
}
