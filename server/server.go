package server

import (
	middleware "csrftoken/server/middleware"
	"fmt"
	"net/http"
)

func StartServer(hostname string, port string) error {
	host := hostname + ":" + port
	fmt.Printf("Listening on port :%s", port)
	handler := middleware.Myhandler()
	http.Handle("/", handler)
	return http.ListenAndServe(host, nil)
}
