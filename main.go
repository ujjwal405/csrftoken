package main

import (
	db "csrftoken/db"
	server "csrftoken/server"
	"csrftoken/server/middleware/myjwt"
	"log"
	"os"

	"github.com/joho/godotenv"
)

func main() {
	err := godotenv.Load(".env")
	if err != nil {
		log.Println("Error occurred while loading env file")
	}
	host := os.Getenv("HOST")
	port := os.Getenv("PORT")
	if port == " " {
		port = "9000"
	}
	db.Initdb()
	_, _, jwterr := myjwt.Initjwt()
	if jwterr != nil {
		log.Println("error while initializing jwt")
		log.Fatal()
	}

	servererr := server.StartServer(host, port)
	if servererr != nil {
		log.Println("Error while running server")
		log.Fatal(servererr)
	}

}
