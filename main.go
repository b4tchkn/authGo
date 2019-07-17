package main

import (
	"database/sql"
	"fmt"
	"log"
	"net/http"

	"github.com/gorilla/mux"

	_ "github.com/mattn/go-sqlite3"
)

type User struct {
	ID int `json:"id"`
	Email string `json:"email"`
	Password string `json:"password"`
}

type JWT struct {
	Token string `json:"token"`
}

type Error struct {
	Message string `json:"message"`
}

func signup(w http.ResponseWriter, r *http.Request) {
    fmt.Println("signup 関数実行")
}

func login(w http.ResponseWriter, r *http.Request) {
    fmt.Println("login 関数実行")
}

func execDB(db *sql.DB, q string) {
	if _, err := db.Exec(q); err != nil {
		log.Fatal(err)
	}
}

func main() {

	db, err := sql.Open("sqlite3", "./sample.sqlite3")
	if err != nil {
		log.Fatal(err)
	}

	q := `
	select * from users
	`

	execDB(db, q)

	db.Close()

	router := mux.NewRouter()

	router.HandleFunc("/signup", signup).Methods("POST")
	router.HandleFunc("/login", login).Methods("POST")

	log.Println("サーバー起動 : 8000 port で受信")

	log.Fatal(http.ListenAndServe(":8000", router))
}