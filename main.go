package main

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"log"
	"net/http"

	"github.com/dgrijalva/jwt-go"

	"golang.org/x/crypto/bcrypt"

	"github.com/gorilla/mux"
	_ "github.com/go-sql-driver/mysql"
)

type User struct {
	ID int64 `json:"id"`
	Email string `json:"email"`
	Password string `json:"password"`
}

type JWT struct {
	Token string `json:"token"`
}

type Error struct {
	Message string `json:"message"`
}

func errorInResponse(w http.ResponseWriter, status int, error Error) {
    w.WriteHeader(status) // 400 とか 500 などの HTTP status コードが入る
    json.NewEncoder(w).Encode(error)
    return
}

func responseByJSON(w http.ResponseWriter, data interface{}) {
	json.NewEncoder(w).Encode(data)
	return
}

func signup(w http.ResponseWriter, r *http.Request) {
		fmt.Println("signup 関数実行")
		var user User
		var error Error

		fmt.Println(r.Body)

		json.NewDecoder(r.Body).Decode(&user)

		if user.Email == "" {
			error.Message = "Emailは必須です"
			errorInResponse(w, http.StatusBadRequest, error)
			return
		}

		if user.Password == "" {
			error.Message = "パスワードは必須です"
			errorInResponse(w, http.StatusBadRequest, error)
			return
		}


		fmt.Println("---------------------")
		//spew.Dump(user)

		hash, err := bcrypt.GenerateFromPassword([]byte(user.Password), 10)

		if err != nil {
			log.Fatal(err)
		}

		fmt.Println("パスワード：", user.Password)
		fmt.Println("ハッシュ化されたパスワード", hash)

		user.Password = string(hash)
		fmt.Println("コンバート後のパスワード：", user.Password)

		result, err := db.Exec("INSERT INTO users(email, password) VALUES(?, ?)", user.Email, user.Password)

		if err != nil {
			log.Fatal(err)
		}

		user.ID, err = result.LastInsertId()
		if err != nil {
			log.Fatal(err)
		}
		//ins, err := db.Prepare("insert into users(email, password) values(?, ?)")
		//ins.Exec(user.Email, user.Password)

		if err != nil {
			error.Message = "サーバエラー"
			errorInResponse(w, http.StatusInternalServerError, error)
			return
		}

		user.Password = ""
		w.Header().Set("Content-Type", "application/json")

		responseByJSON(w, user)
}

func createToken(user User) (string, error) {
	var err error

	secret := "secret"

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"email": user.Email,
		"iss": "__init__",
	})

	tokenString, err := token.SignedString([]byte(secret))

	fmt.Println("---------------------")
	fmt.Println("tokenString:", tokenString)

	if err != nil {
		log.Fatal(err)
	}

	return tokenString, nil
}

func login(w http.ResponseWriter, r *http.Request) {
		fmt.Println("login 関数実行")
		var user User
		json.NewDecoder(r.Body).Decode(&user)
		token, err := createToken(user)

		if err != nil {
			log.Fatal(err)
		}

		fmt.Println(token)
}

var db *sql.DB

func main() {
	var err error
	db, err = sql.Open("mysql", "root:root@/auth")
	if err != nil {
		log.Fatal(err)
	}
	router := mux.NewRouter()

	router.HandleFunc("/signup", signup).Methods("POST")
	router.HandleFunc("/login", login).Methods("POST")

	log.Println("サーバー起動 : 8000 port で受信")

	log.Fatal(http.ListenAndServe(":8000", router))
}