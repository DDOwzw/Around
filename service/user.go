package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"reflect"
	"regexp"
	"time"

	jwt "github.com/dgrijalva/jwt-go"
	"github.com/olivere/elastic"
)

const (
	USER_INDEX = "user" // database
	USER_TYPE  = "user" // table
	// remark that in ES there is only one table allowed in one database
)

type User struct {
	Username string `json:"username"`
	Password string `json:"password"`
	Age      int64  `json:"age"`
	Gender   string `json:"gender"`
}

// this is the private key
// see the const in main.go
// mySigningKey

func checkUser(username, password string) error {
	client, err := elastic.NewClient(elastic.SetURL(ES_URL), elastic.SetSniff(false))
	if err != nil {
		return err
	}
	// select * from users where username = ?
	query := elastic.NewTermQuery("username", username)

	searchResult, err := client.Search().
		Index(USER_INDEX).
		Query(query).
		Pretty(true).
		Do(context.Background()) // execute the search
	if err != nil {
		// if in here, there is something wrong in the ES
		return err
	}

	var utyp User
	for _, item := range searchResult.Each(reflect.TypeOf(utyp)) {
		if u, ok := item.(User); ok {
			if username == u.Username && password == u.Password {
				fmt.Printf("Login in as %s\n", username)
				return nil
			}
		}
	}
	return errors.New("Wrong username or password")
}

func addUser(user User) error {
	// build a connection with ES
	client, err := elastic.NewClient(elastic.SetURL(ES_URL), elastic.SetSniff(false))
	if err != nil {
		return err
	}
	// select * from users where username = ?
	query := elastic.NewTermQuery("username", user.Username)

	searchResult, err := client.Search().
		Index(USER_INDEX).
		Query(query).
		Pretty(true).
		Do(context.Background()) // execute the search
	if err != nil {
		// if in here, there is something wrong in the ES
		return err
	}
	if searchResult.TotalHits() > 0 {
		return errors.New("User already exists")
	}
	_, err = client.Index().
		Index(USER_INDEX).
		Type(USER_TYPE).
		Id(user.Username).
		BodyJson(user).
		Refresh("wait_for").
		Do(context.Background())
	if err != nil {
		return err
	}

	fmt.Printf("User is added: $s\n", user.Username)
	return nil
}

func handlerLogin(w http.ResponseWriter, r *http.Request) {
	fmt.Println("Received one login request")
	w.Header().Set("Content-Type", "text/plain")
	w.Header().Set("Access-Control-Allow-Origin", "*")

	decoder := json.NewDecoder(r.Body)
	var user User
	if err := decoder.Decode(&user); err != nil {
		http.Error(w, "Failed to parse JSON input from client", http.StatusBadRequest)
		fmt.Printf("Failed to parse JSON input from client %v.\n", err)
		return
	}

	if err := checkUser(user.Username, user.Password); err != nil {
		if err.Error() == "Wrong username or password" {
			http.Error(w, "Wrong username or password", http.StatusUnauthorized)
		} else {
			http.Error(w, "Fail to read from ElasticSearch", http.StatusInternalServerError)
		}
		return
	}

	// create a token
	// Create a new token object, specifying signing method and the claims
	// you would like it to contain.
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"username": user.Username,
		"exp":      time.Now().Add(time.Hour * 24).Unix(),
	})
	// Sign and get the complete encoded token as a string using the secret
	tokenString, err := token.SignedString([]byte(mySigningKey))
	if err != nil {
		http.Error(w, "Failed to generate token", http.StatusInternalServerError)
		fmt.Printf("Failed to generate token %v", err)
		return
	}
	w.Write([]byte(tokenString))
}

func handlerSignup(w http.ResponseWriter, r *http.Request) {
	fmt.Println("Received one signup request")
	w.Header().Set("Content-Type", "text/plain")
	w.Header().Set("Access-Control-Allow-Origin", "*")

	decoder := json.NewDecoder(r.Body)
	var user User
	if err := decoder.Decode(&user); err != nil {
		http.Error(w, "Failed to parse JSON input from client", http.StatusBadRequest)
		fmt.Printf("Failed to parse JSON input from client %v.\n", err)
		return
	}

	if user.Username == "" || user.Password == "" || !regexp.MustCompile(`^[a-z0-9_]+$`).MatchString(user.Username) {
		http.Error(w, "Invalid username or password", http.StatusBadRequest)
		fmt.Printf("Invalid username or password.\n")
		return
	}

	if err := addUser(user); err != nil {
		if err.Error() == "User already exists" {
			http.Error(w, "User already exists", http.StatusBadRequest)
		} else {
			http.Error(w, "Failed to save to ElasticSearch", http.StatusInternalServerError)
		}
		return
	}

	w.Write([]byte("User added successfully."))
}
