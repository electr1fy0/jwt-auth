package main

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

var jwtKey = []byte("meow meow key")

type LoginInput struct {
	UserID int    `json:"userID"`
	Name   string `json:"name"`
}

func generateHandler(w http.ResponseWriter, r *http.Request) {
	var input LoginInput

	json.NewDecoder(r.Body).Decode(&input)
	claims := jwt.MapClaims{
		"userID": input.UserID,
		"name":   input.Name,
		"exp":    time.Now().Add(25 * time.Second).Unix(),
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	tokenString, _ := token.SignedString(jwtKey)

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{"token": tokenString})

}

func verifyHandler(w http.ResponseWriter, r *http.Request) {
	authHeader := r.Header.Get("Authorization")
	if authHeader == "" {
		http.Error(w, "missing auth header", http.StatusUnauthorized)
		return
	}

	tokenStr := strings.TrimPrefix(authHeader, "Bearer ")

	token, _ := jwt.Parse(tokenStr, func(t *jwt.Token) (any, error) {
		if _, ok := t.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("sign method err")
		}
		return jwtKey, nil
	})

	if claims, ok := token.Claims.(jwt.MapClaims); ok {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]any{
			"message": "token valid",
			"claims":  claims,
		})
	} else {
		fmt.Println("invalid")
	}

}

func main() {
	http.HandleFunc("/generate", generateHandler)
	http.HandleFunc("/verify", verifyHandler)

	fmt.Println("server started on :8080")
	http.ListenAndServe(":8082", nil)
}
