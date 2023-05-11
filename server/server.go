package main

import (
	"fmt"
	"log"
	"net/http"
	"time"

	"github.com/dgrijalva/jwt-go"
)


func main() {
	//jwt, _ := generateJWT([]byte("d066e1db96cc0cd3f5a80c0fdc1e569bd1dc73593564de7a691b5ef39044a9e0"))
	//print(jwt)
	
	// handle `/` route
	http.HandleFunc( "/", func( res http.ResponseWriter, req *http.Request ) {
		tokenString := req.Header.Get("Authorization");
		tokenString = tokenString[7:]

		claims, err := verifyJWT(tokenString, []byte("d066e1db96cc0cd3f5a80c0fdc1e569bd1dc73593564de7a691b5ef39044a9e0"))
		if err != nil {
			panic(err)
		}
		fmt.Fprint(res, claims)
		fmt.Fprint( res, "Hello World! Authorized!!" )
	} )

	// run server on port "9000"
	log.Fatal( http.ListenAndServeTLS( ":9000", "SSL-Certificate/localhost.crt", "SSL-Certificate/localhost.key", nil ) )

}


func generateJWT(secretKey []byte) (string, error) {
	// Create the claims for the token
	claims := jwt.MapClaims{
		"username": "Anas",
		"Student Id": "180014243",
		"dummy date": "dffdfgdfgadadffgafgafgfgadfffffffffffffffffffffffff",
		"exp":      time.Now().Add(time.Hour * 24).Unix(), // Token expires in 24 hours
	}

	// Create the token with the claims and sign it using the secret key
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	tokenString, err := token.SignedString(secretKey)
	if err != nil {
		return "", err
	}

	return tokenString, nil
}

func verifyJWT(tokenString string, secretKey []byte) (jwt.MapClaims, error) {
	// Parse the token and verify the signature
	token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		return secretKey, nil
	})
	if err != nil {
		return nil, err
	}

	// Check if the token is valid
	if claims, ok := token.Claims.(jwt.MapClaims); ok && token.Valid {
		return claims, nil
	}

	return nil, fmt.Errorf("invalid token")
}
