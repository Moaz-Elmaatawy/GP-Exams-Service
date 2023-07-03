package main

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"os"

	"github.com/dgrijalva/jwt-go"
)

type Exam struct {
	ExamID      int64  `json:"examId"`
	ExamContent string `json:"examContent"`
}

var examMap map[int64]string

func main() {
	//jwt, _ := generateJWT([]byte("d066e1db96cc0cd3f5a80c0fdc1e569bd1dc73593564de7a691b5ef39044a9e0"))
	//print(jwt)

	client := &http.Client{}

	req, err := http.NewRequest("GET", "https://api.example.com", nil)
	if err != nil {
		fmt.Println("Error creating request:", err)
		return
	}

	apiKey := os.Getenv("apiKey")
	req.Header.Set("X-API-KEY", apiKey)

	resp, err := client.Do(req)
	if err != nil {
		fmt.Println("Error sending request:", err)
		return
	}
	defer resp.Body.Close()

	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		fmt.Println("Error reading response:", err)
		return
	}

	var exams []Exam
	err = json.Unmarshal(body, &exams)
	if err != nil {
		fmt.Println("Error decoding response body:", err)
		return
	}

	examMap = make(map[int64]string)
	for _, exam := range exams {
		examMap[exam.ExamID] = exam.ExamContent
	}

	// handle requests
	http.HandleFunc("/", func(res http.ResponseWriter, req *http.Request) {
		tokenString := req.Header.Get("Authorization")
		tokenString = tokenString[7:]

		claims, err := verifyJWT(tokenString, []byte("d066e1db96cc0cd3f5a80c0fdc1e569bd1dc73593564de7a691b5ef39044a9e0"))
		if err != nil {
			panic(err)
		}
		// Extract the examId from the JWT claims
		examID := claims["examId"].(float64)
		examIDInt := int64(examID)

		// Retrieve the corresponding value from examMap
		examContent, ok := examMap[examIDInt]
		if !ok {
			res.WriteHeader(http.StatusNotFound)
			fmt.Fprintf(res, "Exam not found for examId: %d", examIDInt)
			return
		}

		res.Header().Set("Content-Type", "application/json")
		responseBody, err := json.Marshal(map[string]string{
			"examContent": examContent,
		})
		if err != nil {
			res.WriteHeader(http.StatusInternalServerError)
			fmt.Fprint(res, "Internal Server Error")
			return
		}
		fmt.Fprint(res, claims)
		fmt.Fprint(res, "Hello World! Authorized!!")
		res.WriteHeader(http.StatusOK)
		res.Write(responseBody)
	})

	// run server on port "9000"
	log.Fatal(http.ListenAndServeTLS(":9000", "SSL-Certificate/localhost.crt", "SSL-Certificate/localhost.key", nil))

}

/*func generateJWT(secretKey []byte) (string, error) {
	// Create the claims for the token
	claims := jwt.MapClaims{
		"username":   "Anas",
		"Student Id": "180014243",
		"dummy date": "dffdfgdfgadadffgafgafgfgadfffffffffffffffffffffffff",
		"exp":        time.Now().Add(time.Hour * 24).Unix(), // Token expires in 24 hours
	}

	// Create the token with the claims and sign it using the secret key
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	tokenString, err := token.SignedString(secretKey)
	if err != nil {
		return "", err
	}

	return tokenString, nil
}*/

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
