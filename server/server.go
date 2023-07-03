package main

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"net/http"
	"os"
	"strings"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/s3"
	"github.com/dgrijalva/jwt-go"
)

type Exam struct {
	ExamID      int64  `json:"examId"`
	ExamContent string `json:"examContent"`
}

var (
	examBucketMap    map[int64][]string
	aesEncryptionKey = []byte("0123456789abcdef0123456789abcdef") // AES-256 key
)

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

	examBucketMap = make(map[int64][]string)
	for _, exam := range exams {
		encryptedContent, err := encrypt([]byte(exam.ExamContent))
		if err != nil {
			fmt.Println("Error encrypting exam content:", err)
			continue
		}

		bucketLinks, err := createBucketsAndStoreExam(exam.ExamID, encryptedContent)
		if err != nil {
			fmt.Println("Error creating buckets and storing exam:", err)
			continue
		}

		examBucketMap[exam.ExamID] = bucketLinks
	}

	// Print the map
	for examID, bucketLinks := range examBucketMap {
		fmt.Printf("Exam ID: %d\n", examID)
		fmt.Println("Bucket Links:", strings.Join(bucketLinks, ", "))
		fmt.Println()
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
		studentID := claims["studentId"].(float64)
		studentIDInt := int64(studentID)

		bucketLink := examBucketMap[examIDInt][studentIDInt%10]

		res.Header().Set("Content-Type", "application/json")
		responseBody, err := json.Marshal(map[string]string{
			"bucketLink": bucketLink,
			"key":        string(aesEncryptionKey),
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
func encrypt(plaintext []byte) ([]byte, error) {
	block, err := aes.NewCipher(aesEncryptionKey)
	if err != nil {
		return nil, err
	}

	ciphertext := make([]byte, aes.BlockSize+len(plaintext))
	iv := ciphertext[:aes.BlockSize]

	_, err = io.ReadFull(rand.Reader, iv)
	if err != nil {
		return nil, err
	}

	mode := cipher.NewCBCEncrypter(block, iv)
	mode.CryptBlocks(ciphertext[aes.BlockSize:], plaintext)

	return ciphertext, nil
}
func createBucketsAndStoreExam(examID int64, encryptedContent []byte) ([]string, error) {
	sess := session.Must(session.NewSession())

	s3Svc := s3.New(sess)

	var bucketLinks []string
	for i := 0; i < 10; i++ {
		bucketName := fmt.Sprintf("exam-bucket-%d-%d", examID, i+1)

		_, err := s3Svc.CreateBucket(&s3.CreateBucketInput{
			Bucket: aws.String(bucketName),
		})
		if err != nil {
			return nil, err
		}

		_, err = s3Svc.PutObject(&s3.PutObjectInput{
			Bucket: aws.String(bucketName),
			Key:    aws.String("encrypted_exam"),
			Body:   bytes.NewReader(encryptedContent),
		})
		if err != nil {
			return nil, err
		}

		bucketLinks = append(bucketLinks, getBucketLink(bucketName))
	}

	return bucketLinks, nil
}
func getBucketLink(bucketName string) string {
	return fmt.Sprintf("https://s3.amazonaws.com/%s", bucketName)
}
