package main

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"log"
	"net/http"
	"os"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v4"
	"github.com/square/go-jose/v3"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
)

var privateKey *rsa.PrivateKey
var publicKey *rsa.PublicKey
var mongoClient *mongo.Client
var mongoCollection *mongo.Collection

func init() {
	// Generate a new RSA key pair at startup
	var err error
	privateKey, err = rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		log.Fatalf("Failed to generate private key: %v", err)
	}
	publicKey = &privateKey.PublicKey

	// Get MongoDB URI from environment variable
	mongoURI := os.Getenv("MONGO_URI")
	if mongoURI == "" {
		log.Fatalf("MONGO_URI environment variable not set")
	}

	// Connect to MongoDB
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	mongoClient, err = mongo.Connect(ctx, options.Client().ApplyURI(mongoURI))
	if err != nil {
		log.Fatalf("Failed to connect to MongoDB: %v", err)
	}

	// Ping MongoDB to ensure connection is established
	err = mongoClient.Ping(ctx, nil)
	if err != nil {
		log.Fatalf("Failed to ping MongoDB: %v", err)
	}

	// Select the database and collection
	mongoCollection = mongoClient.Database("jwe_db").Collection("responses")
	log.Println("Connected to MongoDB")
}

func generateJWE(c *gin.Context) {
	// Read base64 encoded header
	header := c.GetHeader("X-Claims")
	if header == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Missing X-Claims header"})
		return
	}

	// Decode base64 header
	claimsJSON, err := base64.StdEncoding.DecodeString(header)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid base64 encoding"})
		return
	}

	// Print the decoded claims for debugging
	fmt.Println("Decoded Claims JSON:", string(claimsJSON))

	// Parse claims
	var claims map[string]interface{}
	if err := json.Unmarshal(claimsJSON, &claims); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid JSON"})
		return
	}

	// Print the parsed claims for debugging
	fmt.Println("Parsed Claims:", claims)

	// Create JWT
	token := jwt.NewWithClaims(jwt.SigningMethodRS256, jwt.MapClaims(claims))
	jwtString, err := token.SignedString(privateKey)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to sign JWT"})
		return
	}

	// Print the JWT for debugging
	fmt.Println("Signed JWT:", jwtString)

	// Encrypt JWT to create JWE
	encrypter, err := jose.NewEncrypter(jose.A256GCM, jose.Recipient{
		Algorithm: jose.RSA_OAEP_256,
		Key:       publicKey,
	}, nil)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to create encrypter"})
		return
	}

	object, err := encrypter.Encrypt([]byte(jwtString))
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to encrypt JWT"})
		return
	}

	jweString, err := object.CompactSerialize()
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to serialize JWE"})
		return
	}

	// Convert private key to PEM format
	privateKeyPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(privateKey),
	})

	// Convert public key to PEM format
	publicKeyBytes, err := x509.MarshalPKIXPublicKey(publicKey)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to marshal public key"})
		return
	}
	publicKeyPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: publicKeyBytes,
	})

	// Verify the JWE can be decrypted with the private key
	decryptedJWT, err := decryptJWE(jweString, privateKey)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to decrypt JWE"})
		return
	}

	// Print the decrypted JWT for debugging
	fmt.Println("Decrypted JWT:", decryptedJWT)

	// Create response object
	response := gin.H{
		"jwe":            jweString,
		"jwe_publicKey":  string(publicKeyPEM),
		"jwt_publicKey":  string(publicKeyPEM),
		"jwe_privateKey": string(privateKeyPEM),
		"jwt_privateKey": string(privateKeyPEM),
	}

	// Store response in MongoDB
	if err := storeResponse(response); err != nil {
		log.Printf("Failed to store response in MongoDB: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to store response in MongoDB"})
		return
	}

	// Respond with JSON
	c.JSON(http.StatusOK, response)
}

func storeResponse(response gin.H) error {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_, err := mongoCollection.InsertOne(ctx, response)
	if err != nil {
		log.Printf("Error inserting document into MongoDB: %v", err)
	}
	return err
}

func verifyJWE(c *gin.Context) {
	// Read JWE from header
	jweString := c.GetHeader("X-JWE")
	if jweString == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Missing X-JWE header"})
		return
	}

	// Decrypt the JWE
	decryptedJWT, err := decryptJWE(jweString, privateKey)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to decrypt JWE"})
		return
	}

	// Print the decrypted JWT for debugging
	fmt.Println("Decrypted JWT:", decryptedJWT)

	// Respond with the decrypted JWT
	c.JSON(http.StatusOK, gin.H{"jwt": decryptedJWT})
}

func decryptJWE(jweString string, privateKey *rsa.PrivateKey) (string, error) {
	object, err := jose.ParseEncrypted(jweString)
	if err != nil {
		log.Printf("Error parsing JWE: %v", err)
		return "", err
	}

	decrypted, err := object.Decrypt(privateKey)
	if err != nil {
		log.Printf("Error decrypting JWE: %v", err)
		return "", err
	}

	return string(decrypted), nil
}

func main() {
	r := gin.Default()
	r.POST("/generate-jwe", generateJWE)
	r.POST("/verify-jwe", verifyJWE)
	log.Println("Server started at :8080")
	r.Run(":8080")
}
