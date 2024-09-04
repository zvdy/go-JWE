// main.go
package main

import (
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"log"
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v4"
	"github.com/square/go-jose/v3"
)

var (
	privateKey *rsa.PrivateKey
	publicKey  *rsa.PublicKey
)

func init() {
	var err error
	privateKey, err = rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		log.Fatalf("Failed to generate private key: %v", err)
	}
	publicKey = &privateKey.PublicKey
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

	// Parse claims
	var claims map[string]interface{}
	if err := json.Unmarshal(claimsJSON, &claims); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid JSON"})
		return
	}

	// Create JWT
	token := jwt.NewWithClaims(jwt.SigningMethodRS256, jwt.MapClaims(claims))
	jwtString, err := token.SignedString(privateKey)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to sign JWT"})
		return
	}

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

	// Respond with JWE
	c.Header("Content-Type", "application/jose")
	c.String(http.StatusOK, jweString)
}

func main() {
	r := gin.Default()
	r.POST("/generate-jwe", generateJWE)
	log.Println("Server started at :8080")
	r.Run(":8080")
}
