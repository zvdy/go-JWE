// verify_jwe.go
package main

import (
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"log"
	"os"

	"github.com/square/go-jose/v3"
)

type Output struct {
	JWE           string `json:"jwe"`
	JWEPrivateKey string `json:"jwe_privateKey"`
	JWEPublicKey  string `json:"jwe_publicKey"`
	JWTPrivateKey string `json:"jwt_privateKey"`
	JWTPublicKey  string `json:"jwt_publicKey"`
}

func main() {
	// Read the file
	data, err := os.ReadFile("output.txt")
	if err != nil {
		log.Fatalf("Failed to read file: %v", err)
	}

	// Parse the JSON content
	var output Output
	if err := json.Unmarshal(data, &output); err != nil {
		log.Fatalf("Failed to unmarshal JSON: %v", err)
	}

	// Decode the private key from PEM format
	block, _ := pem.Decode([]byte(output.JWEPrivateKey))
	if block == nil || block.Type != "PRIVATE KEY" {
		log.Fatalf("Failed to decode PEM block containing private key")
	}

	privateKey, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		log.Fatalf("Failed to parse private key: %v", err)
	}

	// Decrypt the JWE
	decryptedJWT, err := decryptJWE(output.JWE, privateKey)
	if err != nil {
		log.Fatalf("Failed to decrypt JWE: %v", err)
	}

	fmt.Println("Decrypted JWT:", decryptedJWT)
}

func decryptJWE(jweString string, privateKey *rsa.PrivateKey) (string, error) {
	object, err := jose.ParseEncrypted(jweString)
	if err != nil {
		return "", err
	}

	decrypted, err := object.Decrypt(privateKey)
	if err != nil {
		return "", err
	}

	return string(decrypted), nil
}
