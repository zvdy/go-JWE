package main

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
)

func main() {
	// Sample claims
	claims := map[string]interface{}{
		"sub":   "1234567890",
		"name":  "John Doe",
		"admin": true,
		"iat":   1516239022,
	}

	// Convert claims to JSON
	claimsJSON, err := json.Marshal(claims)
	if err != nil {
		fmt.Println("Error marshalling claims:", err)
		return
	}

	// Encode JSON to base64
	encodedClaims := base64.StdEncoding.EncodeToString(claimsJSON)
	fmt.Println("Base64 Encoded Claims:", encodedClaims)
}
