package main

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
)

func main() {
	// Sample claims
	claims := map[string]interface{}{
		"iss":   "https://example.com",          // Issuer
		"sub":   "1234567890",                   // Subject
		"aud":   "https://api.example.com",      // Audience
		"exp":   "1672531199",                     // Expiration time (Unix timestamp)
		"nbf":   "1516239022",                     // Not before time (Unix timestamp)
		"iat":   "1516239022",                     // Issued at time (Unix timestamp)
		"jti":   "unique-jwt-id-12345",          // JWT ID
		"name":  "John Doe",                     // Custom claim: Name
		"email": "john.doe@example.com",         // Custom claim: Email
		"role":  "admin",                        // Custom claim: Role
		"admin": "true",                           // Custom claim: Admin flag
		"org":   "Example Organization",         // Custom claim: Organization
		"scope": "read:messages write:messages", // Custom claim: Scope
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
