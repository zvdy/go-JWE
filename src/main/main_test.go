package main

import (
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/assert"
)

func setupRouter() *gin.Engine {
	r := gin.Default()
	r.POST("/generate-jwe", generateJWE)
	r.POST("/verify-jwe", verifyJWE)
	return r
}

func TestMain(m *testing.M) {
	// Check if MONGO_URI is set
	if os.Getenv("MONGO_URI") == "" {
		panic("MONGO_URI environment variable not set")
	}
	os.Exit(m.Run())
}

func TestGenerateJWE(t *testing.T) {
	router := setupRouter()

	t.Run("Successful JWE Generation", func(t *testing.T) {
		claims := `{"admin":"true","aud":"https://api.example.com","email":"john.doe@example.com","exp":"1672531199","iat":"1516239022","iss":"https://example.com","jti":"unique-jwt-id-12345","name":"John Doe","nbf":"1516239022","org":"Example Organization","role":"admin","scope":"read:messages write:messages","sub":"1234567890"}`
		encodedClaims := base64.StdEncoding.EncodeToString([]byte(claims))

		// Hardcoded credentials
		hardcodedUsername := "zvdy"
		hardcodedPassword := "zvdy"

		req, _ := http.NewRequest("POST", "/generate-jwe", nil)
		req.Header.Set("X-Claims", encodedClaims)
		req.SetBasicAuth(hardcodedUsername, hardcodedPassword)
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusOK, w.Code)
		assert.Contains(t, w.Body.String(), "jwe")
		assert.Contains(t, w.Body.String(), "jwe_publicKey")
		assert.Contains(t, w.Body.String(), "jwt_publicKey")
		assert.Contains(t, w.Body.String(), "jwe_privateKey")
		assert.Contains(t, w.Body.String(), "jwt_privateKey")
	})
}

func TestVerifyJWE(t *testing.T) {
	router := setupRouter()

	t.Run("Successful JWE Verification", func(t *testing.T) {
		// Generate a JWE for testing
		claims := `{"admin":"true","aud":"https://api.example.com","email":"john.doe@example.com","exp":"1672531199","iat":"1516239022","iss":"https://example.com","jti":"unique-jwt-id-12345","name":"John Doe","nbf":"1516239022","org":"Example Organization","role":"admin","scope":"read:messages write:messages","sub":"1234567890"}`
		encodedClaims := base64.StdEncoding.EncodeToString([]byte(claims))

		req, _ := http.NewRequest("POST", "/generate-jwe", nil)
		req.Header.Set("X-Claims", encodedClaims)
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusOK, w.Code)
		var response map[string]string
		json.Unmarshal(w.Body.Bytes(), &response)
		jweString := response["jwe"]

		// Verify the JWE
		req, _ = http.NewRequest("POST", "/verify-jwe", nil)
		req.Header.Set("X-JWE", jweString)
		w = httptest.NewRecorder()
		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusOK, w.Code)
		assert.Contains(t, w.Body.String(), "jwt")
	})

	t.Run("Missing X-JWE Header", func(t *testing.T) {
		req, _ := http.NewRequest("POST", "/verify-jwe", nil)
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusBadRequest, w.Code)
		assert.Contains(t, w.Body.String(), "Missing X-JWE header")
	})

	t.Run("Invalid JWE", func(t *testing.T) {
		req, _ := http.NewRequest("POST", "/verify-jwe", nil)
		req.Header.Set("X-JWE", "invalid-jwe")
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusInternalServerError, w.Code)
		assert.Contains(t, w.Body.String(), "Failed to decrypt JWE")
	})
}
