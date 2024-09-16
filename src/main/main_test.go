package main

import (
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/assert"
)

func setupRouter() *gin.Engine {
	router := gin.Default()
	router.POST("/generate-jwe", generateJWE)
	router.POST("/verify-jwe", verifyJWE)
	return router
}

func TestGenerateJWE(t *testing.T) {
	router := setupRouter()

	t.Run("Successful JWE Generation", func(t *testing.T) {
		claims := `{"admin":"true","aud":"https://api.example.com","email":"john.doe@example.com","exp":"1672531199","iat":"1516239022","iss":"https://example.com","jti":"unique-jwt-id-12345","name":"John Doe","nbf":"1516239022","org":"Example Organization","role":"admin","scope":"read:messages write:messages","sub":"1234567890"}`
		encodedClaims := base64.StdEncoding.EncodeToString([]byte(claims))

		req, _ := http.NewRequest("POST", "/generate-jwe", nil)
		req.Header.Set("X-Claims", encodedClaims)
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusOK, w.Code)
		assert.Contains(t, w.Body.String(), "jwe")
		assert.Contains(t, w.Body.String(), "jwe_publicKey")
		assert.Contains(t, w.Body.String(), "jwt_publicKey")
		assert.Contains(t, w.Body.String(), "jwe_privateKey")
		assert.Contains(t, w.Body.String(), "jwt_privateKey")
	})

	t.Run("Missing X-Claims Header", func(t *testing.T) {
		req, _ := http.NewRequest("POST", "/generate-jwe", nil)
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusBadRequest, w.Code)
		assert.Contains(t, w.Body.String(), "Missing X-Claims header")
	})

	t.Run("Invalid Base64 Encoding", func(t *testing.T) {
		req, _ := http.NewRequest("POST", "/generate-jwe", nil)
		req.Header.Set("X-Claims", "invalid-base64")
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusBadRequest, w.Code)
		assert.Contains(t, w.Body.String(), "Invalid base64 encoding")
	})

	t.Run("Invalid JSON in Claims", func(t *testing.T) {
		invalidJSON := base64.StdEncoding.EncodeToString([]byte(`{"admin":true,`))
		req, _ := http.NewRequest("POST", "/generate-jwe", nil)
		req.Header.Set("X-Claims", invalidJSON)
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusBadRequest, w.Code)
		assert.Contains(t, w.Body.String(), "Invalid JSON")
	})
}

func TestVerifyJWE(t *testing.T) {
	router := setupRouter()

	t.Run("Successful JWE Verification", func(t *testing.T) {
		claims := `{"admin":"true","aud":"https://api.example.com","email":"john.doe@example.com","exp":"1672531199","iat":"1516239022","iss":"https://example.com","jti":"unique-jwt-id-12345","name":"John Doe","nbf":"1516239022","org":"Example Organization","role":"admin","scope":"read:messages write:messages","sub":"1234567890"}`
		encodedClaims := base64.StdEncoding.EncodeToString([]byte(claims))

		req, _ := http.NewRequest("POST", "/generate-jwe", nil)
		req.Header.Set("X-Claims", encodedClaims)
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusOK, w.Code)
		var response map[string]string
		err := json.Unmarshal(w.Body.Bytes(), &response)
		assert.NoError(t, err)
		jweString := response["jwe"]

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
