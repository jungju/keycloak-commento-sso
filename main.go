package main

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"

	"github.com/gin-gonic/gin"
)

// Payload To commento
type Payload struct {
	Name  string `form:"name" json:"name"`
	Email string `form:"email" json:"email"`
	Token string `form:"token" json:"token"`
}

func main() {
	keycloakURL := os.Getenv("KEYCLOAK_URL")
	keycloakRealm := os.Getenv("KEYCLOAK_REALM")
	keycloakClientID := os.Getenv("KEYCLOAK_CLIENT_ID")
	secretKey := os.Getenv("SECRET_KEY")
	commentoURL := os.Getenv("COMMENTO_URL")

	rawSecretKey, err := hex.DecodeString(secretKey)
	if err != nil {
		log.Fatal(err)
	}

	r := gin.Default()
	r.LoadHTMLGlob("*")
	r.StaticFile("/keycloak.min.js", "keycloak.min.js")
	r.StaticFile("/login", "login.html")

	r.GET("/sso", func(c *gin.Context) {
		token := c.Query("token")
		hmacHex := c.Query("hmac")
		if token == "" || hmacHex == "" {
			c.AbortWithStatus(http.StatusBadRequest)
			return
		}

		rawHMAC, err := hex.DecodeString(hmacHex)
		if err != nil {
			c.AbortWithError(http.StatusBadRequest, err)
			return
		}

		rawToken, err := hex.DecodeString(token)
		if err != nil {
			c.AbortWithError(http.StatusBadRequest, err)
			return
		}

		hash := hmac.New(sha256.New, rawSecretKey)
		hash.Write(rawToken)
		expectedHMAC := hash.Sum(nil)

		if string(rawHMAC) != string(expectedHMAC) {
			c.AbortWithStatus(http.StatusUnauthorized)
			return
		}

		c.Redirect(
			http.StatusFound,
			fmt.Sprintf(
				"/login?token=%s&keycloak_url=%s&keycloak_realm=%s&keycloak_clientID=%s",
				token,
				keycloakURL,
				keycloakRealm,
				keycloakClientID,
			),
		)
	})

	r.GET("/post", func(c *gin.Context) {
		payload := &Payload{}
		if err := c.Bind(payload); err != nil {
			c.AbortWithError(http.StatusBadRequest, err)
			return
		}

		payloadJSONBytes, err := json.Marshal(payload)
		if err != nil {
			c.AbortWithError(http.StatusBadRequest, err)
			return
		}

		hash := hmac.New(sha256.New, rawSecretKey)
		io.WriteString(hash, string(payloadJSONBytes))
		sha := hex.EncodeToString(hash.Sum(nil))

		payloadJSONHex := hex.EncodeToString(payloadJSONBytes)

		c.Redirect(
			http.StatusFound,
			fmt.Sprintf(
				"%s/api/oauth/sso/callback?payload=%s&hmac=%s",
				commentoURL,
				payloadJSONHex,
				sha,
			),
		)
	})

	r.Run()
}
