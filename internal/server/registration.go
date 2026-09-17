package server

import (
	"ATG/internal/sso"
	"ATG/internal/tokenstore"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"mime"
	"net/http"
	"time"
)

type TokenRegistration struct {
	Name    string    `json:"name"`
	Token   string    `json:"token"`
	Expires time.Time `json:"expires,omitzero"`
}

func RegisterHandler(tStore *tokenstore.RuntimeStore) (handler http.HandlerFunc) {
	handler = func(response http.ResponseWriter, request *http.Request) {
		if request.Method != http.MethodPost {
			response.WriteHeader(http.StatusMethodNotAllowed)
			return
		}
		mediaType, _, err := mime.ParseMediaType(request.Header.Get("Content-Type"))
		if err != nil || mediaType != "application/json" {
			http.Error(response, "Content-Type must be application/json", http.StatusUnsupportedMediaType)
			return
		}

		body, err := io.ReadAll(request.Body)
		if err != nil {
			log.Printf("%s: Failed to read body: %v\n", request.RemoteAddr, err)
			http.Error(response, "Failed to read body", http.StatusInternalServerError)
			return
		}

		var regRequest TokenRegistration
		err = json.Unmarshal(body, &regRequest)
		if err != nil {
			log.Printf("%s: Failed to unmarshal registration JSON: %v\n", request.RemoteAddr, err)
			http.Error(response, "Failed to parse request", http.StatusBadRequest)
			return
		}

		claims, err := sso.UserFrom(request)
		if err != nil {
			log.Printf("%s: Failed to retrieve claims from request: %v\n", request.RemoteAddr, err)
			http.Error(response, "Failed to parse request", http.StatusBadRequest)
		}
		username := claims.Email

		if username == "" {
			log.Printf("%s: Could not extract username from client request\n", request.RemoteAddr)
			http.Error(response, "Invalid User", http.StatusBadRequest)
			return
		}

		err = validateTokenRegRequest(regRequest)
		if err != nil {
			log.Printf("User %s: Token %s: validation: %v\n", username, regRequest.Name, err)
			http.Error(response, "Invalid Token", http.StatusBadRequest)
			return
		}

		err = tStore.StoreToken(username, regRequest.Name, regRequest.Token, regRequest.Expires)
		if err != nil {
			log.Printf("User %s: Token %s: Register: %v\n", username, regRequest.Name, err)
			http.Error(response, "Failed Registration", http.StatusInternalServerError)
			return
		}

		// Test validation before returning ok
		testSuccess, err := tStore.IsTokenAuthorized(regRequest.Token)
		if !testSuccess {
			log.Printf("User %s: Token %s: New token failed verification test: %v\n", username, regRequest.Name, err)
			http.Error(response, "Failed verification test", http.StatusInternalServerError)
			return
		}

		log.Printf("Successfully registered new API token %s for user %s (source %s)", regRequest.Name, username, request.RemoteAddr)
		response.WriteHeader(http.StatusOK)
	}
	return
}

func validateTokenRegRequest(regRequest TokenRegistration) (err error) {
	err = tokenstore.ValidateTokenString(regRequest.Token)
	if err != nil {
		return
	}

	err = tokenstore.ValidateTokenName(regRequest.Name)
	if err != nil {
		return
	}

	if regRequest.Expires.After(time.Now().Add(tokenstore.MaximumTokenExpiration)) {
		err = fmt.Errorf("token expiry time is too far in future (must be less than %s)",
			tokenstore.MaximumTokenExpiration.String())
		return
	}
	return
}
