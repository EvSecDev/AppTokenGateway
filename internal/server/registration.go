package server

import (
	"ATG/internal/sso"
	"ATG/internal/tokenstore"
	"encoding/json"
	"io"
	"log"
	"mime"
	"net/http"
)

type TokenRegistration struct {
	Token string `json:"token"`
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

		err = tokenstore.ValidateTokenString(regRequest.Token)
		if err != nil {
			log.Printf("User %s: Token validation: %v\n", username, err)
			http.Error(response, "Invalid Token", http.StatusBadRequest)
			return
		}

		err = tStore.StoreToken(username, regRequest.Token)
		if err != nil {
			log.Printf("User %s: Register token: %v\n", username, err)
			http.Error(response, "Failed Registration", http.StatusInternalServerError)
			return
		}

		// Test validation before returning ok
		testSuccess, err := tStore.IsTokenAuthorized(regRequest.Token)
		if !testSuccess {
			log.Printf("User %s: New token failed verification test: %v\n", username, err)
			http.Error(response, "Failed verification test", http.StatusInternalServerError)
			return
		}

		log.Printf("Successfully registered new API token for user %s (source %s)", username, request.RemoteAddr)
		response.WriteHeader(http.StatusOK)
	}
	return
}
