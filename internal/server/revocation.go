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

type TokenRevoke struct {
	Name string `json:"name"`
}

// Handles any revocations for a token for a user
func RevocationHandler(tStore *tokenstore.RuntimeStore) (handler http.HandlerFunc) {
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

		var revokeReq TokenRevoke
		err = json.Unmarshal(body, &revokeReq)
		if err != nil {
			log.Printf("%s: Failed to unmarshal revoke JSON: %v\n", request.RemoteAddr, err)
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

		err = tStore.RevokeToken(tokenstore.Token{
			UserID: username,
			Name:   revokeReq.Name,
		})
		if err != nil {
			log.Printf("%s: Encountered error revoking token %s for user %s: %v\n",
				request.RemoteAddr, revokeReq.Name, username, err)
			http.Error(response, "Failed revocation", http.StatusInternalServerError)
			return
		}

		log.Printf("Successfully revoked API token %s for user %s (source %s)", revokeReq.Name, username, request.RemoteAddr)
		response.WriteHeader(http.StatusOK)
	}
	return
}
