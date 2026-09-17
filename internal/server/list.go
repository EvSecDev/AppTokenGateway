package server

import (
	"ATG/internal/sso"
	"ATG/internal/tokenstore"
	"cmp"
	"encoding/json"
	"log"
	"net/http"
	"slices"
	"time"
)

type TokenInfo struct {
	Name    string    `json:"name"`
	Expires time.Time `json:"expires,omitzero"`
}

// Handles any revocations for a token for a user
func ListHandler(tStore *tokenstore.RuntimeStore) (handler http.HandlerFunc) {
	handler = func(response http.ResponseWriter, request *http.Request) {
		if request.Method != http.MethodGet {
			response.WriteHeader(http.StatusMethodNotAllowed)
			return
		}

		claims, err := sso.UserFrom(request)
		if err != nil {
			log.Printf("%s: Failed to retrieve claims from request: %v\n", request.RemoteAddr, err)
			http.Error(response, "Failed to parse request", http.StatusBadRequest)
			return
		}
		username := claims.Email

		if username == "" {
			log.Printf("%s: Could not extract username from client request\n", request.RemoteAddr)
			http.Error(response, "Invalid User", http.StatusBadRequest)
			return
		}

		userTokens := tStore.ListTokens(username)
		var list []TokenInfo
		for _, token := range userTokens {
			list = append(list, TokenInfo{
				Name:    token.Name,
				Expires: token.Expires,
			})
		}
		slices.SortFunc(list, func(a, b TokenInfo) int {
			return cmp.Compare(a.Name, b.Name)
		})

		listResponse, err := json.Marshal(list)
		if err != nil {
			log.Printf("%s: User %s token list failed to marshal: %v\n", request.RemoteAddr, username, err)
			http.Error(response, "Failed creating token list", http.StatusInternalServerError)
			return
		}

		_, err = response.Write(listResponse)
		if err != nil {
			log.Printf("%s: User %s: failed response write: %v\n", request.RemoteAddr, username, err)
			http.Error(response, "Failed response write", http.StatusInternalServerError)
			return
		}
	}
	return
}
