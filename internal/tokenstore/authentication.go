package tokenstore

import (
	"ATG/internal/logger"
	"log"
	"net/http"
	"strings"
)

// Handles the authentication request from Nginx
func (store *RuntimeStore) NewTokenAuthHandler() (handler http.HandlerFunc) {
	handler = func(response http.ResponseWriter, request *http.Request) {
		token, found := store.extractToken(request)
		if !found {
			http.Error(response, "Unauthorized", http.StatusUnauthorized)
			return
		}
		isAuthorized, err := store.IsTokenAuthorized(token)
		if err != nil {
			if logger.Limit.Allow() {
				log.Printf("%s: Request contained invalid token: %v\n", request.RemoteAddr, err)
			}
			http.Error(response, "Forbidden", http.StatusForbidden)
			return
		}
		if !isAuthorized {
			if logger.Limit.Allow() {
				log.Printf("%s: Request contained an unknown token: %q\n", request.RemoteAddr, token)
			}
			http.Error(response, "Forbidden", http.StatusForbidden)
			return
		}
		response.WriteHeader(http.StatusOK)
	}
	return
}

// Attempts to extract a token from the request based on configured headers
func (store *RuntimeStore) extractToken(request *http.Request) (token string, reqHasToken bool) {
	for _, header := range store.httpHeaders {
		token = request.Header.Get(header)
		if token != "" {
			// If the token is prefixed with 'Bearer ', remove it (scheme is case-insensitive per RFC 6750)
			const bearerPrefix = "Bearer "
			if len(token) > len(bearerPrefix) &&
				strings.EqualFold(token[:len(bearerPrefix)], bearerPrefix) {
				token = token[len(bearerPrefix):]
			}
			reqHasToken = true
			return
		}
	}
	if logger.Limit.Allow() {
		log.Printf("%s: Request did not contain any of the known permitted authorization headers %v\n",
			request.RemoteAddr, store.httpHeaders)
	}
	return
}
