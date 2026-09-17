package tokenstore

import (
	"ATG/internal/logger"
	"crypto/sha512"
	"fmt"
	"log"
	"net/http"
	"strings"
	"time"
)

// Handles the authentication request from Nginx
func (store *RuntimeStore) NewTokenAuthHandler() (handler http.HandlerFunc) {
	handler = func(response http.ResponseWriter, request *http.Request) {
		rawToken, found := store.extractToken(request)
		if !found {
			http.Error(response, "Unauthorized", http.StatusUnauthorized)
			return
		}
		isAuthorized, err := store.IsTokenAuthorized(rawToken)
		if err != nil {
			if logger.Limit.Allow() {
				log.Printf("%s: Request contained invalid token: %v\n", request.RemoteAddr, err)
			}
			http.Error(response, "Forbidden", http.StatusForbidden)
			return
		}
		if !isAuthorized {
			if logger.Limit.Allow() {
				log.Printf("%s: Request contained an unknown token\n", request.RemoteAddr)
			}
			http.Error(response, "Forbidden", http.StatusForbidden)
			return
		}
		response.WriteHeader(http.StatusOK)
	}
	return
}

// Checks if the provided token is valid
func (store *RuntimeStore) IsTokenAuthorized(rawToken string) (isAuthorized bool, err error) {
	err = ValidateTokenString(rawToken)
	if err != nil {
		return
	}

	hasher := sha512.New()
	hasher.Write([]byte(rawToken))
	tokenHash := string(hasher.Sum(nil))

	store.authorizedTokensMutex.RLock()
	token, tokenIsKnown := store.authorizedTokens[tokenHash]
	store.authorizedTokensMutex.RUnlock()
	if !tokenIsKnown {
		return
	}
	if !token.Expires.IsZero() && time.Now().After(token.Expires) {
		// Evict token
		err = store.RevokeToken(token)
		if err != nil {
			err = fmt.Errorf("failed revoking expired token: %w", err)
			return
		}
		isAuthorized = false
	} else {
		isAuthorized = true
	}
	return
}

// Attempts to extract a token from the request based on configured headers
func (store *RuntimeStore) extractToken(request *http.Request) (rawToken string, reqHasToken bool) {
	for _, header := range store.httpHeaders {
		rawToken = request.Header.Get(header)
		if rawToken != "" {
			// If the token is prefixed with 'Bearer ', remove it (scheme is case-insensitive per RFC 6750)
			const bearerPrefix = "Bearer "
			if len(rawToken) > len(bearerPrefix) &&
				strings.EqualFold(rawToken[:len(bearerPrefix)], bearerPrefix) {
				rawToken = rawToken[len(bearerPrefix):]
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
