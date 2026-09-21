package tokenstore

import (
	"crypto/sha512"
	"fmt"
	"net/http"
	"strings"
	"time"
)

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
func (store *RuntimeStore) ExtractToken(request *http.Request) (rawToken string, err error) {
	for _, header := range store.httpHeaders {
		rawToken = request.Header.Get(header)
		if rawToken != "" {
			// If the token is prefixed with 'Bearer ', remove it (scheme is case-insensitive per RFC 6750)
			const bearerPrefix = "Bearer "
			if len(rawToken) > len(bearerPrefix) &&
				strings.EqualFold(rawToken[:len(bearerPrefix)], bearerPrefix) {
				rawToken = rawToken[len(bearerPrefix):]
			}
			return
		}
	}
	err = fmt.Errorf("request did not contain any of the known permitted authorization headers %v", store.httpHeaders)
	return
}
