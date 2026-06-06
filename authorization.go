package main

import (
	"crypto/sha512"
	"fmt"
	"log"
	"net/http"
	"strings"
)

// Handles the authentication request from Nginx
func AuthHandler(config *RuntimeConfig) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		token, found := config.ExtractToken(r)
		if !found {
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}
		isAuthorized, err := config.IsTokenAuthorized(token)
		if err != nil {
			if config.logLimiter.Allow() {
				log.Printf("%s: Request contained invalid token: %v\n", r.RemoteAddr, err)
			}
			http.Error(w, "Forbidden", http.StatusForbidden)
			return
		}
		if !isAuthorized {
			if config.logLimiter.Allow() {
				log.Printf("%s: Request contained an unknown token: %v\n", r.RemoteAddr, err)
			}
			http.Error(w, "Forbidden", http.StatusForbidden)
			return
		}
		w.WriteHeader(http.StatusOK)
	}
}

// Attempts to extract a token from the request based on configured headers
func (cfg *RuntimeConfig) ExtractToken(request *http.Request) (token string, reqHasToken bool) {
	for _, header := range cfg.Static.TokenHeaders {
		token = request.Header.Get(header)
		if token != "" {
			// If the token is prefixed with 'Bearer ', remove it
			after, ok := strings.CutPrefix(token, "Bearer ")
			if ok {
				token = after
			}
			reqHasToken = true
			return
		}
	}
	if cfg.logLimiter.Allow() {
		log.Printf("%s: Request did not contain any of the known permitted authorization headers %v\n",
			request.RemoteAddr, cfg.Static.TokenHeaders)
	}
	return
}

// Checks if the provided token is valid
func (cfg *RuntimeConfig) IsTokenAuthorized(token string) (isAuthorized bool, err error) {
	err = ValidateTokenString(token)
	if err != nil {
		return
	}

	hasher := sha512.New()
	hasher.Write([]byte(token))
	gotHash := string(hasher.Sum(nil))

	cfg.AuthMutex.RLock()
	_, isAuthorized = cfg.AuthorizedKeys[gotHash]
	cfg.AuthMutex.RUnlock()
	return
}

// Checks to ensure token string is valid text
func ValidateTokenString(token string) (err error) {
	if len(token) < MinTokenLength {
		err = fmt.Errorf("token is too small (%d): must be at least %d",
			len(token), MinTokenLength)
		return
	}
	if len(token) > MaxTokenLength {
		err = fmt.Errorf("token is too large (%d): must not be larger than %d",
			len(token), MaxTokenLength)
		return
	}

	for _, char := range token {
		if !(char >= '0' && char <= '9' || char >= 'a' && char <= 'f') {
			err = fmt.Errorf("token contains non-hexadecimal and/or non-lower case characters")
			return
		}
	}

	return
}
