package main

import (
	"crypto/sha512"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"slices"
)

func RegisterHandler(config *RuntimeConfig) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}

		body, err := io.ReadAll(r.Body)
		if err != nil {
			log.Printf("%s: Failed to read body: %v\n", r.RemoteAddr, err)
			http.Error(w, "Failed to read body", http.StatusInternalServerError)
			return
		}

		var regRequest TokenRegistration
		err = json.Unmarshal(body, &regRequest)
		if err != nil {
			log.Printf("%s: Failed to unmarshal registration JSON: %v\n", r.RemoteAddr, err)
			http.Error(w, "Failed to parse request", http.StatusBadRequest)
			return
		}

		claims := r.Context().Value(CtxKeyUserInfo).(userClaims)
		username := claims.Email

		if username == "" {
			log.Printf("%s: Could not extract username from client request\n", r.RemoteAddr)
			http.Error(w, "Invalid User", http.StatusBadRequest)
			return
		}

		err = ValidateTokenString(regRequest.Token)
		if err != nil {
			log.Printf("User %s: Token validation: %v\n", username, err)
			http.Error(w, "Invalid Token", http.StatusBadRequest)
			return
		}

		err = config.StoreNewToken(username, regRequest.Token)
		if err != nil {
			log.Printf("User %s: Register token: %v\n", username, err)
			http.Error(w, "Failed Registration", http.StatusInternalServerError)
			return
		}

		// Test validation before returning ok
		testSuccess, err := config.IsTokenAuthorized(regRequest.Token)
		if !testSuccess {
			log.Printf("User %s: New token failed verification test: %v\n", username, err)
			http.Error(w, "Failed verification test", http.StatusInternalServerError)
			return
		}

		log.Printf("Successfully registered new API token for user %s (source %s)", username, r.RemoteAddr)
		w.WriteHeader(http.StatusOK)
	}
}

// Hashes and writes new token to key store file
func (cfg *RuntimeConfig) StoreNewToken(username string, token string) (err error) {
	cfg.AuthMutex.Lock()
	defer cfg.AuthMutex.Unlock()

	existingTokenHash := cfg.Auth.UserKeys[username]

	// We have no need to read the token after storage
	hasher := sha512.New()
	hasher.Write([]byte(token))
	hash := hasher.Sum(nil)

	if slices.Equal(existingTokenHash, hash) {
		// No-op
		return
	}

	cfg.Auth.UserKeys[username] = hash

	newKeyStore, err := json.MarshalIndent(cfg.Auth, "", "  ")
	if err != nil {
		err = fmt.Errorf("marshal: %w", err)
		return
	}

	err = os.WriteFile(cfg.Static.KeyStorePath, newKeyStore, 0600)
	if err != nil {
		err = fmt.Errorf("key store write: %w", err)
		return
	}

	// Update lookup map
	cfg.AuthorizedKeys = reverseAuthKeysMap(cfg.Auth.UserKeys)
	return
}
