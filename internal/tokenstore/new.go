package tokenstore

import (
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"os"
)

// Create new runtime token storage from a storage file and expected token-containing http headers.
// Initializes on disk storage if it does not exist.
func New(tokenStorePath string, tokenHeaders []string) (store *RuntimeStore, err error) {
	store = &RuntimeStore{
		keyStorePath: tokenStorePath,
		httpHeaders:  tokenHeaders,
		auth: authorizedTokens{
			UserKeys: make(map[string][]byte),
		},
		authorizedKeys: make(map[string]bool),
	}

	log.Printf("Loading API key store file from '%s'\n", tokenStorePath)

	authKeysFile, err := os.ReadFile(tokenStorePath)
	switch {
	case errors.Is(err, os.ErrNotExist):
		var emptyKeyMap authorizedTokens
		emptyKeyMap.UserKeys = make(map[string][]byte)

		var newKeyStore []byte
		newKeyStore, err = json.Marshal(emptyKeyMap)
		if err != nil {
			err = fmt.Errorf("failed to initialize new empty key map: %w", err)
			return
		}

		err = os.WriteFile(tokenStorePath, newKeyStore, 0600)
		if err != nil {
			err = fmt.Errorf("failed to write new empty key map: %w", err)
			return
		}

		store.auth = emptyKeyMap
	case err == nil:
		err = json.Unmarshal(authKeysFile, &store.auth)
		if err != nil {
			err = fmt.Errorf("failed to parse key store file: %w", err)
			return
		}

		store.authorizedKeys = reverseAuthKeysMap(store.auth.UserKeys)
	default:
		err = fmt.Errorf("failed to read key store file: %w", err)
		return
	}
	return
}
