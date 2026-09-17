package tokenstore

import (
	"bytes"
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
		storePath:   tokenStorePath,
		httpHeaders: tokenHeaders,
		diskStore: TokenStorage{
			UserKeys: make(map[string]map[string]Token),
		},
		authorizedTokens: make(map[string]Token),
	}

	log.Printf("Loading API key store file from '%s'\n", tokenStorePath)

	authKeysFile, err := os.ReadFile(tokenStorePath)
	switch {
	case errors.Is(err, os.ErrNotExist):
		var emptyKeyMap TokenStorage
		emptyKeyMap.UserKeys = make(map[string]map[string]Token)

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

		store.diskStore = emptyKeyMap
	case err == nil:
		strictDecoder := json.NewDecoder(bytes.NewReader(authKeysFile))
		strictDecoder.DisallowUnknownFields()
		err = strictDecoder.Decode(&store.diskStore)
		if err != nil {
			err = fmt.Errorf("failed to parse key store file: %w", err)
			return
		}

		store.updateAuthorizedTokens()
	default:
		err = fmt.Errorf("failed to read key store file: %w", err)
		return
	}
	return
}

// Updates the authorized token view from the diskStore
func (store *RuntimeStore) updateAuthorizedTokens() {
	store.authorizedTokensMutex.Lock()
	defer store.authorizedTokensMutex.Unlock()

	store.diskStoreMutex.RLock()
	defer store.diskStoreMutex.RUnlock()

	tokenList := make(map[string]Token, len(store.diskStore.UserKeys))
	for _, tokens := range store.diskStore.UserKeys {
		for _, token := range tokens {
			tokenList[string(token.Hash)] = token
		}
	}
	store.authorizedTokens = tokenList
}
