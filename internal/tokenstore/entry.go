package tokenstore

import (
	"crypto/sha512"
	"encoding/json"
	"fmt"
	"os"
	"slices"
)

// Hashes and writes token to key store file, overwriting any existing token.
func (store *RuntimeStore) StoreToken(username string, token string) (err error) {
	store.authMutex.Lock()
	defer store.authMutex.Unlock()

	existingTokenHash := store.auth.UserKeys[username]

	// We have no need to read the token after storage
	hasher := sha512.New()
	hasher.Write([]byte(token))
	hash := hasher.Sum(nil)

	if slices.Equal(existingTokenHash, hash) {
		// No-op
		return
	}

	store.auth.UserKeys[username] = hash

	newKeyStore, err := json.MarshalIndent(store.auth, "", "  ")
	if err != nil {
		err = fmt.Errorf("marshal: %w", err)
		return
	}

	err = os.WriteFile(store.keyStorePath, newKeyStore, 0600)
	if err != nil {
		err = fmt.Errorf("key store write: %w", err)
		return
	}

	// Update lookup map
	store.authorizedKeys = reverseAuthKeysMap(store.auth.UserKeys)
	return
}

// Checks if the provided token is valid
func (store *RuntimeStore) IsTokenAuthorized(token string) (isAuthorized bool, err error) {
	err = ValidateTokenString(token)
	if err != nil {
		return
	}

	hasher := sha512.New()
	hasher.Write([]byte(token))
	gotHash := string(hasher.Sum(nil))

	store.authMutex.RLock()
	_, isAuthorized = store.authorizedKeys[gotHash]
	store.authMutex.RUnlock()
	return
}
