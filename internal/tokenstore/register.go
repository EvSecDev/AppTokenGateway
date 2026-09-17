package tokenstore

import (
	"crypto/sha512"
	"fmt"
	"slices"
	"time"
)

// Hashes and writes token to key store file, overwriting any existing token.
// Expires time of zero means no expiry.
func (store *RuntimeStore) StoreToken(username, tokenName, rawToken string, expires time.Time) (err error) {
	store.diskStoreMutex.Lock()

	existingTokens, ok := store.diskStore.UserKeys[username]
	if !ok {
		existingTokens = make(map[string]Token)
	}

	if len(existingTokens) > MaximumTokensPerUser {
		err = fmt.Errorf("user has reached maximum number of registered tokens (%d)", MaximumTokensPerUser)
		store.diskStoreMutex.Unlock()
		return
	}

	existingToken := existingTokens[tokenName]

	// We have no need to read the token after storage
	hasher := sha512.New()
	hasher.Write([]byte(rawToken))
	hash := hasher.Sum(nil)

	if slices.Equal(existingToken.Hash, hash) &&
		existingToken.Expires.Equal(expires) {
		// No-op
		store.diskStoreMutex.Unlock()
		return
	}

	existingToken.UserID = username
	existingToken.Name = tokenName
	existingToken.Hash = hash
	existingToken.Expires = expires
	existingTokens[tokenName] = existingToken

	store.diskStore.UserKeys[username] = existingTokens
	store.diskStoreMutex.Unlock()

	err = store.syncDiskStore()
	store.updateAuthorizedTokens()
	return
}
