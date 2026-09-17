package tokenstore

import "slices"

// Removes token from runtime and storage.
func (store *RuntimeStore) RevokeToken(token Token) (err error) {
	store.diskStoreMutex.Lock()

	tokens, ok := store.diskStore.UserKeys[token.UserID]
	if !ok {
		store.diskStoreMutex.Unlock()
		return
	}
	stored, ok := tokens[token.Name]
	if !ok {
		store.diskStoreMutex.Unlock()
		return
	}
	// If a hash was provided (auth-path eviction), verify it still matches.
	// Prevents evicting a freshly re-registered token that happens to share the name.
	if len(token.Hash) > 0 && !slices.Equal(stored.Hash, token.Hash) {
		store.diskStoreMutex.Unlock()
		return
	}
	delete(tokens, token.Name)

	if len(tokens) == 0 {
		delete(store.diskStore.UserKeys, token.UserID)
	} else {
		store.diskStore.UserKeys[token.UserID] = tokens
	}
	store.diskStoreMutex.Unlock()

	store.updateAuthorizedTokens()
	err = store.syncDiskStore()
	return
}
