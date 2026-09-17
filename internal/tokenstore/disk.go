package tokenstore

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
)

// Prevents tokens from being written to disk - BLOCKS until no writers remains
func (store *RuntimeStore) HaltTokenWrites() {
	store.diskStoreMutex.Lock()
}

// Syncs current runtime view of tokens and writes to disk.
func (store *RuntimeStore) syncDiskStore() (err error) {
	store.diskStoreMutex.Lock()
	defer store.diskStoreMutex.Unlock()

	newKeyStore, err := json.MarshalIndent(store.diskStore, "", "  ")
	if err != nil {
		err = fmt.Errorf("marshal: %w", err)
		return
	}

	if store.tempDir != "" {
		tmpFile := filepath.Join(store.tempDir, "store.tmp")
		err = os.WriteFile(tmpFile, newKeyStore, 0600)
		if err != nil {
			err = fmt.Errorf("token store tmp write: %w", err)
			return
		}
		err = os.Rename(tmpFile, store.storePath)
		if err != nil {
			err = fmt.Errorf("token store overwrite: %w", err)
			return
		}
	} else {
		// Fallback to direct write without temp dir
		err = os.WriteFile(store.storePath, newKeyStore, 0600)
		if err != nil {
			err = fmt.Errorf("token store write: %w", err)
			return
		}
	}
	return
}

// Gets the full list of tokens for a user
func (store *RuntimeStore) ListTokens(username string) (allTokens []Token) {
	store.diskStoreMutex.RLock()
	defer store.diskStoreMutex.RUnlock()
	tokens, ok := store.diskStore.UserKeys[username]
	if !ok {
		return
	}
	for _, token := range tokens {
		allTokens = append(allTokens, token)
	}
	return
}
