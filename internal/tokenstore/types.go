package tokenstore

import (
	"sync"
	"time"
)

type RuntimeStore struct {
	storePath string   // File path persistently storing the known tokens
	tempDir string // Temporary directory on the same filesystem as the token store path
	httpHeaders  []string // Which http headers contain the token

	// Authentication source
	diskStore      TokenStorage // Static store of user to api tokens
	diskStoreMutex sync.RWMutex // Protects file access

	authorizedTokens      map[string]Token // Reverse map of just the authorized hashed tokens and their details
	authorizedTokensMutex sync.RWMutex     // Protects live authorized token map
}

type TokenStorage struct {
	UserKeys map[string]map[string]Token `json:"tokens"`
}

type Token struct {
	UserID  string    `json:"userID"`
	Name    string    `json:"name"`
	Expires time.Time `json:"expires,omitzero"`
	Hash    []byte    `json:"hashedToken"`
}
