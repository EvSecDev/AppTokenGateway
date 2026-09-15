package tokenstore

import "sync"

type RuntimeStore struct {
	keyStorePath string   // File path persistently storing the known tokens
	httpHeaders  []string // Which http headers contain the token

	// Authentication source
	auth           authorizedTokens // Static store of user to api keys
	authorizedKeys map[string]bool  // Reverse map of auth user keys
	authMutex      sync.RWMutex     // Protects both Auth and AuthorizedKeys (as well as file access)
}

type authorizedTokens struct {
	UserKeys map[string][]byte `json:"keys"`
}
