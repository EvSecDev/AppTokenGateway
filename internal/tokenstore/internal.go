package tokenstore

import "fmt"

func reverseAuthKeysMap(userKeys map[string][]byte) (keyList map[string]bool) {
	keyList = make(map[string]bool, len(userKeys))
	for _, token := range userKeys {
		keyList[string(token)] = true
	}
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

// Prevents tokens from being written to disk - BLOCKS until no writers remains
func (store *RuntimeStore) HaltTokenWrites() {
	store.authMutex.Lock()
}
