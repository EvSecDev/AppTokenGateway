package tokenstore

import (
	"fmt"
	"unicode/utf8"
)

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

// Ensures token name is valid text
func ValidateTokenName(name string) (err error) {
	if len(name) < MinTokenNameLength {
		err = fmt.Errorf("token name is too small (%d): must be at least %d",
			len(name), MinTokenNameLength)
		return
	}
	if len(name) > MaxTokenNameLength {
		err = fmt.Errorf("token name is too large (%d): must not be larger than %d",
			len(name), MaxTokenNameLength)
		return
	}

	if !utf8.ValidString(name) {
		err = fmt.Errorf("token name is not valid utf8")
		return
	}
	for _, char := range name {
		if char > 127 {
			err = fmt.Errorf("token name is not ascii")
			return
		}
	}
	return
}
