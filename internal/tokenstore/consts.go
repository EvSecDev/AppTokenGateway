package tokenstore

import "time"

const (
	MinTokenLength int = 32
	MaxTokenLength int = 128

	MinTokenNameLength int = 1
	MaxTokenNameLength int = 64

	MaximumTokensPerUser int = 32

	MaximumTokenExpiration time.Duration = 90 * 24 * time.Hour // 3 months
)
