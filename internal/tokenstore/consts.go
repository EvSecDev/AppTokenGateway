package tokenstore

import "time"

const (
	MinTokenLength int = 32
	MaxTokenLength int = 128

	MinTokenNameLength int = 1
	MaxTokenNameLength int = 64

	MaximumTokensPerUser int = 32

	MinimumTokenExpiration time.Duration = 50 * time.Second    // Slightly under 1 minute to permit registering 1 minute (registration latency)
	MaximumTokenExpiration time.Duration = 90 * 24 * time.Hour // 3 months
)
