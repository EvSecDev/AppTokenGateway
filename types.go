package main

import (
	"sync"
	"sync/atomic"
	"time"

	"golang.org/x/oauth2"
)

type RuntimeConfig struct {
	OAuth      *oauth2.Config
	Static     JSONConfig
	TLSEnabled bool

	// Auth (non-oidc)
	Auth           AuthorizedTokens // Static store of user to api keys
	AuthorizedKeys map[string]bool  // Reverse map of auth user keys
	AuthMutex      sync.RWMutex     // Protects both Auth and AuthorizedKeys (as well as file access)

	// Logging
	logLimiter *logLimiter // logging unauth request failures at a slow rate
}

type JSONConfig struct {
	ListenPort    string     `json:"listen_port"`
	ListenAddress string     `json:"listen_address,omitempty"`
	TLSKey        string     `json:"tls_key_file,omitempty"`
	TLSCert       string     `json:"tls_cert_file,omitempty"`
	OIDC          OIDCConfig `json:"oidc_config"`
	TokenHeaders  []string   `json:"token_headers"`
	KeyStorePath  string     `json:"api_key_store"`
}

type OIDCConfig struct {
	Provider     string   `json:"provider"`
	ClientID     string   `json:"client_id"`
	ClientSecret string   `json:"client_secret"`
	RedirectURL  string   `json:"redirect_url"`
	Scope        []string `json:"scope"`
}

type AuthorizedTokens struct {
	UserKeys map[string][]byte `json:"keys"`
}

type TokenRegistration struct {
	Token string `json:"token"`
}

type userClaims struct {
	Email string `json:"email"`
	Sub   string `json:"sub"`
}

type logLimiter struct {
	interval time.Duration
	maxLogs  atomic.Int64
	count    atomic.Int64
	resetAt  atomic.Int64 // unix nano
}
