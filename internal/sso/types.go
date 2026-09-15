package sso

import (
	"github.com/coreos/go-oidc/v3/oidc"
	"golang.org/x/oauth2"
)

type OIDCProvider struct {
	config   *oauth2.Config
	verifier *oidc.IDTokenVerifier
}

type ctxKey struct{}

type UserClaims struct {
	Email string `json:"email"`
	Sub   string `json:"sub"`
}
