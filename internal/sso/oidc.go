package sso

import (
	"ATG/internal/config"
	"context"
	"fmt"
	"log"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
	"golang.org/x/oauth2"
)

// Initializes provider and returns config verifier for OIDC/OAUTH2
func NewOIDCProvider(oidcCfg *config.OIDCConfig) (provider *OIDCProvider, err error) {
	log.Printf("Initializing OIDC with provider at '%s'\n", oidcCfg.Provider)
	provider = &OIDCProvider{}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	newProvider, err := oidc.NewProvider(ctx, oidcCfg.Provider)
	if err != nil {
		err = fmt.Errorf("provider: %w", err)
		return
	}

	provider.config = &oauth2.Config{
		ClientID:     oidcCfg.ClientID,
		ClientSecret: oidcCfg.ClientSecret,
		RedirectURL:  oidcCfg.RedirectURL,
		Scopes:       oidcCfg.Scope,
		Endpoint:     newProvider.Endpoint(),
	}

	provider.verifier = newProvider.Verifier(&oidc.Config{
		ClientID:             oidcCfg.ClientID,
		SupportedSigningAlgs: []string{"ES256", "RS256"},
	})
	return
}
