package main

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"log"
	"net/http"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
	"golang.org/x/oauth2"
)

// Initializes provider and returns verifier for OIDC/OAUTH2
func (cfg *RuntimeConfig) InitOIDCProvider() (verifier *oidc.IDTokenVerifier, err error) {
	log.Printf("Initializing OIDC with provider at '%s'\n", cfg.Static.OIDC.Provider)

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	newProvider, err := oidc.NewProvider(ctx, cfg.Static.OIDC.Provider)
	if err != nil {
		err = fmt.Errorf("provider: %w", err)
		return
	}

	cfg.OAuth = &oauth2.Config{
		ClientID:     cfg.Static.OIDC.ClientID,
		ClientSecret: cfg.Static.OIDC.ClientSecret,
		RedirectURL:  cfg.Static.OIDC.RedirectURL,
		Scopes:       cfg.Static.OIDC.Scope,
		Endpoint:     newProvider.Endpoint(),
	}

	verifier = newProvider.Verifier(&oidc.Config{
		ClientID:             cfg.Static.OIDC.ClientID,
		SupportedSigningAlgs: []string{"ES256", "RS256"},
	})
	return
}

// Central redirector to OIDC provider login page
func LoginHandler(config *RuntimeConfig) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// Generate a random state
		stateBytes := make([]byte, 32)
		_, err := rand.Read(stateBytes)
		if err != nil {
			if config.logLimiter.Allow() {
				log.Printf("%s: Random state generation error: %v\n", r.RemoteAddr, err)
			}
			http.Error(w, "Failed to generate state", http.StatusInternalServerError)
			return
		}
		state := base64.URLEncoding.EncodeToString(stateBytes)

		// Store state in a secure, HttpOnly cookie
		http.SetCookie(w, &http.Cookie{
			Name:     StateCookie,
			Value:    state,
			Path:     "/",
			HttpOnly: true,
			Secure:   true,
			SameSite: http.SameSiteStrictMode,
			MaxAge:   300, // valid for 5 minutes
		})

		// Redirect to OIDC provider with state
		url := config.OAuth.AuthCodeURL(state)
		http.Redirect(w, r, url, http.StatusFound)
	}
}

// Handles the callback from the OIDC provider
func CallbackHandler(config *RuntimeConfig, verifier *oidc.IDTokenVerifier) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		code := r.URL.Query().Get("code")
		if code == "" {
			http.Error(w, "No code in request", http.StatusBadRequest)
			return
		}

		returnedState := r.URL.Query().Get("state")
		stateCookie, err := r.Cookie(StateCookie)
		if err != nil || returnedState != stateCookie.Value {
			if config.logLimiter.Allow() {
				log.Printf("%s: Invalid state parameter: %v\n", r.RemoteAddr, err)
			}
			http.Error(w, "Invalid state parameter", http.StatusBadRequest)
			return
		}

		// Delete state cookie after verification
		http.SetCookie(w, &http.Cookie{
			Name:     StateCookie,
			Value:    "",
			Path:     "/",
			HttpOnly: true,
			Secure:   true,
			MaxAge:   -1,
		})

		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()

		token, err := config.OAuth.Exchange(ctx, code)
		if err != nil {
			if config.logLimiter.Allow() {
				log.Printf("%s: Failed to exchange token: %v\n", r.RemoteAddr, err)
			}
			http.Error(w, "Failed to exchange token", http.StatusInternalServerError)
			return
		}

		rawIDToken, ok := token.Extra(IdentityCookie).(string)
		if !ok {
			http.Error(w, "No id_token field in OAuth2 token response", http.StatusInternalServerError)
			return
		}

		idToken, err := verifier.Verify(ctx, rawIDToken)
		if err != nil {
			if config.logLimiter.Allow() {
				log.Printf("%s: Failed to verify ID token: %v\n", r.RemoteAddr, err)
			}
			http.Error(w, "Failed to verify ID token", http.StatusInternalServerError)
			return
		}

		http.SetCookie(w, &http.Cookie{
			Name:     IdentityCookie,
			Value:    rawIDToken,
			Path:     "/",
			HttpOnly: true,
			Secure:   true,
			SameSite: http.SameSiteLaxMode,
			MaxAge:   int(time.Until(idToken.Expiry).Seconds()),
		})

		var claims struct {
			Email string `json:"email"`
		}
		err = idToken.Claims(&claims)
		if err != nil {
			if config.logLimiter.Allow() {
				log.Printf("%s: Failed to parse claims: %v\n", r.RemoteAddr, err)
			}
			http.Error(w, "Failed to parse claims", http.StatusInternalServerError)
			return
		}

		http.Redirect(w, r, UserIntf, http.StatusSeeOther)
	}
}

func RequireOIDC(config *RuntimeConfig, verifier *oidc.IDTokenVerifier) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			cookie, err := r.Cookie(IdentityCookie)
			if err != nil {
				http.Redirect(w, r, UserLogin, http.StatusFound)
				return
			}

			idToken, err := verifier.Verify(
				r.Context(),
				cookie.Value,
			)
			if err != nil {
				if config.logLimiter.Allow() {
					log.Printf("%s: Failed OIDC verification: %v\n", r.RemoteAddr, err)
				}
				http.Redirect(w, r, UserLogin, http.StatusFound)
				return
			}

			var claims userClaims

			err = idToken.Claims(&claims)
			if err != nil {
				if config.logLimiter.Allow() {
					log.Printf("%s: Failed parsing claims: %v\n", r.RemoteAddr, err)
				}
				http.Redirect(w, r, UserLogin, http.StatusFound)
				return
			}

			ctx := context.WithValue(
				r.Context(),
				CtxKeyUserInfo,
				claims,
			)

			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}
