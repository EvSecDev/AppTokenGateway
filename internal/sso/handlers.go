package sso

import (
	"ATG/internal/logger"
	"context"
	"crypto/rand"
	"encoding/base64"
	"log"
	"net/http"
	"strings"
	"time"
)

const (
	UserIntf  string = "/"
	UserLogin string = "/login"
	Callback  string = "/callback"

	IdentityCookie string = "id_token"
	StateCookie    string = "oidc_state"

	CtxKeyUserInfo string = "user"
)

// Central redirector to OIDC provider login page
func (provider OIDCProvider) NewLoginHandler() (handler http.HandlerFunc) {
	handler = func(response http.ResponseWriter, request *http.Request) {
		// Generate a random state
		stateBytes := make([]byte, 32)
		_, err := rand.Read(stateBytes)
		if err != nil {
			if logger.Limit.Allow() {
				log.Printf("%s: Random state generation error: %v\n", request.RemoteAddr, err)
			}
			http.Error(response, "Failed to generate state", http.StatusInternalServerError)
			return
		}
		state := base64.URLEncoding.EncodeToString(stateBytes)

		// Store state in a secure, HttpOnly cookie
		http.SetCookie(response, &http.Cookie{
			Name:     StateCookie,
			Value:    state,
			Path:     "/",
			HttpOnly: true,
			Secure:   true,
			SameSite: http.SameSiteStrictMode,
			MaxAge:   300, // valid for 5 minutes
		})

		// Redirect to OIDC provider with state
		url := provider.config.AuthCodeURL(state)
		http.Redirect(response, request, url, http.StatusFound)
	}
	return
}

// Handles the callback from the OIDC provider
func (provider OIDCProvider) NewCallbackHandler() (handler http.HandlerFunc) {
	handler = func(response http.ResponseWriter, request *http.Request) {
		code := request.URL.Query().Get("code")
		if code == "" {
			http.Error(response, "No code in request", http.StatusBadRequest)
			return
		}

		returnedState := request.URL.Query().Get("state")
		stateCookie, err := request.Cookie(StateCookie)
		if err != nil || returnedState != stateCookie.Value {
			if logger.Limit.Allow() {
				log.Printf("%s: Invalid state parameter: %v\n", request.RemoteAddr, err)
			}
			http.Error(response, "Invalid state parameter", http.StatusBadRequest)
			return
		}

		// Delete state cookie after verification
		http.SetCookie(response, &http.Cookie{
			Name:     StateCookie,
			Value:    "",
			Path:     "/",
			HttpOnly: true,
			Secure:   true,
			MaxAge:   -1,
		})

		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()

		token, err := provider.config.Exchange(ctx, code)
		if err != nil {
			if logger.Limit.Allow() {
				log.Printf("%s: Failed to exchange token: %v\n", request.RemoteAddr, err)
			}
			http.Error(response, "Failed to exchange token", http.StatusInternalServerError)
			return
		}

		rawIDToken, ok := token.Extra(IdentityCookie).(string)
		if !ok {
			http.Error(response, "No id_token field in OAuth2 token response", http.StatusInternalServerError)
			return
		}

		idToken, err := provider.verifier.Verify(ctx, rawIDToken)
		if err != nil {
			if logger.Limit.Allow() {
				log.Printf("%s: Failed to verify ID token: %v\n", request.RemoteAddr, err)
			}
			http.Error(response, "Failed to verify ID token", http.StatusInternalServerError)
			return
		}

		http.SetCookie(response, &http.Cookie{
			Name:     IdentityCookie,
			Value:    rawIDToken,
			Path:     "/",
			HttpOnly: true,
			Secure:   true,
			SameSite: http.SameSiteStrictMode,
			MaxAge:   int(time.Until(idToken.Expiry).Seconds()),
		})

		var claims struct {
			Email string `json:"email"`
		}
		err = idToken.Claims(&claims)
		if err != nil {
			if logger.Limit.Allow() {
				log.Printf("%s: Failed to parse claims: %v\n", request.RemoteAddr, err)
			}
			http.Error(response, "Failed to parse claims", http.StatusInternalServerError)
			return
		}

		http.Redirect(response, request, UserIntf, http.StatusSeeOther)
	}
	return
}

// Creates new http middleware that requires every request passed through be authenticated by the OIDC provider.
func (provider OIDCProvider) RequireAuthenticated() func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
			cookie, err := request.Cookie(IdentityCookie)
			if err != nil {
				http.Redirect(response, request, UserLogin, http.StatusFound)
				return
			}

			idToken, err := provider.verifier.Verify(
				request.Context(),
				cookie.Value,
			)
			if err != nil {
				if logger.Limit.Allow() {
					log.Printf("%s: Failed OIDC verification: %v\n", request.RemoteAddr, err)
				}
				http.Redirect(response, request, UserLogin, http.StatusFound)
				return
			}

			var claims UserClaims

			err = idToken.Claims(&claims)
			if err != nil {
				if logger.Limit.Allow() {
					log.Printf("%s: Failed parsing claims: %v\n", request.RemoteAddr, err)
				}
				http.Redirect(response, request, UserLogin, http.StatusFound)
				return
			}
			claims.Email = strings.ToLower(claims.Email)

			ctx := context.WithValue(
				request.Context(),
				CtxKeyUserInfo,
				claims,
			)

			next.ServeHTTP(response, request.WithContext(ctx))
		})
	}
}
