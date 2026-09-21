package server

import (
	"ATG/internal/logger"
	"ATG/internal/sso"
	"ATG/internal/tokenstore"
	"errors"
	"log"
	"net/http"
)

// Handles the authentication request from Nginx
func TokenAuthHandler(store *tokenstore.RuntimeStore) (handler http.HandlerFunc) {
	handler = func(response http.ResponseWriter, request *http.Request) {
		rawToken, err := store.ExtractToken(request)
		if err != nil {
			if logger.Limit.Allow() {
				log.Printf("%s: %v\n", request.RemoteAddr, err)
			}
			http.Error(response, "Unauthorized", http.StatusUnauthorized)
			return
		}
		remoteAddr := clientAddr(request)

		isAuthorized, err := store.IsTokenAuthorized(rawToken)
		if err != nil {
			if logger.Limit.Allow() {
				log.Printf("%s: Request contained invalid token: %v\n", remoteAddr, err)
			}
			http.Error(response, "Forbidden", http.StatusForbidden)
			return
		}

		if !isAuthorized {
			if logger.Limit.Allow() {
				log.Printf("%s: Request contained an unknown token\n", remoteAddr)
			}
			http.Error(response, "Forbidden", http.StatusForbidden)
			return
		}
		response.WriteHeader(http.StatusOK)
	}
	return
}

// Creates new http middleware that requires every request passed through be authenticated by the OIDC provider.
func RequireAuthenticated(provider *sso.OIDCProvider) (authCheckFunc func(http.Handler) http.Handler) {
	authCheckFunc = func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
			requestWithCtx, err := provider.IsRequestAuthorized(request)
			if err != nil {
				// Log specific reason request was rejected (empty cookie is normal)
				if logger.Limit.Allow() && !errors.Is(err, http.ErrNoCookie) {
					log.Printf("%s: OIDC Authorization: %v\n", request.RemoteAddr, err)
				}

				// Always send user back to login page.
				http.Redirect(response, request, UserLoginPath, http.StatusFound)
				return
			}
			next.ServeHTTP(response, requestWithCtx)
		})
	}
	return
}
