package server

import (
	"ATG/internal/logger"
	"ATG/internal/sso"
	"log"
	"net/http"
)

// Central redirector to OIDC provider login page
func LoginHandler(provider *sso.OIDCProvider) (handler http.HandlerFunc) {
	handler = func(response http.ResponseWriter, request *http.Request) {
		redirURL, cookie, err := provider.PrepareOIDCRedirect()
		if err != nil {
			if logger.Limit.Allow() {
				log.Printf("%s: %v\n", clientAddr(request), err)
			}
			http.Error(response, "Failed to prepare login redirect", http.StatusInternalServerError)
			return
		}

		// Redirect to OIDC provider with state
		http.SetCookie(response, cookie)
		http.Redirect(response, request, redirURL, http.StatusFound)
	}
	return
}

// Handles the callback from the OIDC provider
func CallbackHandler(provider *sso.OIDCProvider) (handler http.HandlerFunc) {
	handler = func(response http.ResponseWriter, request *http.Request) {
		cookies, status, err := provider.VerifyCallback(request)
		for _, cookie := range cookies {
			http.SetCookie(response, cookie)
		}
		if err != nil {
			if logger.Limit.Allow() && status == http.StatusInternalServerError {
				log.Printf("Failed to verify OIDC callback: %v\n", err)
			}
			http.Error(response, "Failed to verify OIDC callback", status)
			return
		}
		http.Redirect(response, request, UserIntfPath, http.StatusSeeOther)
	}
	return
}
