package sso

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"net/http"
	"strings"
	"time"
)

const (
	IdentityCookie string = "id_token"
	StateCookie    string = "oidc_state"
	CtxKeyUserInfo string = "user"
)

// Prepares redirect to the configured OIDC provider login with secure cookie.
func (provider OIDCProvider) PrepareOIDCRedirect() (redirectURL string, cookie *http.Cookie, err error) {
	// Generate a random state
	stateBytes := make([]byte, 32)
	_, err = rand.Read(stateBytes)
	if err != nil {
		err = fmt.Errorf("random state generation error: %w", err)
		return
	}
	state := base64.URLEncoding.EncodeToString(stateBytes)

	// Store state in a secure, HttpOnly cookie
	cookie = &http.Cookie{
		Name:     StateCookie,
		Value:    state,
		Path:     "/",
		HttpOnly: true,
		Secure:   true,
		SameSite: http.SameSiteStrictMode,
		MaxAge:   300, // valid for 5 minutes
	}

	redirectURL = provider.config.AuthCodeURL(state)
	return
}

// Verifies the callback from the OIDC provider.
// Cookies should always be set on the response regardless of error.
func (provider OIDCProvider) VerifyCallback(request *http.Request) (cookies []*http.Cookie, status int, err error) {
	code := request.URL.Query().Get("code")
	if code == "" {
		err = fmt.Errorf("no code in request")
		status = http.StatusBadRequest
		return
	}

	returnedState := request.URL.Query().Get("state")
	stateCookie, err := request.Cookie(StateCookie)
	if err != nil || returnedState != stateCookie.Value {
		err = fmt.Errorf("invalid state parameter: %w", err)
		status = http.StatusBadRequest
		return
	}

	// Delete state cookie after verification
	cookies = append(cookies, &http.Cookie{
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
		err = fmt.Errorf("Failed to exchange token with provider: %w", err)
		status = http.StatusInternalServerError
		return
	}

	rawIDToken, ok := token.Extra(IdentityCookie).(string)
	if !ok {
		detailErr := fmt.Errorf("oauth2 token response missing field id_token")
		err = fmt.Errorf("missing provider response field: %w", detailErr)
		status = http.StatusInternalServerError
		return
	}

	idToken, err := provider.verifier.Verify(ctx, rawIDToken)
	if err != nil {
		err = fmt.Errorf("failed to verify ID token: %w", err)
		status = http.StatusInternalServerError
		return
	}

	cookies = append(cookies, &http.Cookie{
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
		err = fmt.Errorf("failed to parse claims: %w", err)
		status = http.StatusInternalServerError
		return
	}
	return
}

// Middleware to check if the incoming request is authorized against the OIDC provider.
// Also sets user claims inside the request context.
func (provider OIDCProvider) IsRequestAuthorized(request *http.Request) (reqWithCtx *http.Request, err error) {
	cookie, err := request.Cookie(IdentityCookie)
	if err != nil {
		err = fmt.Errorf("cookie retrieval: %w", err)
		return
	}

	idToken, err := provider.verifier.Verify(
		request.Context(),
		cookie.Value,
	)
	if err != nil {
		err = fmt.Errorf("verification failed: %w", err)
		return
	}

	var claims UserClaims

	err = idToken.Claims(&claims)
	if err != nil {
		err = fmt.Errorf("failed parsing claims: %w", err)
		return
	}
	claims.Email = strings.ToLower(claims.Email)

	ctx := context.WithValue(
		request.Context(),
		CtxKeyUserInfo,
		claims,
	)
	reqWithCtx = request.WithContext(ctx)
	return
}
