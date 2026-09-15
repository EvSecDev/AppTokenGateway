package server

import (
	"ATG/internal/config"
	"ATG/internal/sso"
	"ATG/internal/tokenstore"
	"net/http"
)

type Server struct {
	cfg      *config.JSONConfig
	store    *tokenstore.RuntimeStore
	provider *sso.OIDCProvider
	http     *http.Server
}
