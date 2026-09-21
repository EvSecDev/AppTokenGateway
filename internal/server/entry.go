package server

import (
	"ATG/internal/config"
	"ATG/internal/sso"
	"ATG/internal/tokenstore"
	"context"
	"embed"
	"fmt"
	"io/fs"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"time"

	"golang.org/x/sys/unix"
)

// Read in web static files at compile time
//
//go:embed static-files/*
var webFiles embed.FS

const (
	UserIntfPath    string = "/atgui"
	UserLoginPath   string = "/login"
	CallbackPath    string = "/callback"
	TokenAuthPath   string = "/auth"
	TokenRegPath    string = "/register"
	TokenRevokePath string = "/revoke"
	TokenListPath   string = "/tokens"
)

// Create a new server instance
func New(configPath string) (server *Server, err error) {
	server = &Server{}

	server.cfg, err = config.Load(configPath)
	if err != nil {
		err = fmt.Errorf("config: %w", err)
		return
	}

	server.store, err = tokenstore.New(server.cfg.KeyStorePath, server.cfg.TokenHeaders)
	if err != nil {
		err = fmt.Errorf("token store load: %w", err)
		return
	}

	server.provider, err = sso.NewOIDCProvider(&server.cfg.OIDC)
	if err != nil {
		err = fmt.Errorf("oidc initialization: %w", err)
		return
	}
	return
}

// Construct all handlers and paths for the http server configuration
func (server *Server) SetupHTTP() (err error) {
	staticFS, err := fs.Sub(webFiles, "static-files")
	if err != nil {
		err = fmt.Errorf("embedfs error: %w", err)
		return
	}

	mux := http.NewServeMux()

	// Public - no OIDC required
	mux.HandleFunc(UserLoginPath, LoginHandler(server.provider))   // Sends user at first browse to the OIDC provider
	mux.HandleFunc(CallbackPath, CallbackHandler(server.provider)) // Redirect location back from OIDC provider after login

	// Public - API Token required (in header)
	mux.HandleFunc(TokenAuthPath, TokenAuthHandler(server.store)) // Endpoint for proxy to validate all requests

	// Private - User authentication (SSO) required
	ssoAuthRequired := RequireAuthenticated(server.provider)
	mux.Handle(TokenRegPath, ssoAuthRequired(RegisterHandler(server.store)))      // API for user registering new token
	mux.Handle(TokenRevokePath, ssoAuthRequired(RevocationHandler(server.store))) // API for user revoking existing token
	mux.Handle(TokenListPath, ssoAuthRequired(ListHandler(server.store)))         // API for user listing existing tokens

	// Delivering html/css/js to user
	fileServer := http.FileServer(http.FS(staticFS))
	mux.Handle(
		UserIntfPath+"/",
		ssoAuthRequired(
			http.StripPrefix(UserIntfPath, fileServer),
		),
	)

	log.Printf("Token authorizations : %s\n", TokenAuthPath)
	log.Printf("Token registrations  : %s\n", TokenRegPath)
	log.Printf("Token revocations    : %s\n", TokenRevokePath)
	log.Printf("Token list           : %s\n", TokenListPath)
	log.Printf("User interface       : %s\n", UserIntfPath)

	server.http = &http.Server{
		Handler:      mux,
		ReadTimeout:  10 * time.Second,
		WriteTimeout: 10 * time.Second,
		IdleTimeout:  5 * time.Second,
	}
	return
}

// Run the HTTP listener and handle program lifecycle
func (server *Server) Run() (err error) {
	socket, err := server.cfg.CreateListenAddress()
	if err != nil {
		return
	}
	server.http.Addr = socket.String()

	if server.cfg.TLSEnabled() {
		log.Printf("Auth server starting at https://%s\n", server.http.Addr)
	} else {
		log.Printf("Auth server starting at http://%s\n", server.http.Addr)
	}

	// Listener started in background
	errCh := make(chan error, 2)
	go backgroundListener(server.http, server.cfg, errCh)

	// Foreground signal handler to ensure file writes finish before shutdown
	sigChan := make(chan os.Signal, 4)
	signal.Notify(sigChan, unix.SIGINT, unix.SIGQUIT, unix.SIGTERM, unix.SIGHUP)
	for {
		// Block waiting for signals or listener error
		select {
		case sig := <-sigChan:
			fmt.Printf("\nShutting down, received signal: %v\n", sig)

			// Lock the auth mutex - success means no writes occurring so safe to shutdown.
			//  Otherwise we block until we can hold the lock and then safely shutdown
			server.store.HaltTokenWrites()

			shutdownCtx, cancel := context.WithDeadline(context.Background(), time.Now().Add(15*time.Second))
			defer cancel()
			server.http.Shutdown(shutdownCtx)
			return
		case err = <-errCh:
			return
		}
	}
}

func backgroundListener(server *http.Server, cfg *config.JSONConfig, errCh chan error) {
	tcpSocket, err := net.Listen("tcp", server.Addr)
	if err != nil {
		errCh <- fmt.Errorf("tcp socket: %w", err)
		return
	}

	if cfg.TLSCert != "" {
		err = server.ServeTLS(tcpSocket, cfg.TLSCert, cfg.TLSKey)
	} else {
		err = server.Serve(tcpSocket)
	}
	if err != nil {
		if err == http.ErrServerClosed {
			log.Printf("HTTP server shut down cleanly")
		} else {
			errCh <- fmt.Errorf("listener: %v\n", err)
		}
		return
	}
}
