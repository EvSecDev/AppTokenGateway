package main

import (
	"context"
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

func httpListener(configPath string) (err error) {
	config, err := LoadConfig(configPath)
	if err != nil {
		err = fmt.Errorf("config: %w", err)
		return
	}

	staticFS, err := fs.Sub(webFiles, "static-files")
	if err != nil {
		err = fmt.Errorf("embedfs error: %w", err)
		return
	}

	fullAddr := net.JoinHostPort(config.Static.ListenAddress, config.Static.ListenPort)
	socket, err := net.ResolveTCPAddr("tcp", fullAddr)
	if err != nil {
		err = fmt.Errorf("failed address resolution for listen socket %q: %w", fullAddr, err)
		return
	}

	verifier, err := config.InitOIDCProvider()
	if err != nil {
		err = fmt.Errorf("oidc initialization: %w", err)
		return
	}

	mux := http.NewServeMux()

	// Public - no OIDC required
	mux.HandleFunc(UserLogin, LoginHandler(config))                 // Sends user at first browse to the OIDC provider
	mux.HandleFunc(OIDCCallback, CallbackHandler(config, verifier)) // Redirect location back from OIDC provider after login

	// Public - API Token required (in header)
	mux.HandleFunc(TokenAuthPath, AuthHandler(config)) // Endpoint for proxy to validate all requests

	// Private - User authentication required
	mux.Handle(TokenRegPath, RequireOIDC(config, verifier)(RegisterHandler(config)))        // API for user registering new token through client javascript
	mux.Handle(UserIntf, RequireOIDC(config, verifier)(http.FileServer(http.FS(staticFS)))) // Delivering html/css/js to user

	server := &http.Server{
		Addr:         socket.String(),
		Handler:      mux,
		ReadTimeout:  10 * time.Second,
		WriteTimeout: 10 * time.Second,
		IdleTimeout:  5 * time.Second,
	}

	if config.TLSEnabled {
		log.Printf("Auth server starting at https://%s\n", socket.String())
	} else {
		log.Printf("Auth server starting at http://%s\n", socket.String())
	}
	log.Printf("Token authorizations : %s\n", TokenAuthPath)
	log.Printf("Token registrations  : %s\n", TokenRegPath)
	log.Printf("User interface       : %s\n", UserIntf)

	// Listener started in background
	errCh := make(chan error, 2)
	go backgroundListener(server, config, errCh)

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
			config.AuthMutex.Lock()

			shutdownCtx, cancel := context.WithDeadline(context.Background(), time.Now().Add(15*time.Second))
			defer cancel()
			server.Shutdown(shutdownCtx)
			return
		case err = <-errCh:
			return
		}
	}
}

func backgroundListener(server *http.Server, config *RuntimeConfig, errCh chan error) {
	tcpSocket, err := net.Listen("tcp", server.Addr)
	if err != nil {
		errCh <- fmt.Errorf("tcp socket: %w", err)
		return
	}

	if config.TLSEnabled {
		err = server.ServeTLS(tcpSocket, config.Static.TLSCert, config.Static.TLSKey)
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
