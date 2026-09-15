package config

import (
	"fmt"
	"log"
	"net"
)

const (
	DefaultAddress string = "localhost"
	DefaultPort    string = "8080"
)

// Loads the configuration from provided file
func Load(cfgPath string) (config *JSONConfig, err error) {
	log.Printf("Loading configuration file from '%s'\n", cfgPath)

	config, err = loadJSONConfig(cfgPath)
	if err != nil {
		return
	}
	err = validateJSONConfig(config)
	if err != nil {
		return
	}

	if config.TLSEnabled() {
		log.Printf("Warning: no TLS files specified, defaulting to unencrypted HTTP listener. This is an insecure configuration.\n")
	}
	return
}

// Uses the config listen ip and port from the config to create a full listen address
func (config *JSONConfig) CreateListenAddress() (address net.Addr, err error) {
	fullAddr := net.JoinHostPort(config.ListenAddress, config.ListenPort)
	socket, err := net.ResolveTCPAddr("tcp", fullAddr)
	if err != nil {
		err = fmt.Errorf("failed address resolution for listen socket %q: %w", fullAddr, err)
		return
	}
	address = socket
	return
}

// Checks if TLS is enabled in the configuration
func (config *JSONConfig) TLSEnabled() (enabled bool) {
	if config.TLSCert != "" && config.TLSKey != "" {
		enabled = true
	}
	return
}
