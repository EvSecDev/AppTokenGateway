package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"os"
	"strings"
	"sync"
	"time"
)

// Loads the configuration from a file
func LoadConfig(cfgPath string) (config *RuntimeConfig, err error) {
	log.Printf("Loading configuration file from '%s'\n", cfgPath)

	config = &RuntimeConfig{
		AuthorizedKeys: make(map[string]bool),
		AuthMutex:      sync.RWMutex{},
	}

	cfg, err := loadJSONConfig(cfgPath)
	if err != nil {
		return
	}
	config.Static = *cfg
	err = validateJSONConfig(config.Static)
	if err != nil {
		return
	}

	if config.Static.TLSKey != "" {
		config.TLSEnabled = true
	} else {
		log.Printf("Warning: no TLS files specified, defaulting to unencrypted HTTP listener. This is an insecure configuration.\n")
	}

	// Unauth logging limit
	config.logLimiter = newLogLimiter(MaxLogsPerSecond, time.Second)

	log.Printf("Loading API key store file from '%s'\n", config.Static.KeyStorePath)

	authKeysFile, err := os.ReadFile(config.Static.KeyStorePath)
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		err = fmt.Errorf("failed to read key store file: %w", err)
		return
	}

	if errors.Is(err, os.ErrNotExist) {
		var emptyKeyMap AuthorizedTokens
		emptyKeyMap.UserKeys = make(map[string][]byte)

		var newKeyStore []byte
		newKeyStore, err = json.Marshal(emptyKeyMap)
		if err != nil {
			err = fmt.Errorf("failed to initialize new empty key map: %w", err)
			return
		}

		err = os.WriteFile(config.Static.KeyStorePath, newKeyStore, 0600)
		if err != nil {
			err = fmt.Errorf("failed to write new empty key map: %w", err)
			return
		}

		config.Auth = emptyKeyMap
	} else {
		err = json.Unmarshal(authKeysFile, &config.Auth)
		if err != nil {
			err = fmt.Errorf("failed to parse key store file: %w", err)
			return
		}

		config.AuthorizedKeys = reverseAuthKeysMap(config.Auth.UserKeys)
	}

	return
}

func loadJSONConfig(cfgPath string) (cfg *JSONConfig, err error) {
	data, err := os.ReadFile(cfgPath)
	if err != nil {
		return
	}
	err = json.Unmarshal(data, &cfg)
	if err != nil {
		return
	}
	return
}

func validateJSONConfig(cfg JSONConfig) (err error) {
	if cfg.ListenAddress == "" {
		cfg.ListenAddress = DefaultAddress
	}

	if !strings.HasPrefix(strings.ToLower(cfg.OIDC.Provider), "https://") {
		err = fmt.Errorf("oidc provider must have scheme 'https://'")
		return
	}

	if (cfg.TLSCert != "" && cfg.TLSKey == "") ||
		(cfg.TLSCert == "" && cfg.TLSKey != "") {
		err = fmt.Errorf("both tls_key_file and tls_cert_file must be specified")
		return
	}

	if cfg.KeyStorePath == "" {
		err = fmt.Errorf("missing key store file path")
		return
	}
	if cfg.ListenPort == "" {
		err = fmt.Errorf("listen port is empty")
		return
	}
	return
}

func reverseAuthKeysMap(userKeys map[string][]byte) (keyList map[string]bool) {
	keyList = make(map[string]bool, len(userKeys))
	for _, token := range userKeys {
		keyList[string(token)] = true
	}
	return
}

// Creates a sample configuration at specified path
func createTemplateConfig(cfgPath string) (err error) {
	_, err = os.Stat(cfgPath)
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		err = fmt.Errorf("failed to check existing config presence: %w", err)
		return
	}
	if err == nil {
		err = fmt.Errorf("existing configuration is present at %s: refusing to overwrite (please specify a different path)", cfgPath)
		return
	}

	templateCfg := &JSONConfig{
		ListenPort:    DefaultPort,
		ListenAddress: DefaultAddress,
		OIDC: OIDCConfig{
			Provider:     "https://sso.example.com/application/o/slug",
			ClientID:     "abcdefghijklmno",
			ClientSecret: "deadbeefdeadbeefdeadbeef",
			RedirectURL:  "https://myapp.example.com/token/new",
			Scope:        []string{""},
		},
		KeyStorePath: "/etc/ssl/authorized-api-keys.json",
	}

	newCfg, err := json.MarshalIndent(templateCfg, "", "  ")
	if err != nil {
		err = fmt.Errorf("failed marshal: %w", err)
		return
	}

	err = os.WriteFile(cfgPath, newCfg, 0640)
	if err != nil {
		err = fmt.Errorf("failed file write: %w", err)
		return
	}
	return
}
