package config

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
)

// Creates a sample configuration at specified path
func CreateTemplate(cfgPath string) (err error) {
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
			RedirectURL:  "https://myapp.example.com/callback",
			Scope:        []string{""},
		},
		TokenHeaders: []string{"Authorization"},
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
