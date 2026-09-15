package config

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"
)

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

func validateJSONConfig(cfg *JSONConfig) (err error) {
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
