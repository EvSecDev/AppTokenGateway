package config

type JSONConfig struct {
	ListenPort    string     `json:"listen_port"`
	ListenAddress string     `json:"listen_address,omitempty"`
	TLSKey        string     `json:"tls_key_file,omitempty"`
	TLSCert       string     `json:"tls_cert_file,omitempty"`
	OIDC          OIDCConfig `json:"oidc_config"`
	TokenHeaders  []string   `json:"token_headers"`
	KeyStorePath  string     `json:"api_key_store"`
}

type OIDCConfig struct {
	Provider     string   `json:"provider"`
	ClientID     string   `json:"client_id"`
	ClientSecret string   `json:"client_secret"`
	RedirectURL  string   `json:"redirect_url"`
	Scope        []string `json:"scope"`
}
