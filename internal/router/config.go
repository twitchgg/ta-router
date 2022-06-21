package router

import (
	"fmt"
)

const (
	CERT_EXT_KEY_MACHINE_ID = "1.1.1.1.1.1"
	TRUSTED_CERT_CHAIN_NAME = "trusted.crt"
	CLIENT_CERT_NAME        = "client.crt"
	CLIENT_PRIVATE_KEY_NAME = "client.key"
)

// Config wireguard router config
type Config struct {
	CertPath           string
	ServerName         string
	ManagerEndpoint    string
	WireguardPath      string
	WireguardToolsPath string
	IPToolsPath        string
	IPTablesPath       string
	IPSetPath          string
}

// Check check wireguard router config
func (c *Config) Check() error {
	if c.CertPath == "" {
		return fmt.Errorf("certificate root path not define")
	}
	if c.ServerName == "" {
		return fmt.Errorf("service certificate server name not define")
	}
	if c.ManagerEndpoint == "" {
		return fmt.Errorf("management service endpoint not define")
	}
	return nil
}
