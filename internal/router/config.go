package router

import (
	"crypto/tls"
	"fmt"
	"io/ioutil"
	"path/filepath"

	"ntsc.ac.cn/ta-registry/pkg/rpc"
	"ntsc.ac.cn/ta-registry/pkg/secure"
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

// GetTlsConfig get grpc service tls config
func (c *Config) GetTlsConfig(machineID string) (*tls.Config, error) {
	certPath, err := filepath.Abs(c.CertPath)
	if err != nil {
		return nil, fmt.Errorf("read certificate path failed: %s", err.Error())
	}
	trustedPath := certPath + string(filepath.Separator) + TRUSTED_CERT_CHAIN_NAME
	clientCertPath := certPath + string(filepath.Separator) + CLIENT_CERT_NAME
	privKeyPath := certPath + string(filepath.Separator) + CLIENT_PRIVATE_KEY_NAME
	trusted, err := ioutil.ReadFile(trustedPath)
	if err != nil {
		return nil, fmt.Errorf(
			"read truested certificate chain failed: %s", err.Error())
	}
	cert, err := ioutil.ReadFile(clientCertPath)
	if err != nil {
		return nil, fmt.Errorf(
			"read client certificate failed: %s", err.Error())
	}
	clientCert, err := secure.PEMToX509Certificate(cert)
	if err != nil {
		return nil, fmt.Errorf(
			"parse client certificate pem data failed: %s", err.Error())
	}
	certMachineID, err := secure.GetCertExtValue(clientCert, CERT_EXT_KEY_MACHINE_ID)
	if err != nil {
		return nil, fmt.Errorf(
			"not found machine id from certificate")
	}
	if machineID != certMachineID {
		return nil, fmt.Errorf("machine id does not match")
	}
	privKey, err := ioutil.ReadFile(privKeyPath)
	if err != nil {
		return nil, fmt.Errorf(
			"read client certificate private key failed: %s", err.Error())
	}
	tlsConf, err := rpc.NewClientTLSConfig(&rpc.ClientTLSConfig{
		CACert:     trusted,
		Cert:       cert,
		PrivKey:    privKey,
		ServerName: c.ServerName,
	})
	if err != nil {
		return nil, fmt.Errorf("generate tls config failed: %s", err.Error())
	}
	return tlsConf, nil
}
