package router

import (
	"fmt"

	"github.com/denisbrodbeck/machineid"
	"ntsc.ac.cn/ta-registry/pkg/pb"
	"ntsc.ac.cn/ta-registry/pkg/rpc"
	"ntsc.ac.cn/ta-router/pkg/iptables"
	"ntsc.ac.cn/ta-router/pkg/wireguard"
)

// WireguardRouter wireguard router
type WireguardRouter struct {
	conf      *Config
	rsc       pb.RegistryServiceClient
	machineID string
	wireguard *wireguard.WireguardTools
	iptables  *iptables.IPTables
}

// NewWireguardRouter create wireguard router
func NewWireguardRouter(conf *Config) (*WireguardRouter, error) {
	if conf == nil {
		return nil, fmt.Errorf("rpc server config is not define")
	}
	machineID, err := machineid.ID()
	if err != nil {
		return nil, fmt.Errorf("generate machine id failed: %s", err.Error())
	}
	if err := conf.Check(); err != nil {
		return nil, fmt.Errorf("check config failed: %s", err.Error())
	}
	tlsConf, err := conf.GetTlsConfig(machineID)
	if err != nil {
		return nil, fmt.Errorf("generate tls config failed: %s", err.Error())
	}
	conn, err := rpc.DialRPCConn(&rpc.DialOptions{
		RemoteAddr: conf.ManagerEndpoint,
		TLSConfig:  tlsConf,
	})
	if err != nil {
		return nil, fmt.Errorf(
			"dial management grpc connection failed: %s", err.Error())
	}
	return &WireguardRouter{
		conf:      conf,
		machineID: machineID,
		rsc:       pb.NewRegistryServiceClient(conn),
	}, nil
}

// Start start wireguard router
func (r *WireguardRouter) Start() chan error {
	errChan := make(chan error, 1)
	if err := r.checkEnvs(); err != nil {
		errChan <- err
		return errChan
	}
	if err := r.initWireguard(); err != nil {
		errChan <- fmt.Errorf("init wireguard service failed: %s", err.Error())
		return errChan
	}
	return errChan
}
