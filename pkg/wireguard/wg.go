package wireguard

import (
	"bufio"
	"fmt"
	"io"
	"strconv"
	"strings"
	"time"

	"ntsc.ac.cn/ta-router/pkg/rexec"
)

type ShowType int

const (
	SHOW_TYPE_UNKNOW ShowType = iota
	SHOW_TYPE_PUB_KEY
	SHOW_TYPE_PRIV_KEY
	SHOW_TYPE_LISTEN_PORT
	SHOW_TYPE_FWMARK
	SHOW_TYPE_PEERS
	SHOW_TYPE_PRESHARED_KEY
	SHOW_TYPE_ENDPOINTS
	SHOW_TYPE_ALLOWED_IPS
	SHOW_TYPE_LATEST_HANDSHAKES
	SHOW_TYPE_TRANSFER
	SHOW_TYPE_PERSISTENT_KEEPALIVE
	SHOW_TYPE_DUMP
)

// String show type to string
func (st ShowType) String() string {
	switch st {
	case SHOW_TYPE_PUB_KEY:
		return "public-key"
	case SHOW_TYPE_PRIV_KEY:
		return "private-key"
	case SHOW_TYPE_LISTEN_PORT:
		return "listen-port"
	case SHOW_TYPE_FWMARK:
		return "fwmark"
	case SHOW_TYPE_PEERS:
		return "peers"
	case SHOW_TYPE_PRESHARED_KEY:
		return "preshared-keys"
	case SHOW_TYPE_ENDPOINTS:
		return "endpoints"
	case SHOW_TYPE_ALLOWED_IPS:
		return "allowed-ips"
	case SHOW_TYPE_LATEST_HANDSHAKES:
		return "latest-handshakes"
	case SHOW_TYPE_TRANSFER:
		return "transfer"
	case SHOW_TYPE_PERSISTENT_KEEPALIVE:
		return "persistent-keepalive"
	case SHOW_TYPE_DUMP:
		return "dump"
	default:
		return "unknow"
	}
}

// EndpointInfo wireguard endpoint information
type EndpointInfo struct {
	PublicKey  string
	PrivateKey string
	ListenPort int
	Fwmark     string
}

// ShowInterfaces show wireguard inerfaces name
func (wt *WireguardTools) ShowInterfaces() ([]string, error) {
	exe, err := rexec.NewExecuter("wg_show_inerfaces",
		wt.wgPath, []string{"show", "interfaces"})
	if err != nil {
		return nil, fmt.Errorf(
			"show wireguard interfaces info failed: %s", err.Error())
	}
	result, err := exe.Run()
	if err != nil {
		return nil, fmt.Errorf(
			"show wireguard inerfaces info failed: %s", result)
	}
	interfaces := make([]string, 0)
	r := bufio.NewReader(strings.NewReader(result))
	for {
		l, _, err := r.ReadLine()
		if err != nil {
			if err == io.EOF {
				break
			}
			return nil, fmt.Errorf(
				"show wireguard endpoint info failed: %s", err.Error())
		}
		interfaces = append(interfaces, string(l))
	}
	return interfaces, nil
}

// ShowDump show wireguard inerfaces dump
func (wt *WireguardTools) ShowDump(dev string) (string, error) {
	exe, err := rexec.NewExecuter("wg_dump",
		wt.wgPath, []string{"show", dev, "dump"})
	if err != nil {
		return "", fmt.Errorf(
			"show wireguard endpoint info failed: %s", err.Error())
	}
	result, err := exe.Run()
	if err != nil {
		return "", fmt.Errorf(
			"show wireguard endpoint info failed: %s", result)
	}
	return result, nil

}

// ShowEndpoints show wireguard endpoint information
func (wt *WireguardTools) ShowEndpoints(dev string) (*EndpointInfo, error) {
	result, err := wt.ShowDump(dev)
	if err != nil {
		return nil, fmt.Errorf(
			"dump wireguard info with dev [%s]failed: %s", dev, result)
	}
	r := bufio.NewReader(strings.NewReader(result))
	l, _, err := r.ReadLine()
	if err != nil {
		return nil, fmt.Errorf(
			"show wireguard endpoint info failed: %s", err.Error())
	}
	parts := strings.Split(string(l), "	")
	if len(parts) != 4 {
		return nil, fmt.Errorf("read endpoint info size failed [%d]", len(parts))
	}
	port, err := strconv.Atoi(parts[2])
	if err != nil {
		return nil, fmt.Errorf("read endpoint port failed: [%s]", err.Error())
	}
	return &EndpointInfo{
		PrivateKey: parts[0],
		PublicKey:  parts[1],
		ListenPort: port,
		Fwmark:     parts[3],
	}, nil
}

// PeerInfo wireguard peer information
type PeerInfo struct {
	PublicKey        string
	PresharedKey     string
	Endpoints        string
	AllowedIPs       []string
	LatestHandshake  time.Duration
	TransferReceived int
	TransferSent     int
}

// ShowPeers show wireguard peer information
func (wt *WireguardTools) ShowPeers(dev string) ([]*PeerInfo, error) {
	result, err := wt.ShowDump(dev)
	if err != nil {
		return nil, fmt.Errorf(
			"dump wireguard info with dev [%s]failed: %s", dev, result)
	}
	r := bufio.NewReader(strings.NewReader(result))
	peers := make([]*PeerInfo, 0)
	for {
		l, _, err := r.ReadLine()
		if err != nil {
			if err == io.EOF {
				break
			}
			return nil, fmt.Errorf(
				"show wireguard endpoint info failed: %s", err.Error())
		}
		parts := strings.Split(string(l), "	")
		if len(parts) != 8 {
			continue
		}
		allowedIPs := strings.Split(parts[3], ",")
		ltd, err := strconv.Atoi(parts[4])
		if err != nil {
			return nil, fmt.Errorf("parse latest handshake time failed: %s", err.Error())
		}
		lhsd := time.Duration(0)
		if ltd != 0 {
			lhsd = time.Since(time.Unix(int64(ltd), 0))
		}
		tr, err := strconv.Atoi(parts[5])
		if err != nil {
			return nil, fmt.Errorf("parse transfer received failed: %s", err.Error())
		}
		ts, err := strconv.Atoi(parts[6])
		if err != nil {
			return nil, fmt.Errorf("parse transfer sent failed: %s", err.Error())
		}
		peers = append(peers, &PeerInfo{
			PublicKey:        parts[0],
			PresharedKey:     parts[1],
			Endpoints:        parts[2],
			AllowedIPs:       allowedIPs,
			LatestHandshake:  lhsd,
			TransferReceived: tr,
			TransferSent:     ts,
		})
	}
	return peers, nil
}
