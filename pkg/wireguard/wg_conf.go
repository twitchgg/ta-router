package wireguard

import (
	"fmt"
	"io"
	"io/ioutil"
	"strconv"
	"strings"
)

// ServerListenerConfig server
type ServerListenerConfig struct {
	Address       string
	Port          int
	PrivKey       string
	MasqueradeEth string
	DNS           string
}

// EndpointConf wireguard endpoint config
type EndpointConf struct {
	Address  string
	Port     int
	PrivKey  string
	PostUp   string
	PostDown string
}

// PeerConfig wireguard peer config
type PeerConfig struct {
	PublicKey    string
	PresharedKey string
	AllowedIPs   string
	Commit       string
}

// NewEndpointConfig new wireguard endpoint config
func NewEndpointConfig(w io.Writer, conf *ServerListenerConfig) error {
	var aBuf strings.Builder
	aBuf.WriteString("[Interface]\n")
	aBuf.WriteString("Address = " + conf.Address + "\n")
	aBuf.WriteString("ListenPort = " + strconv.Itoa(conf.Port) + "\n")
	aBuf.WriteString("PrivateKey = " + conf.PrivKey + "\n")
	if conf.MasqueradeEth != "" {
		var postUpBuf strings.Builder
		postUpBuf.WriteString("iptables -A FORWARD -i %i -j ACCEPT; ")
		postUpBuf.WriteString("iptables -A FORWARD -o %i -j ACCEPT; ")
		postUpBuf.WriteString("iptables -t nat -A POSTROUTING -o " +
			conf.MasqueradeEth +
			" -j MASQUERADE")
		aBuf.WriteString("PostUp = " + postUpBuf.String() + "\n")
		var postDownBuf strings.Builder
		postDownBuf.WriteString("iptables -D FORWARD -i %i -j ACCEPT; ")
		postDownBuf.WriteString("iptables -D FORWARD -o %i -j ACCEPT; ")
		postDownBuf.WriteString("iptables -t nat -D POSTROUTING -o " +
			conf.MasqueradeEth +
			" -j MASQUERADE")
		aBuf.WriteString("PostDown = " + postDownBuf.String() + "\n")
	}
	if conf.DNS != "" {
		aBuf.WriteString("DNS = " + conf.DNS + "\n")
	}
	_, err := w.Write([]byte(aBuf.String()))
	return err
}

// AddPeersConfig add wireguard peer config
func AddPeersConfig(rw io.ReadWriter, peers []*PeerConfig) error {
	if rw == nil {
		return fmt.Errorf("config source is nil")
	}
	data, err := ioutil.ReadAll(rw)
	rw.Write(data)
	rw.Write([]byte("\n"))
	if err != nil {
		return fmt.Errorf("read config failed: %s", err.Error())
	}
	if len(peers) == 0 {
		return fmt.Errorf("no peers")
	}
	for _, p := range peers {
		var sb strings.Builder
		sb.WriteString("[Peer]\n")
		if p.Commit != "" {
			sb.WriteString("# " + p.Commit + "\n")
		}
		sb.WriteString("PublicKey = " + p.PublicKey + "\n")
		sb.WriteString("PresharedKey = " + p.PresharedKey + "\n")
		sb.WriteString("AllowedIPs = " + p.AllowedIPs + "\n\n")
		rw.Write([]byte(sb.String()))
	}
	return nil
}
