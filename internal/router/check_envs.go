package router

import (
	"fmt"
	"net/url"

	"github.com/sirupsen/logrus"
	"golang.zx2c4.com/wireguard/wgctrl"
	"ntsc.ac.cn/ta-router/pkg/iptables"
	"ntsc.ac.cn/ta-router/pkg/iptools"
	"ntsc.ac.cn/ta-router/pkg/tools"
	"ntsc.ac.cn/ta-router/pkg/wireguard"
)

func (r *WireguardRouter) checkEnvs() (err error) {
	if r.wireguard, err = wireguard.NewWireguardTools(
		r.conf.WireguardPath, r.conf.WireguardToolsPath, r.conf.IPToolsPath); err != nil {
		return fmt.Errorf("check wireguard tools failed: %v", err)
	}

	if r.wgctl, err = wgctrl.New(); err != nil {
		return fmt.Errorf("check wireguard ctrl client failed: %v", err)
	}
	if r.ipTools, err = iptools.NewIPTools(r.conf.IPToolsPath); err != nil {
		return fmt.Errorf("check ip tools failed: %v", err)
	}
	logrus.WithField("prefix", "router.check_envs").
		Infof("check wireguard environment success")
	if r.iptables, err = iptables.NewIPTables(
		r.conf.IPTablesPath, r.conf.IPSetPath); err != nil {
		return fmt.Errorf("check iptables and ipset failed: %v", err)
	}
	logrus.WithField("prefix", "router.check_envs").
		Infof("check iptables environment success")
	pingAddr, _ := url.Parse(r.conf.ManagerEndpoint)
	if rtt, err := tools.Ping(pingAddr.Hostname()); err != nil {
		return fmt.Errorf("check internet failed: %v", err)
	} else {
		logrus.WithField("prefix", "router.check_envs").
			Infof("check internet success,ping addr [%s] counter [%d] rtt avg [%s]",
				pingAddr.Hostname(), tools.DEFAULT_PING_COUNT, rtt)
	}
	return nil
}
