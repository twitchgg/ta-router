package router

import (
	"fmt"
	"net/url"

	"github.com/sirupsen/logrus"
	"ntsc.ac.cn/ta-router/pkg/iptables"
	"ntsc.ac.cn/ta-router/pkg/tools"
	"ntsc.ac.cn/ta-router/pkg/wireguard"
)

func (r *WireguardRouter) checkEnvs() (err error) {
	if r.wireguard, err = wireguard.NewWireguardTools(
		r.conf.WireguardPath, r.conf.WireguardToolsPath); err != nil {
		return fmt.Errorf("check wireguard tools failed: %s", err.Error())
	}
	logrus.WithField("prefix", "router.check_envs").
		Infof("check wireguard environment success")
	if r.iptables, err = iptables.NewIPTables(
		r.conf.IPTablesPath, r.conf.IPSetPath); err != nil {
		return fmt.Errorf("check iptables and ipset failed: %s", err.Error())
	}
	logrus.WithField("prefix", "router.check_envs").
		Infof("check iptables environment success")
	pingAddr, _ := url.Parse(r.conf.ManagerEndpoint)
	if rtt, err := tools.Ping(pingAddr.Hostname()); err != nil {
		return fmt.Errorf("check internet failed: %s", err.Error())
	} else {
		logrus.WithField("prefix", "router.check_envs").
			Infof("check internet success,ping addr [%s] counter [%d] rtt avg [%s]",
				pingAddr.Hostname(), tools.DEFAULT_PING_COUNT, rtt)
	}
	return nil
}
