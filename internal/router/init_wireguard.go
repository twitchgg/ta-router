package router

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/sirupsen/logrus"
	"google.golang.org/protobuf/types/known/timestamppb"
	"ntsc.ac.cn/ta-registry/pkg/pb"
	"ntsc.ac.cn/ta-router/pkg/rexec"
)

func (r *WireguardRouter) initWireguard() error {
	ctx, cancel := context.WithTimeout(context.Background(), time.Second*5)
	defer cancel()
	conf, err := r.rsc.RegistRouter(ctx, &pb.RegistRouterRequest{
		MachineID: r.machineID,
		SysTime:   timestamppb.Now(),
	})
	if err != nil {
		return err
	}
	wanInfo := conf.WanInfo
	if err = _initWanNet(wanInfo); err != nil {
		return err
	}
	if err = _replaceDNS(conf.DnsServer); err != nil {
		return err
	}
	return nil
}

func _initWanNet(wanInfo *pb.EthernetCard) error {
	if wanInfo.DhcpClient != "" {
		e, err := rexec.NewExecuter("dhclient", "dhclient", []string{wanInfo.Name})
		if err != nil {
			return fmt.Errorf("create dhclient failed: %s", err.Error())
		}
		er := <-e.Start()
		if er.Error != nil {
			return fmt.Errorf("create dhclient failed: %s", err.Error())
		}
	} else {
		if err := _initEthernet(
			wanInfo.Name, wanInfo.Addresses, wanInfo.Gateway); err != nil {
			return fmt.Errorf(
				"init ethernet [%s]failed: %s", wanInfo.Name, err.Error())
		}
	}
	return nil
}

func _replaceDNS(dns []string) error {
	if len(dns) > 0 {
		dnsArrays := make([]string, 0)
		for _, ip := range dns {
			dnsArrays = append(dnsArrays, "nameserver "+ip)
			dnsStr := strings.Join(dnsArrays, "\n")
			cmd, err := rexec.NewExecuter("dns", "bash", []string{
				"-c", fmt.Sprintf("echo -e '%s' > /etc/resolv.conf", dnsStr),
			})
			if err != nil {
				return fmt.Errorf("create replace dns script failed: %s", err.Error())
			}
			res := <-cmd.Start()
			if res.Error != nil {
				return fmt.Errorf("replace dns failed: %s", res.Error.Error())
			}
		}
	}
	logrus.WithField("prefix", "wireguard").Infof(
		"replace dns servers [%s] success", dns)
	return nil
}

func _initEthernet(name string, ips []string, gw string) error {
	cmd, err := rexec.NewExecuter("ip", "ip", []string{"addr", "flush", "dev", name})
	if err != nil {
		return fmt.Errorf("create ip tools failed: %s", err.Error())
	}
	res := <-cmd.Start()
	if res.Error != nil {
		return fmt.Errorf("flush ip failed: %s", res.Error.Error())
	}
	logrus.WithField("prefix", "wireguard").Infof(
		"flush dev [%s] ip success", name)
	for _, ip := range ips {
		if cmd, err = rexec.NewExecuter("ip", "ip",
			[]string{"addr", "add", ip, "dev", name}); err != nil {
			return fmt.Errorf("create ip tools failed: %s", err.Error())
		}
		if res = <-cmd.Start(); res.Error != nil {
			return fmt.Errorf("dev [%s] add ip [%s] failed: %s",
				name, ip, res.Error.Error())
		}
		logrus.WithField("prefix", "wireguard").Infof(
			"dev [%s] add ip [%s] success", name, ip)
	}
	if cmd, err = rexec.NewExecuter("ip", "ip",
		[]string{"route", "add", "default", "via",
			gw, "dev", name}); err != nil {
		return fmt.Errorf("create ip tools failed: %s", err.Error())
	}
	if res = <-cmd.Start(); res.Error != nil {
		return fmt.Errorf("add default gateway [%s] dev [%s] failed: %s",
			gw, name, res.Error.Error())
	}
	logrus.WithField("prefix", "wireguard").Infof(
		"dev [%s] add default gateway [%s] success", name, gw)
	return nil
}
