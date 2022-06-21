package router

import (
	"context"
	"fmt"
	"net"
	"strings"
	"time"

	"github.com/sirupsen/logrus"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
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
	for _, wgconf := range conf.WgConfig {
		dev, err := r.wgctl.Device(wgconf.Name)
		if err != nil {
			if !strings.Contains(err.Error(), "not exist") {
				return fmt.Errorf("query wireguard interface [%s] failed: %v", wgconf.Name, err)
			}
		}
		wgIf := wgconf.InterfaceDef
		if wgIf == nil {
			return fmt.Errorf("wireguard interface [%s] not define", dev.Name)
		}
		if dev != nil {
			if err = r.wireguard.DelWireguardInterface(dev.Name); err != nil {
				return fmt.Errorf("delete interface [%s] failed: %v", dev.Name, err)
			}
			logrus.WithField("prefix", "wireguard").
				Infof("delete wireguard interface [%s] success", dev.Name)
		}
		if err = r.wireguard.AddWireguardInterface(wgconf.Name); err != nil {
			return err
		}
		logrus.WithField("prefix", "wireguard").
			Infof("add wireguard interface [%s] success", wgconf.Name)
		privKey, err := wgtypes.ParseKey(wgIf.PrivKey)
		if err != nil {
			return fmt.Errorf("parse wireguard private failed: %v", err)
		}
		lisPort := int(wgIf.Port)
		wgPeers := make([]wgtypes.PeerConfig, 0)
		allowsIPsArray := make([]string, 0)
		for _, wgPeer := range wgconf.Peers {
			pubKey, err := wgtypes.ParseKey(wgPeer.PubKey)
			if err != nil {
				return fmt.Errorf("parse wireguard public key failed: %v", err)
			}
			var psk *wgtypes.Key
			if wgPeer.PsKey != "" {
				if _psk, err := wgtypes.ParseKey(wgPeer.PsKey); err != nil {
					return fmt.Errorf("parse wireguard presharedkey failed: %v", err)
				} else {
					psk = &_psk
				}
			}
			var kad *time.Duration
			if wgPeer.Keepalive != 0 {
				wkap := int(wgPeer.Keepalive)
				_kad := time.Duration(time.Second * time.Duration(wkap))
				kad = &_kad
			}
			_, peerIPNet, err := net.ParseCIDR(wgPeer.PeerAddr)
			if err != nil {
				return fmt.Errorf("resolve peer address [%s] failed: %v", wgPeer.PeerAddr, err)
			}
			allowIPS := make([]net.IPNet, 0)
			allowIPS = append(allowIPS, *peerIPNet)
			for _, in := range wgPeer.AllowIPs {
				if _, ipnet, err := net.ParseCIDR(in); err != nil {
					return fmt.Errorf("parse net cidr [%s] failed: %v", in, err)
				} else {
					allowIPS = append(allowIPS, *ipnet)
					allowsIPsArray = append(allowsIPsArray, in)
				}
			}
			wgPeers = append(wgPeers, wgtypes.PeerConfig{
				PublicKey:                   pubKey,
				PresharedKey:                psk,
				PersistentKeepaliveInterval: kad,
				// Endpoint:                    endpoint,
				AllowedIPs: allowIPS,
			})
		}
		if err = r.wgctl.ConfigureDevice(wgconf.Name, wgtypes.Config{
			PrivateKey:   &privKey,
			ListenPort:   &lisPort,
			ReplacePeers: true,
			Peers:        wgPeers,
		}); err != nil {
			return fmt.Errorf("config wireguard interface [%s] failed: %v",
				wgconf.Name, err)
		}
		if err = r.ipTools.AddIPv4Address(
			wgconf.InterfaceDef.Address, wgconf.Name); err != nil {
			return fmt.Errorf("add ip address [%s] to dev [%s] failed: %v",
				wgconf.InterfaceDef.Address, wgconf.Name, err)
		}
		logrus.WithField("prefix", "wireguard").
			Infof("add ip address [%s] to dev [%s] success",
				wgconf.InterfaceDef.Address, wgconf.Name)
		if err = r.wireguard.UpDevice(wgconf.Name); err != nil {
			return err
		}
		logrus.WithField("prefix", "wireguard").
			Infof("up dev [%s] success and set mtu to [1420]", wgconf.Name)
		for _, addr := range allowsIPsArray {
			if err = r.ipTools.AddRouteToDev(addr, wgconf.Name, ""); err != nil {
				return err
			}
			logrus.WithField("prefix", "wireguard").
				Infof("add address [%s] route to dev [%s] success", addr, wgconf.Name)
		}
		logrus.WithField("prefix", "wireguard").
			Infof("config wireguard interface [%s] success", wgconf.Name)
	}
	return nil
}

func _initWanNet(wanInfo *pb.EthernetCard) error {
	if len(wanInfo.Addresses) == 0 {
		return nil
	}
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
