package wireguard

import (
	"fmt"
	"os/exec"
	"strconv"

	"ntsc.ac.cn/ta-router/pkg/iptools"
	"ntsc.ac.cn/ta-router/pkg/rexec"
)

type WireguardTools struct {
	wgPath      string
	wgQuickPath string
	ipTools     *iptools.IPTools
}

// NewWireguardTools new wireguard tootls
func NewWireguardTools(wgPath, wgQuickPath string, ipToolsPath string) (*WireguardTools, error) {
	if wgPath == "" {
		wgPath = "wg"
	}
	if wgQuickPath == "" {
		wgQuickPath = "wg-quick"
	}
	var err error
	if wgPath, err = exec.LookPath(wgPath); err != nil {
		return nil, fmt.Errorf("loop path [%s] failed: %v", wgPath, err)
	}
	if wgQuickPath, err = exec.LookPath(wgQuickPath); err != nil {
		return nil, fmt.Errorf("loop path [%s] failed: %v", wgQuickPath, err)
	}
	iptools, err := iptools.NewIPTools(ipToolsPath)
	if err != nil {
		return nil, err
	}
	return &WireguardTools{
		wgPath:      wgPath,
		wgQuickPath: wgQuickPath,
		ipTools:     iptools,
	}, nil
}

// IsIPv4ForwardEnable assert is system ipv4 forward enabled
func IsIPv4ForwardEnable() (bool, error) {
	exe, err := rexec.NewExecuter("cat_ipv4_forward",
		"cat", []string{"/proc/sys/net/ipv4/ip_forward"})
	if err != nil {
		return false, fmt.Errorf(
			"exec cat ip forward failed: %s", err.Error())
	}
	result, err := exe.Run()
	if err != nil {
		return false, fmt.Errorf(
			"exec cat ip forward failed: %s", result)
	}
	r, err := strconv.Atoi(result)
	if err != nil {
		return false, fmt.Errorf("parse cat ip forward result failed: %s", err.Error())
	}
	if r == 1 {
		return true, nil
	}
	return false, nil
}

// EnableIPv4Forward enable system ipv4 forward
func EnableIPv4Forward() error {
	exe, err := rexec.NewExecuter("enable_ipv4_forward",
		"bash", []string{"-c", "echo 1 > /proc/sys/net/ipv4/ip_forward"})
	if err != nil {
		return fmt.Errorf(
			"enable ip forward failed: %s", err.Error())
	}
	result, err := exe.Run()
	if err != nil {
		return fmt.Errorf(
			"enable ip forward failed: %s", result)
	}
	return nil
}

type QuickType int

const (
	// QUICK_TYPE_UP wireguard interface up operate
	QUICK_TYPE_UP QuickType = iota
	// QUICK_TYPE_DOWN wireguard interface down operate
	QUICK_TYPE_DOWN
)

func (qt QuickType) String() string {
	switch qt {
	case QUICK_TYPE_UP:
		return "up"
	case QUICK_TYPE_DOWN:
		return "down"
	default:
		return ""
	}
}

// Quick wireguard wg-quick tools executer
func (wt *WireguardTools) Quick(confPath string, quickType QuickType) error {
	exe, err := rexec.NewExecuter("wg-quick-op",
		wt.wgQuickPath, []string{quickType.String(), confPath})
	if err != nil {
		return fmt.Errorf(
			"enable ip forward failed: %s", err.Error())
	}
	result, err := exe.Run()
	if err != nil {
		return fmt.Errorf(
			"enable ip forward failed: %s", result)
	}
	return nil
}

// RestartDev restart wireguard interface with dev name or config file
func (wt *WireguardTools) RestartDev(confPath string) error {
	wt.Quick(confPath, QUICK_TYPE_DOWN)
	return wt.Quick(confPath, QUICK_TYPE_UP)
}

// ReloadDev reload wireguard interface with dev name
func (wt *WireguardTools) ReloadDev(dev string) error {
	cmd := "WGNET=" + dev + ";wg syncconf ${WGNET} <(wg-quick strip ${WGNET})"
	exe, err := rexec.NewExecuter("wg-reload",
		"bash", []string{"-c", cmd})
	if err != nil {
		return fmt.Errorf(
			"reload dev failed: %s", err.Error())
	}
	result, err := exe.Run()
	if err != nil {
		return fmt.Errorf(
			"reload dev [%s] failed: %s", dev, result)
	}
	return nil
}

// DelWireguardInterface delete wireguard interface
func (wt *WireguardTools) DelWireguardInterface(name string) error {
	return wt.ipTools.DeleteLink(name)
}

func (wt *WireguardTools) AddWireguardInterface(name string) error {
	return wt.ipTools.AddLink(name, "wireguard")
}

func (wt *WireguardTools) UpDevice(name string) error {
	args := make([]string, 0)
	args = append(args, "link")
	args = append(args, "set")
	args = append(args, "mtu")
	args = append(args, "1420")
	args = append(args, "up")
	args = append(args, "dev")
	args = append(args, name)
	exe, err := rexec.NewExecuter("ip",
		wt.ipTools.IPToolsPath(), args)
	if err != nil {
		return fmt.Errorf(
			"set mtu and up wireguard dev [%s] failed: %v", name, err)
	}
	if _, err = exe.Run(); err != nil {
		return fmt.Errorf(
			"set mtu and up wireguard dev [%s] failed: %v", name, err)
	}
	return nil
}
