package iptools

import (
	"fmt"
	"os/exec"

	"ntsc.ac.cn/ta-router/pkg/rexec"
)

// IPTools linux ip tools
type IPTools struct {
	ipToolsPath string
}

func NewIPTools(ipToolsPath string) (*IPTools, error) {
	if ipToolsPath == "" {
		ipToolsPath = "ip"
	}
	var err error
	if ipToolsPath, err = exec.LookPath(ipToolsPath); err != nil {
		return nil, fmt.Errorf("loop path [%s] failed: %v", ipToolsPath, err)
	}
	return &IPTools{ipToolsPath: ipToolsPath}, nil
}

// DeleteLink delete link
func (t *IPTools) DeleteLink(name string) error {
	exe, err := rexec.NewExecuter("ip",
		t.ipToolsPath, []string{"link", "del", name})
	if err != nil {
		return fmt.Errorf(
			"del link [%s] failed: %v", name, err)
	}
	if _, err = exe.Run(); err != nil {
		return fmt.Errorf(
			"del link [%s] failed: %v", name, err)
	}
	return nil
}

func (t *IPTools) AddLink(name, linkType string) error {
	exe, err := rexec.NewExecuter("ip",
		t.ipToolsPath, []string{"link", "add", "dev", name, "type", linkType})
	if err != nil {
		return fmt.Errorf(
			"add link [%s] with type [%s] failed: %v", name, linkType, err)
	}
	if _, err = exe.Run(); err != nil {
		return fmt.Errorf(
			"add link [%s] with type [%s] failed: %v", name, linkType, err)
	}
	return nil
}

func (t *IPTools) AddRouteToDev(cidr, dev, table string) error {
	args := make([]string, 0)
	args = append(args, "route")
	args = append(args, "add")
	args = append(args, cidr)
	args = append(args, "dev")
	args = append(args, dev)
	if table != "" {
		args = append(args, "table")
		args = append(args, table)
	}
	exe, err := rexec.NewExecuter("ip",
		t.ipToolsPath, args)
	if err != nil {
		return fmt.Errorf(
			"add route failed: %v", err)
	}
	if _, err = exe.Run(); err != nil {
		return fmt.Errorf(
			"add route failed: %v", err)
	}
	return nil
}

func (t *IPTools) AddIPv4Address(addr, dev string) error {
	args := make([]string, 0)
	args = append(args, "-4")
	args = append(args, "address")
	args = append(args, "add")
	args = append(args, addr)
	args = append(args, "dev")
	args = append(args, dev)
	exe, err := rexec.NewExecuter("ip",
		t.ipToolsPath, args)
	if err != nil {
		return fmt.Errorf(
			"add ip v4 address failed: %v", err)
	}
	if _, err = exe.Run(); err != nil {
		return fmt.Errorf(
			"add ip v4 failed: %v", err)
	}
	return nil
}

func (t *IPTools) IPToolsPath() string {
	return t.ipToolsPath
}
