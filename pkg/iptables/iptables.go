package iptables

import (
	"bufio"
	"fmt"
	"io"
	"os/exec"
	"strconv"
	"strings"

	"ntsc.ac.cn/ta-router/pkg/rexec"
)

// IPTables iptables wrap
type IPTables struct {
	iptablesPath string
	ipsetPath    string
}

// NewIPTables new iptables wrap
func NewIPTables(iptablesPath, ipsetPath string) (*IPTables, error) {
	var err error
	if iptablesPath == "" {
		iptablesPath = "iptables"
	}
	if ipsetPath == "" {
		ipsetPath = "ipset"
	}
	if iptablesPath, err = exec.LookPath(iptablesPath); err != nil {
		return nil, fmt.Errorf("loop path [%s] failed: %s",
			iptablesPath, err.Error())
	}
	if ipsetPath, err = exec.LookPath(ipsetPath); err != nil {
		return nil, fmt.Errorf("loop path [%s] failed: %s",
			ipsetPath, err.Error())
	}
	return &IPTables{
		iptablesPath: iptablesPath,
		ipsetPath:    ipsetPath,
	}, nil
}

// Rule iptables rule information
type Rule struct {
	Num         int
	Pkts        int
	Bytes       int
	Target      string
	Prot        string
	Opt         string
	In          string
	Out         string
	Source      string
	Destination string
}

// iptablesExec iptables executer
func (t *IPTables) iptablesExec(name string, args []string) (string, error) {
	exe, err := rexec.NewExecuter(name,
		t.iptablesPath, args)
	if err != nil {
		return "", fmt.Errorf(
			"exec iptables [%s] failed: %s", name, err.Error())
	}

	result, err := exe.Run()
	if err != nil {
		return "", fmt.Errorf(
			"exec iptables [%s] failed: %s", name, result)
	}
	return result, nil
}

// List list iptables rules with table and chain name
func (t *IPTables) List(tableName string, chainName string) ([]*Rule, error) {
	args := []string{"-L"}
	if chainName != "" {
		args = append(args, chainName)
	}
	args = append(args, []string{"-v", "-n", "--line-numbers"}...)
	if tableName != "" {
		args = append(args, []string{"-t", tableName}...)
	}

	result, err := t.iptablesExec("iptables_list", args)
	if err != nil {
		return nil, fmt.Errorf(err.Error())
	}
	r := bufio.NewReader(strings.NewReader(result))
	var header1 string
	var header2 string
	rules := make([]*Rule, 0)
	for {
		l, _, err := r.ReadLine()
		if err != nil {
			if err == io.EOF {
				break
			}
			return nil, fmt.Errorf(
				"parse iptables rules failed: %s", err.Error())
		}
		if string(l) == "" {
			continue
		}
		if header1 == "" {
			header1 = string(l)
			continue
		}
		if header2 == "" {
			header2 = string(l)
			continue
		}
		values := strings.Fields(string(l))
		if len(values) < 10 {
			return nil, fmt.Errorf("parse iptables rule failed,size [%d]", len(values))
		}
		num, err := strconv.Atoi(values[0])
		if err != nil {
			return nil, fmt.Errorf("parse iptables rule [num] failed: %s", err.Error())
		}
		pkts, err := strconv.Atoi(values[1])
		if err != nil {
			return nil, fmt.Errorf("parse iptables rule [pkts] failed: %s", err.Error())
		}
		bs, err := strconv.Atoi(values[2])
		if err != nil {
			return nil, fmt.Errorf("parse iptables rule [bytes] failed: %s", err.Error())
		}
		rules = append(rules, &Rule{
			Num:         num,
			Pkts:        pkts,
			Bytes:       bs,
			Target:      values[3],
			Prot:        values[4],
			Opt:         values[5],
			In:          values[6],
			Out:         values[7],
			Source:      values[8],
			Destination: values[9],
		})
	}
	return rules, nil
}
