package iptables

import (
	"bufio"
	"fmt"
	"io"
	"strconv"
	"strings"
)

// NewChain create iptables chain with table
func (t *IPTables) NewChain(tableName, chainName string) error {
	if _, err := t.iptablesExec("iptables_new_chain",
		[]string{"-t", tableName, "-N", chainName}); err != nil {
		return fmt.Errorf("create table [%s] chain [%s] failed: %s",
			tableName, chainName, err.Error())
	}
	return nil
}

// ChainExist assert iptables chain exist with table
func (t *IPTables) ChainExist(tableName, chainName string) (bool, error) {
	_, err := t.List(tableName, chainName)
	if err != nil {
		if strings.Contains(err.Error(), "No chain/target/match") {
			return false, nil
		}
		return false, err
	}
	return true, nil
}

// FlushChain flush iptables chain with table
func (t *IPTables) FlushChain(tableName, chainName string) error {
	_, err := t.iptablesExec("iptables_flush",
		[]string{"-t", tableName, "--flush", chainName})
	if err != nil {
		return fmt.Errorf("flush table [%s] chain [%s] failed",
			tableName, chainName)
	}
	return nil
}

// RemoveChain remove iptables chain with table
func (t *IPTables) RemoveChain(tableName, chainName string) error {
	_, err := t.iptablesExec("iptables_flush",
		[]string{"-t", tableName, "-X", chainName})
	if err != nil {
		return fmt.Errorf("remove table [%s] chain [%s] failed",
			tableName, chainName)
	}
	return nil
}

// FlushAndRemoveChain flush and remove iptables chain with table
func (t *IPTables) FlushAndRemoveChain(tableName, chainName string) error {
	if exist, err := t.ChainExist(tableName, chainName); err != nil {
		return err
	} else if exist {
		if err = t.FlushChain(tableName, chainName); err != nil {
			return err
		}
		if err = t.RemoveChain(tableName, chainName); err != nil {
			return err
		}
	}
	return nil
}

// Chain iptables chain information
type Chain struct {
	Name       string
	Policy     string
	References int
}

// IsCustomChain assert is custom chain
func (c *Chain) IsCustomChain() bool {
	return c.Policy == ""
}

// GetChains get iptables system and custom chain with table
func (t *IPTables) GetChains(tableName string) ([]*Chain, error) {
	result, err := t.iptablesExec("iptables_get_chains", []string{"-t", tableName, "-L"})
	if err != nil {
		return nil, fmt.Errorf("get iptables chain failed: %s", err.Error())
	}
	r := bufio.NewReader(strings.NewReader(result))
	chains := make([]*Chain, 0)
	for {
		l, _, err := r.ReadLine()
		if err != nil {
			if err == io.EOF {
				break
			}
			return nil, fmt.Errorf(
				"parse iptables chain failed: %s", err.Error())
		}
		lineStr := string(l)
		if !strings.HasPrefix(lineStr, "Chain ") {
			continue
		}
		parts := strings.Fields(lineStr)
		chain := &Chain{
			Name: parts[1],
		}
		if strings.Contains(parts[2], "policy") {
			if len(parts) == 4 {
				chain.Policy = parts[3][:len(parts[3])-1]
			} else if len(parts) > 4 {
				chain.Policy = parts[3][:len(parts[3])]
			}
		} else if strings.Contains(parts[3], "references") {
			chain.References, err = strconv.Atoi(parts[2][1:])
			if err != nil {
				return nil, fmt.Errorf("parse refernces failed: %s", err.Error())
			}
		}
		chains = append(chains, chain)
	}
	return chains, nil
}
