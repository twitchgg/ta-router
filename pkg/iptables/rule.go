package iptables

import (
	"fmt"
	"strconv"
)

// RuleOP iptables rule operate type
type RuleOP int

const (
	// RULE_APPEND append iptables rule
	RULE_APPEND RuleOP = iota
	// RULE_INSERT insert iptables rule
	RULE_INSERT
	// RULE_DELETE delete iptables rule
	RULE_DELETE
)

// ArgName get iptables rule operate argument name
func (op RuleOP) ArgName() (string, error) {
	switch op {
	case RULE_APPEND:
		return "-A", nil
	case RULE_INSERT:
		return "-I", nil
	case RULE_DELETE:
		return "-D", nil
	}
	return "", fmt.Errorf("unknow operate [%d]", op)
}

func (t *IPTables) ruleOP(tableName, chainName string, op RuleOP, args []string) error {
	opName, err := op.ArgName()
	if err != nil {
		return err
	}
	opArgs := make([]string, 0)
	opArgs = append(opArgs, []string{"-t", tableName, opName, chainName}...)
	opArgs = append(opArgs, args...)
	if _, err = t.iptablesExec("iptables_op", opArgs); err != nil {
		return err
	}
	return nil
}

// AppendRule append iptables rule
func (t *IPTables) AppendRule(tableName, chainName, action string, rule []string) error {
	rule = append(rule, []string{"-j", action}...)
	return t.ruleOP(tableName, chainName, RULE_APPEND, rule)
}

// InsertRule insert iptables rule
func (t *IPTables) InsertRule(tableName, chainName, action string, rule []string) error {
	rule = append(rule, []string{"-j", action}...)
	return t.ruleOP(tableName, chainName, RULE_INSERT, rule)
}

// DeleteRuleByIndex delete iptables rule by index
func (t *IPTables) DeleteRuleByIndex(tableName, chainName string, idx int) error {
	return t.ruleOP(tableName, chainName, RULE_DELETE, []string{strconv.Itoa(idx)})
}

// DeleteRule delete iptables rule
func (t *IPTables) DeleteRule(tableName, chainName string, rule []string) error {
	return t.ruleOP(tableName, chainName, RULE_DELETE, rule)
}
