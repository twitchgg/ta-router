package wireguard

import (
	"fmt"

	"ntsc.ac.cn/ta-router/pkg/rexec"
)

// Genkey generate wireguard key
func (wt *WireguardTools) Genkey() (string, error) {
	exe, err := rexec.NewExecuter("wg-genkey",
		wt.wgPath, []string{"genkey"})
	if err != nil {
		return "", fmt.Errorf(
			"gen wireguard private key failed: %s", err.Error())
	}
	result, err := exe.Run()
	if err != nil {
		return "", fmt.Errorf(
			"gen wireguard private key failed: %s", err)
	}
	return result, nil
}

// Pubkey export wireguard public key with private key
func (wt *WireguardTools) Pubkey(privKey string) (string, error) {
	cmd := "echo " + privKey + " | " + wt.wgPath + " pubkey"
	exe, err := rexec.NewExecuter("wg-pubkey",
		"bash", []string{"-c", cmd})
	if err != nil {
		return "", fmt.Errorf(
			"gen wireguard public key failed: %s", err.Error())
	}
	result, err := exe.Run()
	if err != nil {
		return "", fmt.Errorf(
			"gen wireguard public key failed: %s", err.Error())
	}
	return result, nil
}

// GenPSK generate wireguard preshared key
func (wt *WireguardTools) GenPSK() (string, error) {
	exe, err := rexec.NewExecuter("wg-genpsk",
		wt.wgPath, []string{"genpsk"})
	if err != nil {
		return "", fmt.Errorf(
			"gen wireguard preshare key failed: %s", err.Error())
	}
	result, err := exe.Run()
	if err != nil {
		return "", fmt.Errorf(
			"gen wireguard preshare key failed: %s", err.Error())
	}
	return result, nil
}
