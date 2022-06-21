package test

import (
	"fmt"
	"testing"

	"golang.zx2c4.com/wireguard/wgctrl"
)

func TestWG(t *testing.T) {
	c, err := wgctrl.New()
	if err != nil {
		t.Fatalf("failed to open wgctrl: %v", err)
	}
	defer c.Close()
	devs, err := c.Devices()
	if err != nil {
		t.Fatalf("failed to query devices: %v", err)
	}
	for _, v := range devs {
		fmt.Println(v.Name)
	}
}
