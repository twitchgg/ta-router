package tools

import (
	"time"

	"github.com/go-ping/ping"
)

const (
	DEFAULT_PING_COUNT = 5
)

func Ping(addr string) (time.Duration, error) {
	pinger, err := ping.NewPinger(addr)
	if err != nil {
		return 0, err
	}
	pinger.Count = DEFAULT_PING_COUNT
	if err = pinger.Run(); err != nil {
		return 0, err
	}
	return pinger.Statistics().AvgRtt, nil
}
