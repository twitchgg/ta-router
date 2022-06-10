package cmd

import (
	"flag"
	"os"

	"github.com/sirupsen/logrus"
	prefixed "github.com/x-cray/logrus-prefixed-formatter"
	"ntsc.ac.cn/ta-router/internal/router"
)

var envs struct {
	registryEndpoint   string
	loggerLevel        string
	certPath           string
	serverName         string
	wireguardPath      string
	wireguardToolsPath string
	iptablesPath       string
	ipsetPath          string
}

func init() {
	_flags()
	logLevel, err := logrus.ParseLevel(envs.loggerLevel)
	if err != nil {
		logrus.WithField("prefix", "root.init_global_vars").
			Fatalf("unsupport log level: %s", envs.loggerLevel)
	}
	logrus.SetOutput(os.Stdout)
	logrus.SetLevel(logLevel)
	formatter := new(prefixed.TextFormatter)
	logrus.SetFormatter(formatter)
}

func _flags() {
	flag.StringVar(&envs.loggerLevel, "logger-level",
		"DEBUG",
		"logger level")
	flag.StringVar(&envs.registryEndpoint, "registry-endpoint",
		"tcp://localhost:1358",
		"registry endpoint")
	flag.StringVar(&envs.certPath, "cert-path",
		"/etc/ntsc/ta/router/certs",
		"system certificates path")
	flag.StringVar(&envs.serverName, "server-name",
		"s1.restry.ta.ntsc.ac.cn",
		"registry service certificate server name")
	flag.StringVar(&envs.wireguardPath, "wg-path", "",
		"wireguard executer path")
	flag.StringVar(&envs.wireguardToolsPath, "wg-tools-path", "",
		"wireguard tools executer path")
	flag.StringVar(&envs.iptablesPath, "iptables-path", "",
		"iptables executer path")
	flag.StringVar(&envs.ipsetPath, "ipset-path", "",
		"ipset executer path")
	flag.Parse()
}

func Execute() {
	r, err := router.NewWireguardRouter(&router.Config{
		CertPath:           envs.certPath,
		ServerName:         envs.serverName,
		ManagerEndpoint:    envs.registryEndpoint,
		WireguardPath:      envs.wireguardPath,
		WireguardToolsPath: envs.wireguardToolsPath,
		IPTablesPath:       envs.iptablesPath,
		IPSetPath:          envs.ipsetPath,
	})
	if err != nil {
		logrus.WithField("prefix", "main").Fatalf(
			"create wireguard router failed: %s", err.Error())
	}
	logrus.WithField("prefix", "main").Fatalf(
		"run wireguard router failed: %s", <-r.Start())
	r.Start()
}
