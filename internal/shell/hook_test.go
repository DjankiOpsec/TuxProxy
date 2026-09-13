package shell

import (
	"strings"
	"testing"
	"tuxproxy/internal/config"
)

func TestInitScript(t *testing.T) {
	cfg := config.DefaultConfig()
	cfg.ExitCountry = "us"
	cfg.SocksPort = 9050
	cfg.HTTPPort = 9080
	cfg.TerminalAutoStartDaemon = true
	cfg.JavaProxySupport = true
	cfg.ShowPromptIndicator = true

	script := InitScript(cfg)

	expectedStrings := []string{
		"export ALL_PROXY=\"socks5h://127.0.0.1:9050\"",
		"export HTTP_PROXY=\"socks5h://127.0.0.1:9050\"",
		"export TUXPROXY_ACTIVE=1",
		"export _JAVA_OPTIONS=\"-DsocksProxyHost=127.0.0.1 -DsocksProxyPort=9050",
		"[tuxproxy:${TUXPROXY_COUNTRY:-US}]",
		"tuxoff()",
		"tuxon()",
		"tuxip()",
	}

	for _, s := range expectedStrings {
		if !strings.Contains(script, s) {
			t.Errorf("InitScript missing expected snippet: %q", s)
		}
	}
}

func TestEnvExport(t *testing.T) {
	cfg := config.DefaultConfig()
	cfg.SocksPort = 9050
	cfg.HTTPPort = 9080

	onOut := EnvExport(cfg, false)
	if !strings.Contains(onOut, "export ALL_PROXY=\"socks5h://127.0.0.1:9050\"") {
		t.Errorf("EnvExport(false) missing ALL_PROXY export")
	}
	if !strings.Contains(onOut, "export _JAVA_OPTIONS=") {
		t.Errorf("EnvExport(false) missing _JAVA_OPTIONS export")
	}

	offOut := EnvExport(cfg, true)
	if !strings.Contains(offOut, "unset ALL_PROXY") {
		t.Errorf("EnvExport(true) missing unset ALL_PROXY")
	}
}
