package tor

import (
	"strings"
	"testing"
	"tuxproxy/internal/config"
)

func TestBuildTorrc(t *testing.T) {
	cfg := &config.Config{
		ExitCountry:       "us",
		StrictNodes:       true,
		BridgeType:        "snowflake",
		SnowflakePath:     "/usr/bin/snowflake-client",
		SnowflakeURL:      "https://snowflake-broker.torproject.net/",
		SnowflakeFront:    "www.google.com",
		SnowflakeAMPCache: "https://cdn.ampproject.org/",
		SafeLogging:       true,
		DisableIPv6:       true,
	}

	torrc := BuildTorrc(cfg, "/tmp/test_dir", 9050, 9080, 9053, 9051)

	if !strings.Contains(torrc, "SocksPort 127.0.0.1:9050 IsolateDestAddr IsolateDestPort") {
		t.Errorf("missing SocksPort with stream isolation")
	}
	if !strings.Contains(torrc, "HTTPTunnelPort 127.0.0.1:9080 IsolateDestAddr IsolateDestPort") {
		t.Errorf("missing HTTPTunnelPort with stream isolation")
	}
	if !strings.Contains(torrc, "ExitNodes {us}") {
		t.Errorf("missing ExitNodes {us}")
	}
	if !strings.Contains(torrc, "StrictNodes 1") {
		t.Errorf("missing StrictNodes 1")
	}
	if !strings.Contains(torrc, "ClientUseIPv6 0") {
		t.Errorf("missing ClientUseIPv6 0")
	}
	if !strings.Contains(torrc, "ClientTransportPlugin snowflake exec") {
		t.Errorf("missing ClientTransportPlugin snowflake")
	}
	if !strings.Contains(torrc, "-ampcache https://cdn.ampproject.org/") {
		t.Errorf("missing snowflake ampcache parameter")
	}
}

func TestPorts(t *testing.T) {
	avail := IsPortAvailable(9050)
	t.Logf("Port 9050 available: %v", avail)

	port := FindAvailablePort(9050)
	if port < 9050 {
		t.Errorf("invalid port returned: %d", port)
	}
}
