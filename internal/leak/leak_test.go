package leak

import (
	"strings"
	"testing"
)

func TestBuildEnvironment(t *testing.T) {
	env := BuildEnvironment(9050, 9080)

	hasAllProxy := false
	hasHttpProxy := false
	hasTuxMarker := false

	for _, e := range env {
		if strings.HasPrefix(e, "ALL_PROXY=socks5h://127.0.0.1:9050") {
			hasAllProxy = true
		}
		if strings.HasPrefix(e, "HTTP_PROXY=socks5h://127.0.0.1:9050") {
			hasHttpProxy = true
		}
		if e == "TUXPROXY_ACTIVE=1" {
			hasTuxMarker = true
		}
	}

	if !hasAllProxy {
		t.Errorf("expected ALL_PROXY to be configured with socks5h://")
	}
	if !hasHttpProxy {
		t.Errorf("expected HTTP_PROXY to be configured with socks5h://")
	}
	if !hasTuxMarker {
		t.Errorf("expected TUXPROXY_ACTIVE=1 marker")
	}
}

func TestIsChromiumOrElectron(t *testing.T) {
	cases := []struct {
		app      string
		expected bool
	}{
		{"antigravity-ide", true},
		{"/usr/bin/antigravity-ide", true},
		{"code", true},
		{"google-chrome-stable", true},
		{"brave", true},
		{"curl", false},
		{"git", false},
		{"python3", false},
	}

	for _, c := range cases {
		res := IsChromiumOrElectron(c.app)
		if res != c.expected {
			t.Errorf("IsChromiumOrElectron(%s) = %v; expected %v", c.app, res, c.expected)
		}
	}
}

func TestChromiumFlags(t *testing.T) {
	flags := ChromiumFlags(9050, true, true)
	flagsStr := strings.Join(flags, " ")

	if !strings.Contains(flagsStr, "--proxy-server=socks5://127.0.0.1:9050") {
		t.Errorf("expected proxy-server flag")
	}
	if !strings.Contains(flagsStr, "--webrtc-ip-handling-policy=disable_non_proxied_udp") {
		t.Errorf("expected WebRTC anti-leak policy")
	}
	if !strings.Contains(flagsStr, "--host-resolver-rules") {
		t.Errorf("expected host resolver rule")
	}
}
