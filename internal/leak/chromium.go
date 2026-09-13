package leak

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// Known Chromium & Electron application binaries
var knownChromiumApps = []string{
	"antigravity-ide",
	"code",
	"code-insiders",
	"vscodium",
	"cursor",
	"google-chrome",
	"google-chrome-stable",
	"chromium",
	"chromium-browser",
	"brave",
	"brave-browser",
	"microsoft-edge",
	"microsoft-edge-stable",
	"slack",
	"discord",
	"spotify",
	"electron",
}

// IsChromiumOrElectron checks whether the target binary or script is Chromium/Electron based
func IsChromiumOrElectron(target string) bool {
	base := strings.ToLower(filepath.Base(target))
	for _, app := range knownChromiumApps {
		if base == app || strings.HasPrefix(base, app+"-") {
			return true
		}
	}

	// Check if script wrapper references electron or known flags
	if data, err := os.ReadFile(target); err == nil && len(data) < 8192 {
		content := strings.ToLower(string(data))
		if strings.Contains(content, "electron") ||
			strings.Contains(content, "antigravity-ide") ||
			strings.Contains(content, "--user-data-dir") {
			return true
		}
	}

	return false
}

// ChromiumFlags generates hardened command-line flags to prevent WebRTC, DNS, and telemetry leaks
func ChromiumFlags(socksPort int, preventWebRTC, preventDNS bool) []string {
	flags := []string{
		// Force all TCP/UDP connections through SOCKS5
		fmt.Sprintf("--proxy-server=socks5://127.0.0.1:%d", socksPort),
	}

	if preventDNS {
		// Strict OPSEC: Block local host resolver lookup, forcing remote resolution through SOCKS5
		flags = append(flags, `--host-resolver-rules=MAP * ~NOTFOUND , EXCLUDE 127.0.0.1`)
	}

	if preventWebRTC {
		// Disable non-proxied UDP to stop WebRTC local/public IP leakage via STUN
		flags = append(flags,
			"--webrtc-ip-handling-policy=disable_non_proxied_udp",
			"--enforce-webrtc-ip-permission-check",
		)
	}

	// Anti-telemetry & fingerprinting mitigations
	flags = append(flags,
		"--disable-breakpad",
		"--disable-component-update",
		"--disable-domain-reliability",
		"--no-pings",
	)

	return flags
}
