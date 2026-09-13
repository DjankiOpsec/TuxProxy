package leak

import (
	"fmt"
	"os"
	"strings"
)

// BuildEnvironment generates a sanitized, leak-proof environment slice for target processes
func BuildEnvironment(socksPort, httpPort int) []string {
	socksH := fmt.Sprintf("socks5h://127.0.0.1:%d", socksPort)
	httpURL := fmt.Sprintf("http://127.0.0.1:%d", httpPort)

	// Clean out any stale proxy variables
	baseEnv := make([]string, 0, len(os.Environ())+16)
	for _, env := range os.Environ() {
		lower := strings.ToLower(env)
		if strings.HasPrefix(lower, "http_proxy=") ||
			strings.HasPrefix(lower, "https_proxy=") ||
			strings.HasPrefix(lower, "all_proxy=") ||
			strings.HasPrefix(lower, "socks_proxy=") ||
			strings.HasPrefix(lower, "ftp_proxy=") ||
			strings.HasPrefix(lower, "_java_options=") ||
			strings.HasPrefix(lower, "java_tool_options=") ||
			strings.HasPrefix(lower, "no_proxy=") {
			continue
		}
		baseEnv = append(baseEnv, env)
	}

	// Inject hardened proxy configuration
	injections := []string{
		// SOCKS5 with remote DNS resolution (the 'h' is critical to prevent DNS leaks)
		fmt.Sprintf("ALL_PROXY=%s", socksH),
		fmt.Sprintf("all_proxy=%s", socksH),
		fmt.Sprintf("SOCKS_PROXY=%s", socksH),
		fmt.Sprintf("socks_proxy=%s", socksH),

		// HTTP/HTTPS Tunnel listeners (use socks5h for seamless HTTP + HTTPS remote resolution without Tor HTTPTunnelPort drops)
		fmt.Sprintf("HTTP_PROXY=%s", socksH),
		fmt.Sprintf("http_proxy=%s", socksH),
		fmt.Sprintf("HTTPS_PROXY=%s", socksH),
		fmt.Sprintf("https_proxy=%s", socksH),
		fmt.Sprintf("FTP_PROXY=%s", socksH),
		fmt.Sprintf("ftp_proxy=%s", socksH),
		fmt.Sprintf("RSYNC_PROXY=127.0.0.1:%d", httpPort),
		fmt.Sprintf("TOR_HTTP_PROXY=%s", httpURL),
		fmt.Sprintf("tor_http_proxy=%s", httpURL),

		// Java / JVM options (IntelliJ IDEA, PyCharm, Android Studio, Gradle, Maven, etc.)
		fmt.Sprintf("_JAVA_OPTIONS=-DsocksProxyHost=127.0.0.1 -DsocksProxyPort=%d -Dhttp.proxyHost=127.0.0.1 -Dhttp.proxyPort=%d -Dhttps.proxyHost=127.0.0.1 -Dhttps.proxyPort=%d",
			socksPort, httpPort, httpPort),
		fmt.Sprintf("JAVA_TOOL_OPTIONS=-DsocksProxyHost=127.0.0.1 -DsocksProxyPort=%d -Dhttp.proxyHost=127.0.0.1 -Dhttp.proxyPort=%d -Dhttps.proxyHost=127.0.0.1 -Dhttps.proxyPort=%d",
			socksPort, httpPort, httpPort),

		// Standard bypass for localhost
		"NO_PROXY=localhost,127.0.0.1",
		"no_proxy=localhost,127.0.0.1",

		// TuxProxy marker
		"TUXPROXY_ACTIVE=1",
		fmt.Sprintf("TUXPROXY_SOCKS=127.0.0.1:%d", socksPort),
		fmt.Sprintf("TUXPROXY_HTTP=127.0.0.1:%d", httpPort),
	}

	return append(baseEnv, injections...)
}
