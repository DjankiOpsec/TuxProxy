package leak

import (
	"fmt"
	"os"
)

// GenerateProxychainsConfig writes a zero-leak proxychains configuration file
func GenerateProxychainsConfig(targetDir string, socksPort int) (string, error) {
	content := fmt.Sprintf(`# TuxProxy auto-generated zero-leak proxychains config
strict_chain
proxy_dns
remote_dns_subnet 224
tcp_read_time_out 15000
tcp_connect_time_out 8000

[ProxyList]
socks5 127.0.0.1 %d
`, socksPort)

	tmpFile, err := os.CreateTemp(targetDir, "tuxproxy-pc-*.conf")
	if err != nil {
		return "", err
	}
	defer tmpFile.Close()

	if _, err := tmpFile.WriteString(content); err != nil {
		_ = os.Remove(tmpFile.Name())
		return "", err
	}
	return tmpFile.Name(), nil
}

