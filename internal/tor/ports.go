package tor

import (
	"fmt"
	"net"
)

// IsPortAvailable checks if a TCP port on 127.0.0.1 is available to bind
func IsPortAvailable(port int) bool {
	ln, err := net.Listen("tcp", fmt.Sprintf("127.0.0.1:%d", port))
	if err != nil {
		return false
	}
	_ = ln.Close()
	return true
}

// FindAvailablePort returns the requested port if available, or the next available port
func FindAvailablePort(startPort int) int {
	for port := startPort; port < startPort+100; port++ {
		if IsPortAvailable(port) {
			return port
		}
	}
	// Fallback to OS assigned ephemeral port
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return startPort
	}
	defer ln.Close()
	return ln.Addr().(*net.TCPAddr).Port
}
