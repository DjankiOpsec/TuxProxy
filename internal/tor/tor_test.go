package tor

import (
	"crypto/rand"
	"encoding/hex"
	"io"
	"net"
	"os"
	"path/filepath"
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

func TestBuildTorrcWithOptions(t *testing.T) {
	cfg := &config.Config{
		ExitCountry: "de",
		SafeLogging: true,
		DisableIPv6: true,
	}

	opts := TorrcOptions{
		DataDir:           "/tmp/tux_data",
		BindAddress:       "10.200.42.1",
		SocksPort:         9050,
		HTTPPort:          9080,
		DNSPort:           9053,
		ControlSocketPath: "/tmp/tux_rt/control.sock",
		CookieAuthFile:    "/tmp/tux_rt/control_auth_cookie",
		UseCookieAuth:     true,
	}

	torrc := BuildTorrcWithOptions(cfg, opts)

	if !strings.Contains(torrc, "SocksPort 10.200.42.1:9050 IsolateDestAddr IsolateDestPort") {
		t.Errorf("missing bind-specific SocksPort: %s", torrc)
	}
	if !strings.Contains(torrc, "DNSPort 10.200.42.1:9053") {
		t.Errorf("missing bind-specific DNSPort: %s", torrc)
	}
	if !strings.Contains(torrc, "ControlSocket /tmp/tux_rt/control.sock GroupWritable 0") {
		t.Errorf("missing ControlSocket directive: %s", torrc)
	}
	if !strings.Contains(torrc, "CookieAuthentication 1") {
		t.Errorf("missing CookieAuthentication 1: %s", torrc)
	}
	if !strings.Contains(torrc, "CookieAuthFile /tmp/tux_rt/control_auth_cookie") {
		t.Errorf("missing CookieAuthFile directive: %s", torrc)
	}
	// Verify it NEVER binds to wildcard 0.0.0.0
	if strings.Contains(torrc, "0.0.0.0") {
		t.Errorf("security violation: torrc contains 0.0.0.0 wildcard binding")
	}
}

func TestSecureRuntimeDir(t *testing.T) {
	sessionID := generateSessionID()
	dir, err := createSecureRuntimeDir(sessionID)
	if err != nil {
		t.Fatalf("createSecureRuntimeDir failed: %v", err)
	}
	defer os.RemoveAll(dir)

	info, err := os.Lstat(dir)
	if err != nil {
		t.Fatalf("lstat failed: %v", err)
	}

	if info.Mode().Perm() != 0700 {
		t.Errorf("expected permissions 0700, got: %o", info.Mode().Perm())
	}
	if info.Mode()&os.ModeSymlink != 0 {
		t.Errorf("runtime directory must not be a symlink")
	}
}

func TestCleanupStaleSocket(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "tux_sock_test_*")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(tmpDir)

	sockPath := filepath.Join(tmpDir, "test.sock")

	// 1. Non-existent socket: should return nil
	if err := cleanupStaleSocket(sockPath); err != nil {
		t.Errorf("expected nil for non-existent socket, got: %v", err)
	}

	// 2. Create dead socket file (not listening)
	if err := os.WriteFile(sockPath, []byte("dead"), 0600); err != nil {
		t.Fatal(err)
	}

	// Should successfully clean up dead socket
	if err := cleanupStaleSocket(sockPath); err != nil {
		t.Errorf("expected cleanup of dead socket to succeed, got: %v", err)
	}
	if _, err := os.Stat(sockPath); !os.IsNotExist(err) {
		t.Errorf("dead socket was not removed")
	}

	// 3. Active listener: should return error and refuse to delete
	listener, err := net.Listen("unix", sockPath)
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()

	if err := cleanupStaleSocket(sockPath); err == nil {
		t.Errorf("expected error when socket is actively listening, got nil")
	}
}

func TestSyntheticSocksHandshake(t *testing.T) {
	// Start mock SOCKS5 server on random localhost port
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()

	port := listener.Addr().(*net.TCPAddr).Port

	// Mock SOCKS5 server loop
	go func() {
		conn, err := listener.Accept()
		if err != nil {
			return
		}
		defer conn.Close()

		greeting := make([]byte, 3)
		if _, err := io.ReadFull(conn, greeting); err != nil {
			return
		}
		if greeting[0] == 0x05 && greeting[1] == 0x01 && greeting[2] == 0x00 {
			// Reply VER=5, METHOD=0 (no auth accepted)
			_, _ = conn.Write([]byte{0x05, 0x00})
		}
	}()

	mgr := &Manager{
		bindAddress: "127.0.0.1",
		socksPort:   port,
	}

	if err := mgr.syntheticSocksHandshake(); err != nil {
		t.Errorf("syntheticSocksHandshake failed: %v", err)
	}
}

func TestSyntheticDNSQuery(t *testing.T) {
	// Start mock UDP DNS server on random localhost port
	udpAddr, err := net.ResolveUDPAddr("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	conn, err := net.ListenUDP("udp", udpAddr)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()

	port := conn.LocalAddr().(*net.UDPAddr).Port

	// Mock DNS server responder
	go func() {
		buf := make([]byte, 512)
		n, clientAddr, err := conn.ReadFrom(buf)
		if err != nil {
			return
		}
		if n >= 12 {
			// Construct mock DNS response: set QR bit (response)
			resp := make([]byte, n)
			copy(resp, buf[:n])
			resp[2] |= 0x80 // QR = 1 (response)
			_, _ = conn.WriteTo(resp, clientAddr)
		}
	}()

	mgr := &Manager{
		bindAddress: "127.0.0.1",
		dnsPort:     port,
	}

	if err := mgr.syntheticDNSQuery(); err != nil {
		t.Errorf("syntheticDNSQuery failed: %v", err)
	}
}

func TestAuthenticateControlCookie(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "tux_auth_test_*")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(tmpDir)

	cookiePath := filepath.Join(tmpDir, "control_auth_cookie")
	cookieBytes := make([]byte, 32)
	_, _ = rand.Read(cookieBytes)
	if err := os.WriteFile(cookiePath, cookieBytes, 0600); err != nil {
		t.Fatal(err)
	}

	sockPath := filepath.Join(tmpDir, "control.sock")
	listener, err := net.Listen("unix", sockPath)
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()

	expectedHex := strings.ToUpper(hex.EncodeToString(cookieBytes))

	// Mock Tor Control listener
	go func() {
		conn, err := listener.Accept()
		if err != nil {
			return
		}
		defer conn.Close()

		buf := make([]byte, 256)
		n, err := conn.Read(buf)
		if err != nil {
			return
		}
		cmd := string(buf[:n])
		if strings.TrimSpace(cmd) == "AUTHENTICATE "+expectedHex {
			_, _ = conn.Write([]byte("250 OK\r\n"))
		} else {
			_, _ = conn.Write([]byte("515 Authentication failed\r\n"))
		}
	}()

	mgr := &Manager{
		controlSocketPath: sockPath,
		cookieAuthPath:    cookiePath,
		opts: ManagerOptions{
			UseCookieAuth: true,
		},
	}

	conn, err := mgr.dialControl()
	if err != nil {
		t.Fatalf("dialControl failed: %v", err)
	}
	defer conn.Close()

	if err := mgr.authenticateControl(conn); err != nil {
		t.Errorf("authenticateControl failed: %v", err)
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
