package main

import (
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"strings"
	"testing"
	"tuxproxy/internal/leak"
)

func TestLeakerBinaryBasics(t *testing.T) {
	// 1. Test build of leaker
	leakerBin := "./tux-leaker"
	if _, err := os.Stat(leakerBin); os.IsNotExist(err) {
		cmd := exec.Command("go", "build", "-o", leakerBin, "./leaker.go")
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("failed to build tux-leaker: %s (%v)", string(out), err)
		}
	}
	defer os.Remove(leakerBin)

	// 2. Test IPv6 unreachable on loopback dummy
	cmd := exec.Command(leakerBin, "ipv6", "--target", "[2001:db8::1]:8888", "--timeout", "200ms")
	out, err := cmd.CombinedOutput()
	// Should exit 0 (blocked) since 2001:db8::1 is unreachable/unassigned
	if err != nil {
		t.Fatalf("leaker ipv6 unexpected exit code: %v (output: %s)", err, string(out))
	}
	if !strings.Contains(string(out), "[BLOCKED:IPV6]") {
		t.Errorf("expected [BLOCKED:IPV6] in output: %s", string(out))
	}

	// 3. Test TCP unreachable on dummy TEST-NET-2 IP
	cmd = exec.Command(leakerBin, "tcp", "--target", "198.51.100.1:55555", "--timeout", "200ms")
	out, err = cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("leaker tcp unexpected exit code: %v (output: %s)", err, string(out))
	}
	if !strings.Contains(string(out), "[BLOCKED:TCP]") {
		t.Errorf("expected [BLOCKED:TCP] in output: %s", string(out))
	}
}

// TestPrivilegedNetNSLeakProof executes kernel-level verification if running as root
func TestPrivilegedNetNSLeakProof(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("[SKIP:PRIVILEGED] TestPrivilegedNetNSLeakProof requires root/sudo with CAP_NET_ADMIN.")
	}

	subnetID := 214
	sessionID := "test-leak-214"
	engine := leak.NewNetNSEngine(leak.NetNSConfig{
		SessionID:    sessionID,
		SubnetID:     subnetID,
		TorSocksPort: 9050,
		TorDNSPort:   9053,
	})

	// Setup mock listeners on gateway address (10.200.214.1)
	gwIP := fmt.Sprintf("10.200.%d.1", subnetID)

	// Setup Network Namespace & nftables
	if err := engine.Setup(); err != nil {
		t.Fatalf("NetNS Setup failed: %v", err)
	}
	defer func() {
		_ = engine.Teardown()
	}()

	// 1. Mock Tor SOCKS listener on 10.200.214.1:9050
	socksListener, err := net.Listen("tcp", fmt.Sprintf("%s:9050", gwIP))
	if err != nil {
		t.Fatalf("failed to bind mock SOCKS listener on %s:9050: %v", gwIP, err)
	}
	defer socksListener.Close()

	// Mock SOCKS5 handshake responder
	go func() {
		for {
			conn, err := socksListener.Accept()
			if err != nil {
				return
			}
			buf := make([]byte, 3)
			_, _ = io.ReadFull(conn, buf)
			_, _ = conn.Write([]byte{0x05, 0x00})
			conn.Close()
		}
	}()

	// 2. Mock Tor DNS listener on 10.200.214.1:9053
	dnsAddr, err := net.ResolveUDPAddr("udp", fmt.Sprintf("%s:9053", gwIP))
	if err != nil {
		t.Fatal(err)
	}
	dnsConn, err := net.ListenUDP("udp", dnsAddr)
	if err != nil {
		t.Fatalf("failed to bind mock DNS listener on %s:9053: %v", gwIP, err)
	}
	defer dnsConn.Close()

	// Mock DNS responder
	dnsPacketsReceived := 0
	go func() {
		buf := make([]byte, 512)
		for {
			n, clientAddr, err := dnsConn.ReadFrom(buf)
			if err != nil {
				return
			}
			dnsPacketsReceived++
			if n >= 12 {
				resp := make([]byte, n)
				copy(resp, buf[:n])
				resp[2] |= 0x80 // QR=1 (response)
				_, _ = dnsConn.WriteTo(resp, clientAddr)
			}
		}
	}()

	leakerBin, err := os.Executable()
	if err != nil {
		leakerBin = "./tux-leaker"
	}
	_ = leakerBin

	// Build leaker if needed
	leakerPath := "/tmp/tux-leaker-test"
	buildCmd := exec.Command("go", "build", "-o", leakerPath, "./leaker.go")
	if out, err := buildCmd.CombinedOutput(); err != nil {
		t.Fatalf("build leaker failed: %s (%v)", string(out), err)
	}
	defer os.Remove(leakerPath)

	// TEST A: Direct TCP connect to external address (MUST BE BLOCKED)
	cmdTCP := engine.ExecCommand(leakerPath, []string{"tcp", "--target", "198.51.100.1:8888", "--timeout", "500ms"}, nil)
	outTCP, errTCP := cmdTCP.CombinedOutput()
	if errTCP != nil {
		t.Errorf("expected exit code 0 (blocked), got: %v (output: %s)", errTCP, string(outTCP))
	}
	if !strings.Contains(string(outTCP), "[BLOCKED:TCP]") {
		t.Errorf("expected [BLOCKED:TCP], got: %s", string(outTCP))
	}

	// TEST B: Direct IPv6 connect (MUST BE BLOCKED)
	cmdIPv6 := engine.ExecCommand(leakerPath, []string{"ipv6", "--target", "[2001:db8::1]:80", "--timeout", "500ms"}, nil)
	outIPv6, errIPv6 := cmdIPv6.CombinedOutput()
	if errIPv6 != nil {
		t.Errorf("expected exit code 0 (blocked), got: %v (output: %s)", errIPv6, string(outIPv6))
	}
	if !strings.Contains(string(outIPv6), "[BLOCKED:IPV6]") {
		t.Errorf("expected [BLOCKED:IPV6], got: %s", string(outIPv6))
	}

	// TEST C: Raw external DNS query to 9.9.9.9:53 (MUST BE DNAT-INTERCEPTED to 10.200.214.1:9053)
	cmdDNS := engine.ExecCommand(leakerPath, []string{"dns", "--server", "9.9.9.9:53", "--timeout", "1000ms"}, nil)
	outDNS, errDNS := cmdDNS.CombinedOutput()
	if errDNS != nil {
		t.Errorf("DNS query unexpected error: %v (output: %s)", errDNS, string(outDNS))
	}
	if !strings.Contains(string(outDNS), "[INTERCEPTED:DNS]") {
		t.Errorf("expected [INTERCEPTED:DNS], got: %s", string(outDNS))
	}
	if dnsPacketsReceived == 0 {
		t.Errorf("expected DNS packet to hit gateway mock listener on 10.200.214.1:9053")
	}

	// TEST D: Fail-Closed Kill Switch Verification
	// Launch background loop child
	loopCmd := engine.ExecCommand(leakerPath, []string{"loop"}, nil)
	if err := loopCmd.Start(); err != nil {
		t.Fatalf("failed to start loop child: %v", err)
	}

	// Immediate teardown simulating Tor failure kill-switch
	if err := engine.Teardown(); err != nil {
		t.Errorf("Teardown error: %v", err)
	}

	// Terminate child
	_ = loopCmd.Process.Kill()
	_ = loopCmd.Wait()

	// Verify namespace is removed
	checkCmd := exec.Command("ip", "netns", "list")
	checkOut, _ := checkCmd.CombinedOutput()
	if strings.Contains(string(checkOut), engine.NetNSName()) {
		t.Errorf("namespace was not pruned after teardown: %s", string(checkOut))
	}
}
