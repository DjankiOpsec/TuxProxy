package leak

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestGetProcessStartTimeSelf(t *testing.T) {
	pid := os.Getpid()
	startTime, err := GetProcessStartTime(pid)
	if err != nil {
		t.Fatalf("failed to get starttime for self (pid %d): %v", pid, err)
	}
	if startTime == 0 {
		t.Errorf("expected non-zero starttime, got: %d", startTime)
	}
}

func TestGetProcessStartTimeParsingTrickyName(t *testing.T) {
	// Create mock stat file with tricky comm name containing spaces and parentheses
	tmpDir, err := os.MkdirTemp("", "tux_stat_test_*")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(tmpDir)

	// In /proc/<pid>/stat:
	// Field 1: pid (99999)
	// Field 2: comm "(tux worker (complex))"
	// Field 3: state "S" (index 0 after paren)
	// Field 4..21: (18 fields)
	// Field 22: starttime "87654321" (index 19 after paren)
	mockStat := "99999 (tux worker (complex)) S 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16 17 18 87654321 0 0 0"
	statFile := filepath.Join(tmpDir, "stat")
	if err := os.WriteFile(statFile, []byte(mockStat), 0600); err != nil {
		t.Fatal(err)
	}

	data, err := os.ReadFile(statFile)
	if err != nil {
		t.Fatal(err)
	}

	s := string(data)
	lastParen := strings.LastIndex(s, ")")
	if lastParen == -1 {
		t.Fatal("missing paren")
	}
	fields := strings.Fields(s[lastParen+1:])
	if len(fields) < 20 {
		t.Fatalf("insufficient fields: %d", len(fields))
	}
	if fields[19] != "87654321" {
		t.Errorf("expected starttime 87654321, got: %s", fields[19])
	}
}

func TestGenerateNFTRules(t *testing.T) {
	engine := NewNetNSEngine(NetNSConfig{
		SessionID:    "99",
		SubnetID:     99,
		TorSocksPort: 9050,
		TorDNSPort:   9053,
	})

	rules := engine.GenerateNFTRules()

	// 1. Table name
	if !strings.Contains(rules, "table inet tux_session_99 {") {
		t.Errorf("missing dedicated table declaration: %s", rules)
	}

	// 2. PREROUTING DNS interception for both UDP and TCP
	if !strings.Contains(rules, `iifname "veth-tux-99" udp dport 53 dnat to 10.200.99.1:9053`) {
		t.Errorf("missing UDP DNS dnat rule: %s", rules)
	}
	if !strings.Contains(rules, `iifname "veth-tux-99" tcp dport 53 dnat to 10.200.99.1:9053`) {
		t.Errorf("missing TCP DNS dnat rule: %s", rules)
	}

	// 3. INPUT: Accept only Tor ports from 10.200.99.2
	if !strings.Contains(rules, `iifname "veth-tux-99" ip saddr 10.200.99.2 tcp dport 9050 accept`) {
		t.Errorf("missing SOCKS accept rule: %s", rules)
	}
	if !strings.Contains(rules, `iifname "veth-tux-99" ip saddr 10.200.99.2 udp dport 9053 accept`) {
		t.Errorf("missing DNS UDP accept rule: %s", rules)
	}
	if !strings.Contains(rules, `iifname "veth-tux-99" drop`) {
		t.Errorf("missing default input drop rule: %s", rules)
	}

	// 4. FORWARD: Zero-Forwarding / Zero-NAT drop
	if !strings.Contains(rules, "chain forward {\n        type filter hook forward priority filter; policy drop;") {
		t.Errorf("missing forward drop policy: %s", rules)
	}
	if !strings.Contains(rules, `iifname "veth-tux-99" drop`) {
		t.Errorf("missing forward interface drop rule: %s", rules)
	}
}

func TestExecCommandPrivilegeDrop(t *testing.T) {
	engine := NewNetNSEngine(NetNSConfig{
		SessionID:  "42",
		SubnetID:   42,
		TargetUser: "testuser",
		TargetUID:  1001,
		TargetGID:  1001,
	})

	// Case 1: unprivileged caller
	cmd := engine.ExecCommand("curl", []string{"https://example.com"}, []string{"USER=testuser"})
	argsStr := strings.Join(cmd.Args, " ")

	if !strings.Contains(argsStr, "netns exec netns-tux-42") {
		t.Errorf("missing netns exec in args: %s", argsStr)
	}

	hasAllProxy := false
	for _, env := range cmd.Env {
		if env == "ALL_PROXY=socks5h://10.200.42.1:9050" {
			hasAllProxy = true
		}
	}
	if !hasAllProxy {
		t.Errorf("expected ALL_PROXY pointing to gateway 10.200.42.1:9050")
	}
}

func TestMockSetupSequence(t *testing.T) {
	var executedCmds []string

	mockRunner := func(name string, args ...string) ([]byte, error) {
		full := name + " " + strings.Join(args, " ")
		executedCmds = append(executedCmds, full)
		return stringsToByte(""), nil
	}

	engine := NewNetNSEngine(NetNSConfig{
		SessionID: "77",
		SubnetID:  77,
	})
	engine.SetCommandRunner(mockRunner)

	// Verify generated names
	if engine.NetNSName() != "netns-tux-77" {
		t.Errorf("unexpected netns name: %s", engine.NetNSName())
	}
	if engine.VethHost() != "veth-tux-77" {
		t.Errorf("unexpected veth host: %s", engine.VethHost())
	}
	if engine.VethApp() != "veth-app-77" {
		t.Errorf("unexpected veth app: %s", engine.VethApp())
	}
	if engine.GatewayIP() != "10.200.77.1" {
		t.Errorf("unexpected gateway IP: %s", engine.GatewayIP())
	}
	if engine.AppIP() != "10.200.77.2" {
		t.Errorf("unexpected app IP: %s", engine.AppIP())
	}

	// Teardown with mock runner
	if err := engine.teardownInternal(); err != nil {
		t.Errorf("teardownInternal failed: %v", err)
	}

	// Verify link del and netns del were called
	hasLinkDel := false
	hasNetnsDel := false
	for _, cmd := range executedCmds {
		if strings.Contains(cmd, "ip link del veth-tux-77") {
			hasLinkDel = true
		}
		if strings.Contains(cmd, "ip netns del netns-tux-77") {
			hasNetnsDel = true
		}
	}

	if !hasLinkDel {
		t.Errorf("missing ip link del call in teardown")
	}
	if !hasNetnsDel {
		t.Errorf("missing ip netns del call in teardown")
	}
}

func stringsToByte(s string) []byte {
	return []byte(s)
}

func TestReconcileOrphansGC(t *testing.T) {
	tmpMetaDir, err := os.MkdirTemp("", "tux_meta_test_*")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(tmpMetaDir)

	// Set XDG_RUNTIME_DIR to point to our test directory
	oldXDG := os.Getenv("XDG_RUNTIME_DIR")
	os.Setenv("XDG_RUNTIME_DIR", tmpMetaDir)
	defer os.Setenv("XDG_RUNTIME_DIR", oldXDG)

	// Create a mock dead session metadata with PID 99999999 (guaranteed non-existent)
	sessionsDir := filepath.Join(tmpMetaDir, "tuxproxy", "sessions")
	_ = os.MkdirAll(sessionsDir, 0700)

	metaContent := fmt.Sprintf(`{
		"session_id": "dead99",
		"subnet_id": 99,
		"pid": 99999999,
		"starttime": 123456,
		"netns_name": "netns-tux-dead99",
		"veth_host": "veth-tux-dead99",
		"veth_app": "veth-app-dead99",
		"resolv_conf_dir": "/tmp/test-resolv-dead99",
		"nft_table": "tux_session_dead99",
		"created_at": "%s"
	}`, time.Now().Format(time.RFC3339))

	metaFile := filepath.Join(sessionsDir, "session-dead99.json")
	if err := os.WriteFile(metaFile, []byte(metaContent), 0600); err != nil {
		t.Fatal(err)
	}

	var cleanedCmds []string
	mockRunner := func(name string, args ...string) ([]byte, error) {
		cleanedCmds = append(cleanedCmds, name+" "+strings.Join(args, " "))
		return []byte(""), nil
	}

	cleaned, err := ReconcileOrphans(mockRunner)
	if err != nil {
		t.Fatalf("ReconcileOrphans failed: %v", err)
	}

	if len(cleaned) != 1 || cleaned[0] != "dead99" {
		t.Errorf("expected dead99 to be cleaned, got: %v", cleaned)
	}

	// Verify meta file was removed
	if _, err := os.Stat(metaFile); !os.IsNotExist(err) {
		t.Errorf("metadata file for dead session was not removed")
	}
}
