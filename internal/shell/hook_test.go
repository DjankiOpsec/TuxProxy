package shell

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
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
		"case \"$-\" in",
		"[ -z \"$PS1\" ] && return 0 2>/dev/null",
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

func TestHookIdempotency(t *testing.T) {
	tmpDir := t.TempDir()
	lockPath := filepath.Join(tmpDir, "tuxproxy.lock")
	t.Setenv("TUXPROXY_LOCK_FILE", lockPath)

	rcFile := filepath.Join(tmpDir, ".bashrc")
	initialContent := "# User bashrc\nalias ll='ls -la'\nexport PATH=/usr/local/bin:$PATH\n"
	if err := os.WriteFile(rcFile, []byte(initialContent), 0644); err != nil {
		t.Fatalf("failed to create test file: %v", err)
	}

	// 1st Install
	if err := InstallHookFiles([]string{rcFile}); err != nil {
		t.Fatalf("InstallHookFiles failed: %v", err)
	}

	data1, err := os.ReadFile(rcFile)
	if err != nil {
		t.Fatalf("failed to read rc file: %v", err)
	}
	content1 := string(data1)

	if strings.Count(content1, hookStartMarker) != 1 {
		t.Fatalf("expected exactly 1 start marker, got %d", strings.Count(content1, hookStartMarker))
	}
	if strings.Count(content1, hookEndMarker) != 1 {
		t.Fatalf("expected exactly 1 end marker, got %d", strings.Count(content1, hookEndMarker))
	}
	if !strings.Contains(content1, "alias ll='ls -la'") {
		t.Fatalf("user alias was lost during installation")
	}

	backups1, err := ListBackups(rcFile)
	if err != nil {
		t.Fatalf("ListBackups failed: %v", err)
	}
	if len(backups1) != 1 {
		t.Fatalf("expected 1 backup after 1st install, got %d", len(backups1))
	}

	// 2nd Install (should be idempotent no-op: no extra backup, content identical)
	if err := InstallHookFiles([]string{rcFile}); err != nil {
		t.Fatalf("2nd InstallHookFiles failed: %v", err)
	}

	data2, err := os.ReadFile(rcFile)
	if err != nil {
		t.Fatalf("failed to read rc file: %v", err)
	}
	if string(data2) != content1 {
		t.Fatalf("idempotent call changed file content")
	}

	backups2, err := ListBackups(rcFile)
	if err != nil {
		t.Fatalf("ListBackups failed: %v", err)
	}
	if len(backups2) != 1 {
		t.Fatalf("idempotent call created redundant backup; count: %d", len(backups2))
	}
}

func TestHookIsolationAndPreservation(t *testing.T) {
	tmpDir := t.TempDir()
	lockPath := filepath.Join(tmpDir, "tuxproxy.lock")
	t.Setenv("TUXPROXY_LOCK_FILE", lockPath)

	rcFile := filepath.Join(tmpDir, ".zshrc")
	userHeader := "# Custom User ZSH Config\nexport EDITOR=nvim\nalias k=kubectl"
	userFooter := "alias gs='git status'\neval \"$(starship init zsh)\""
	initialContent := fmt.Sprintf("%s\n\n%s\n", userHeader, userFooter)

	if err := os.WriteFile(rcFile, []byte(initialContent), 0600); err != nil {
		t.Fatalf("failed to create rc file: %v", err)
	}

	// Install hook
	if err := InstallHookFiles([]string{rcFile}); err != nil {
		t.Fatalf("InstallHookFiles failed: %v", err)
	}

	// Verify both user blocks preserved
	data, _ := os.ReadFile(rcFile)
	installedContent := string(data)
	if !strings.Contains(installedContent, userHeader) {
		t.Fatalf("userHeader lost after install")
	}
	if !strings.Contains(installedContent, userFooter) {
		t.Fatalf("userFooter lost after install")
	}
	if !strings.Contains(installedContent, hookStartMarker) {
		t.Fatalf("hookStartMarker missing")
	}

	// Remove hook (UninstallHookFiles)
	if err := UninstallHookFiles([]string{rcFile}); err != nil {
		t.Fatalf("UninstallHookFiles failed: %v", err)
	}

	cleanedData, _ := os.ReadFile(rcFile)
	cleanedContent := string(cleanedData)

	if strings.Contains(cleanedContent, hookStartMarker) || strings.Contains(cleanedContent, hookEndMarker) {
		t.Fatalf("hook markers still present after uninstall")
	}
	if !strings.Contains(cleanedContent, userHeader) {
		t.Fatalf("userHeader was mangled during uninstall")
	}
	if !strings.Contains(cleanedContent, userFooter) {
		t.Fatalf("userFooter was mangled during uninstall")
	}

	// Permissions preserved (0600)
	info, err := os.Stat(rcFile)
	if err != nil {
		t.Fatalf("stat failed: %v", err)
	}
	if info.Mode().Perm() != 0600 {
		t.Fatalf("expected perm 0600, got %o", info.Mode().Perm())
	}
}

func TestBackupRetentionPolicy(t *testing.T) {
	tmpDir := t.TempDir()
	lockPath := filepath.Join(tmpDir, "tuxproxy.lock")
	t.Setenv("TUXPROXY_LOCK_FILE", lockPath)

	rcFile := filepath.Join(tmpDir, ".bashrc")
	initialContent := "# Version 0\n"
	if err := os.WriteFile(rcFile, []byte(initialContent), 0644); err != nil {
		t.Fatalf("failed to create rcFile: %v", err)
	}

	// Generate 5 distinct revisions to trigger backup retention pruning (strictly keep 3)
	for i := 1; i <= 5; i++ {
		// Small delay to ensure strictly distinct timestamp
		time.Sleep(10 * time.Millisecond)

		// Modify file content
		content := fmt.Sprintf("# Version %d\n", i)
		if err := os.WriteFile(rcFile, []byte(content), 0644); err != nil {
			t.Fatalf("failed to update rcFile: %v", err)
		}

		if err := InstallHookFiles([]string{rcFile}); err != nil {
			t.Fatalf("InstallHookFiles iteration %d failed: %v", i, err)
		}
	}

	backups, err := ListBackups(rcFile)
	if err != nil {
		t.Fatalf("ListBackups failed: %v", err)
	}

	if len(backups) != maxBackups {
		t.Fatalf("expected strictly %d backups retained, got %d: %v", maxBackups, len(backups), backups)
	}

	// Test restoration of the latest backup
	if err := RestoreLatestBackup(rcFile); err != nil {
		t.Fatalf("RestoreLatestBackup failed: %v", err)
	}

	restoredData, err := os.ReadFile(rcFile)
	if err != nil {
		t.Fatalf("failed to read restored file: %v", err)
	}

	// The latest backup before the 5th install was Version 5 without the hook or with previous version
	if !strings.Contains(string(restoredData), "# Version 5") {
		t.Fatalf("restored data did not match expected latest backup; content:\n%s", string(restoredData))
	}
}

func TestAtomicWriteAndTempCleanup(t *testing.T) {
	tmpDir := t.TempDir()
	targetFile := filepath.Join(tmpDir, ".custom_rc")
	testData := []byte("alias secret='ssh user@box'\n")

	if err := atomicWriteFileWithFsync(targetFile, testData, 0600); err != nil {
		t.Fatalf("atomicWriteFileWithFsync failed: %v", err)
	}

	// Verify file exists with exact content and permissions
	data, err := os.ReadFile(targetFile)
	if err != nil {
		t.Fatalf("failed to read target file: %v", err)
	}
	if string(data) != string(testData) {
		t.Fatalf("content mismatch")
	}

	info, err := os.Stat(targetFile)
	if err != nil {
		t.Fatalf("stat failed: %v", err)
	}
	if info.Mode().Perm() != 0600 {
		t.Fatalf("expected perm 0600, got %o", info.Mode().Perm())
	}

	// Verify no temporary files remain in tmpDir
	entries, err := os.ReadDir(tmpDir)
	if err != nil {
		t.Fatalf("ReadDir failed: %v", err)
	}
	for _, entry := range entries {
		if strings.Contains(entry.Name(), ".tmp.") {
			t.Fatalf("orphaned temp file found: %s", entry.Name())
		}
	}
}

func TestFlockConcurrency(t *testing.T) {
	tmpDir := t.TempDir()
	lockPath := filepath.Join(tmpDir, "tuxproxy.lock")
	t.Setenv("TUXPROXY_LOCK_FILE", lockPath)

	rcFile := filepath.Join(tmpDir, ".bashrc")
	if err := os.WriteFile(rcFile, []byte("# Initial user content\n"), 0644); err != nil {
		t.Fatalf("failed to init file: %v", err)
	}

	var wg sync.WaitGroup
	workers := 8

	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			for j := 0; j < 5; j++ {
				if id%2 == 0 {
					_ = InstallHookFiles([]string{rcFile})
				} else {
					_ = UninstallHookFiles([]string{rcFile})
				}
			}
		}(i)
	}

	wg.Wait()

	// Final verification: file should be valid, readable, and contain initial content
	data, err := os.ReadFile(rcFile)
	if err != nil {
		t.Fatalf("rcFile corrupted after concurrent access: %v", err)
	}
	if !strings.Contains(string(data), "# Initial user content") {
		t.Fatalf("initial user content lost during concurrent modifications")
	}
}

func TestNonInteractiveGuardBehavior(t *testing.T) {
	tmpDir := t.TempDir()
	lockPath := filepath.Join(tmpDir, "tuxproxy.lock")
	t.Setenv("TUXPROXY_LOCK_FILE", lockPath)

	rcFile := filepath.Join(tmpDir, ".bashrc")
	if err := InstallHookFiles([]string{rcFile}); err != nil {
		t.Fatalf("InstallHookFiles failed: %v", err)
	}

	// Append a marker that must NOT execute in non-interactive mode
	markerFile := filepath.Join(tmpDir, "executed.txt")
	testBashrc := filepath.Join(tmpDir, "bashrc_with_probe")
	data, _ := os.ReadFile(rcFile)

	probeContent := fmt.Sprintf("%s\necho \"EXECUTED\" > %s\n", string(data), markerFile)
	if err := os.WriteFile(testBashrc, []byte(probeContent), 0644); err != nil {
		t.Fatalf("failed to write probe file: %v", err)
	}

	// Run bash non-interactively sourcing the test file
	cmd := exec.Command("bash", "-c", fmt.Sprintf(". %s", testBashrc))
	output, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("bash non-interactive source failed: %v, output: %s", err, string(output))
	}

	// Verify that non-interactive shell exited at the guard and did NOT reach the probe
	if _, err := os.Stat(markerFile); err == nil {
		t.Fatalf("non-interactive guard failed! Code after guard was executed")
	}
}
