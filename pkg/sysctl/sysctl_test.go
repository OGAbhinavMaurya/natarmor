package sysctl

import (
	"os"
	"path/filepath"
	"testing"
)

func TestReadKeepalive_MockProc(t *testing.T) {
	tempDir := t.TempDir()
	netPath := filepath.Join(tempDir, "sys", "net", "ipv4")
	if err := os.MkdirAll(netPath, 0755); err != nil {
		t.Fatalf("failed to create temp dir: %v", err)
	}

	if err := os.WriteFile(filepath.Join(netPath, "tcp_keepalive_time"), []byte("300\n"), 0644); err != nil {
		t.Fatalf("failed to write tcp_keepalive_time: %v", err)
	}
	if err := os.WriteFile(filepath.Join(netPath, "tcp_keepalive_intvl"), []byte("30\n"), 0644); err != nil {
		t.Fatalf("failed to write tcp_keepalive_intvl: %v", err)
	}
	if err := os.WriteFile(filepath.Join(netPath, "tcp_keepalive_probes"), []byte("5\n"), 0644); err != nil {
		t.Fatalf("failed to write tcp_keepalive_probes: %v", err)
	}

	cfg, err := ReadKeepalive(tempDir)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if cfg.KeepaliveTimeSeconds != 300 {
		t.Errorf("expected 300, got %d", cfg.KeepaliveTimeSeconds)
	}
	if cfg.KeepaliveIntvlSeconds != 30 {
		t.Errorf("expected 30, got %d", cfg.KeepaliveIntvlSeconds)
	}
	if cfg.KeepaliveProbes != 5 {
		t.Errorf("expected 5, got %d", cfg.KeepaliveProbes)
	}
	if cfg.Source != "kernel_proc" {
		t.Errorf("expected source 'kernel_proc', got %s", cfg.Source)
	}
}

func TestReadKeepalive_FallbackDefaults(t *testing.T) {
	tempDir := t.TempDir() // empty directory

	cfg, err := ReadKeepalive(tempDir)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if cfg.KeepaliveTimeSeconds != DefaultKeepaliveTime {
		t.Errorf("expected default %d, got %d", DefaultKeepaliveTime, cfg.KeepaliveTimeSeconds)
	}
	if cfg.KeepaliveIntvlSeconds != DefaultKeepaliveIntvl {
		t.Errorf("expected default %d, got %d", DefaultKeepaliveIntvl, cfg.KeepaliveIntvlSeconds)
	}
	if cfg.KeepaliveProbes != DefaultKeepaliveProbes {
		t.Errorf("expected default %d, got %d", DefaultKeepaliveProbes, cfg.KeepaliveProbes)
	}
	if cfg.Source != "fallback_defaults" {
		t.Errorf("expected source 'fallback_defaults', got %s", cfg.Source)
	}
}

func TestReadKeepalive_LiveKernel(t *testing.T) {
	// Should read host /proc or return defaults cleanly without panic or error
	cfg, err := ReadKeepalive("/proc")
	if err != nil {
		t.Fatalf("live /proc read failed: %v", err)
	}
	if cfg.KeepaliveTimeSeconds <= 0 {
		t.Errorf("invalid keepalive time: %d", cfg.KeepaliveTimeSeconds)
	}
}
