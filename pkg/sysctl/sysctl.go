package sysctl

import (
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

// Default Linux kernel keepalive values
const (
	DefaultKeepaliveTime   = 7200 // 2 hours
	DefaultKeepaliveIntvl  = 75   // 75 seconds
	DefaultKeepaliveProbes = 9    // 9 unanswered probes
)

// KeepaliveConfig holds the parsed TCP keepalive sysctl configuration.
type KeepaliveConfig struct {
	KeepaliveTimeSeconds   int    `json:"tcp_keepalive_time_sec"`
	KeepaliveIntvlSeconds  int    `json:"tcp_keepalive_intvl_sec"`
	KeepaliveProbes        int    `json:"tcp_keepalive_probes"`
	ProcRoot               string `json:"proc_root"`
	Source                 string `json:"source"` // "kernel_proc" or "fallback_defaults"
}

// ReadKeepalive reads TCP keepalive parameters from the specified proc filesystem root.
// If procRoot is empty, it defaults to "/proc".
func ReadKeepalive(procRoot string) (*KeepaliveConfig, error) {
	if procRoot == "" {
		procRoot = "/proc"
	}

	netPath := filepath.Join(procRoot, "sys", "net", "ipv4")

	timeVal, errTime := readIntFile(filepath.Join(netPath, "tcp_keepalive_time"))
	intvlVal, errIntvl := readIntFile(filepath.Join(netPath, "tcp_keepalive_intvl"))
	probesVal, errProbes := readIntFile(filepath.Join(netPath, "tcp_keepalive_probes"))

	cfg := &KeepaliveConfig{
		KeepaliveTimeSeconds:  DefaultKeepaliveTime,
		KeepaliveIntvlSeconds: DefaultKeepaliveIntvl,
		KeepaliveProbes:       DefaultKeepaliveProbes,
		ProcRoot:              procRoot,
		Source:                "kernel_proc",
	}

	// If none of the files could be read, return defaults with indicator
	if errTime != nil && errIntvl != nil && errProbes != nil {
		cfg.Source = "fallback_defaults"
		return cfg, nil
	}

	if errTime == nil {
		cfg.KeepaliveTimeSeconds = timeVal
	}
	if errIntvl == nil {
		cfg.KeepaliveIntvlSeconds = intvlVal
	}
	if errProbes == nil {
		cfg.KeepaliveProbes = probesVal
	}

	return cfg, nil
}

func readIntFile(filePath string) (int, error) {
	data, err := os.ReadFile(filePath)
	if err != nil {
		return 0, err
	}

	trimmed := strings.TrimSpace(string(data))
	val, err := strconv.Atoi(trimmed)
	if err != nil {
		return 0, fmt.Errorf("invalid integer in %s: %w", filePath, err)
	}

	return val, nil
}
