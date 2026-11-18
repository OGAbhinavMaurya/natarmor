package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"net"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/OGAbhinavMaurya/natarmor/pkg/sentry"
	"github.com/OGAbhinavMaurya/natarmor/pkg/shield"
	"github.com/OGAbhinavMaurya/natarmor/pkg/sysctl"
)

const version = "1.0.0"

func main() {
	if len(os.Args) < 2 {
		printUsage()
		os.Exit(1)
	}

	command := os.Args[1]
	args := os.Args[2:]

	var err error
	switch command {
	case "audit":
		err = runAudit(args)
	case "doctor":
		err = runDoctor(args)
	case "shield":
		err = runShield(args)
	case "version", "-v", "--version":
		fmt.Printf("natarmor version %s\n", version)
		return
	case "help", "-h", "--help":
		printUsage()
		return
	default:
		fmt.Fprintf(os.Stderr, "Unknown command: %s\n\n", command)
		printUsage()
		os.Exit(1)
	}

	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
}

func printUsage() {
	usage := `natarmor - Cloud NAT Gateway idle timeout sentry and keepalive shield

Usage:
  natarmor <command> [options]

Commands:
  audit      Audit host/container sysctl keepalives against Cloud NAT timeouts
  doctor     Probe target endpoint and evaluate connection eviction risk
  shield     Run transparent loopback proxy forcing low-interval TCP keepalive probes
  version    Show natarmor version
  help       Show this help message

Audit Options:
  --cloud        Target cloud provider (aws, azure, gcp) [default: aws]
  --proc-root    Path to proc filesystem [default: /proc]
  --json         Output audit report in JSON format

Doctor Options:
  --target       Target host:port endpoint to probe [default: 127.0.0.1:80]
  --cloud        Target cloud provider (aws, azure, gcp) [default: aws]
  --timeout      Probe connection timeout [default: 5s]
  --json         Output doctor report in JSON format

Shield Options:
  --listen           Local loopback listen address [default: 127.0.0.1:8080]
  --upstream         Upstream target host:port address
  --keepalive-idle   Idle time before sending keepalive probes [default: 60s]
  --keepalive-intvl  Interval between keepalive probes [default: 15s]
  --json             Output startup status in JSON format

Examples:
  natarmor audit --cloud aws
  natarmor audit --cloud azure --json
  natarmor doctor --target api.stripe.com:443 --cloud aws
  natarmor shield --listen 127.0.0.1:5432 --upstream db-prod.internal:5432
`
	fmt.Print(usage)
}

func runAudit(args []string) error {
	fs := flag.NewFlagSet("audit", flag.ContinueOnError)
	cloudName := fs.String("cloud", "aws", "Target cloud provider")
	procRoot := fs.String("proc-root", "/proc", "Path to proc filesystem")
	jsonOutput := fs.Bool("json", false, "Output in JSON format")

	if err := fs.Parse(args); err != nil {
		return err
	}

	cloud, err := sentry.GetCloudProvider(*cloudName)
	if err != nil {
		return err
	}

	cfg, err := sysctl.ReadKeepalive(*procRoot)
	if err != nil {
		return fmt.Errorf("failed to read sysctl keepalives: %w", err)
	}

	report := sentry.AuditKeepalive(cfg, cloud)

	if *jsonOutput {
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		return enc.Encode(report)
	}

	fmt.Println("================================================================================")
	fmt.Println("                           NATARMOR AUDIT REPORT                                ")
	fmt.Println("================================================================================")
	fmt.Printf(" Cloud Provider:            %s (%s)\n", report.Cloud.Name, report.Cloud.Service)
	fmt.Printf(" NAT Idle Timeout:          %d seconds (Silent Eviction: %v)\n",
		report.Cloud.IdleTimeoutSeconds, report.Cloud.SilentDrop)
	fmt.Printf(" System tcp_keepalive_time: %d seconds (Source: %s)\n",
		report.Sysctl.KeepaliveTimeSeconds, report.Sysctl.Source)
	fmt.Printf(" Hazard Delta:              %+d seconds\n", report.HazardDeltaSeconds)
	fmt.Printf(" Status:                    [%s]\n", report.Severity)
	fmt.Printf(" Summary:                   %s\n", report.Summary)
	fmt.Println("--------------------------------------------------------------------------------")
	fmt.Println(" Application Connection Pool Audit:")
	for _, app := range report.AppAudits {
		status := "SAFE"
		if app.Vulnerable {
			status = "VULNERABLE"
		}
		fmt.Printf("   * [%-10s] %-8s %-25s (Default: %ds) -> %s\n",
			status, app.Runtime, app.Library, app.DefaultIdleSeconds, app.Mitigation)
	}
	fmt.Println("--------------------------------------------------------------------------------")
	fmt.Println(" Recommendations:")
	for _, rec := range report.Recommendations {
		fmt.Printf("   * %s\n", rec)
	}
	fmt.Println("================================================================================")

	return nil
}

type DoctorReport struct {
	Target             string `json:"target"`
	Cloud              string `json:"cloud"`
	CloudNATTimeoutSec int    `json:"cloud_nat_timeout_sec"`
	Reachable          bool   `json:"reachable"`
	LatencyMs          int64  `json:"latency_ms"`
	KeepaliveTimeSec   int    `json:"tcp_keepalive_time_sec"`
	EvictionVulnerable bool   `json:"eviction_vulnerable"`
	Diagnosis          string `json:"diagnosis"`
}

func runDoctor(args []string) error {
	fs := flag.NewFlagSet("doctor", flag.ContinueOnError)
	target := fs.String("target", "127.0.0.1:80", "Target host:port")
	cloudName := fs.String("cloud", "aws", "Target cloud provider")
	timeout := fs.Duration("timeout", 5*time.Second, "Connection timeout")
	jsonOutput := fs.Bool("json", false, "Output in JSON format")

	if err := fs.Parse(args); err != nil {
		return err
	}

	cloud, err := sentry.GetCloudProvider(*cloudName)
	if err != nil {
		return err
	}

	cfg, _ := sysctl.ReadKeepalive("/proc")
	if cfg == nil {
		cfg = &sysctl.KeepaliveConfig{
			KeepaliveTimeSeconds: sysctl.DefaultKeepaliveTime,
		}
	}

	start := time.Now()
	conn, err := net.DialTimeout("tcp", *target, *timeout)
	latency := time.Since(start).Milliseconds()

	reachable := (err == nil)
	if reachable {
		_ = conn.Close()
	}

	vulnerable := cfg.KeepaliveTimeSeconds > cloud.IdleTimeoutSeconds
	var diag string
	if !reachable {
		diag = fmt.Sprintf("Target %s unreachable: %v", *target, err)
	} else if vulnerable {
		diag = fmt.Sprintf("Socket connections to %s crossing %ds idle will be silently dropped by %s NAT Gateway before OS keepalive (%ds) triggers",
			*target, cloud.IdleTimeoutSeconds, cloud.Name, cfg.KeepaliveTimeSeconds)
	} else {
		diag = fmt.Sprintf("Socket keepalive (%ds) is within safe cloud NAT threshold (%ds)",
			cfg.KeepaliveTimeSeconds, cloud.IdleTimeoutSeconds)
	}

	docReport := DoctorReport{
		Target:             *target,
		Cloud:              cloud.Name,
		CloudNATTimeoutSec: cloud.IdleTimeoutSeconds,
		Reachable:          reachable,
		LatencyMs:          latency,
		KeepaliveTimeSec:   cfg.KeepaliveTimeSeconds,
		EvictionVulnerable: vulnerable,
		Diagnosis:          diag,
	}

	if *jsonOutput {
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		return enc.Encode(docReport)
	}

	fmt.Println("================================================================================")
	fmt.Println("                          NATARMOR DOCTOR REPORT                                ")
	fmt.Println("================================================================================")
	fmt.Printf(" Probe Target:              %s\n", docReport.Target)
	fmt.Printf(" Cloud NAT Threshold:       %d seconds (%s)\n", docReport.CloudNATTimeoutSec, docReport.Cloud)
	fmt.Printf(" Endpoint Reachable:        %v (Latency: %dms)\n", docReport.Reachable, docReport.LatencyMs)
	fmt.Printf(" OS Keepalive Idle Time:    %d seconds\n", docReport.KeepaliveTimeSec)
	fmt.Printf(" Silent Drop Risk:          %v\n", docReport.EvictionVulnerable)
	fmt.Printf(" Diagnosis:                 %s\n", docReport.Diagnosis)
	fmt.Println("================================================================================")

	return nil
}

func runShield(args []string) error {
	fs := flag.NewFlagSet("shield", flag.ContinueOnError)
	listenAddr := fs.String("listen", "127.0.0.1:8080", "Local listen address")
	upstreamAddr := fs.String("upstream", "", "Upstream target host:port")
	keepaliveIdle := fs.Duration("keepalive-idle", 60*time.Second, "Keepalive idle duration")
	keepaliveIntvl := fs.Duration("keepalive-intvl", 15*time.Second, "Keepalive interval duration")
	jsonOutput := fs.Bool("json", false, "Output in JSON format")

	if err := fs.Parse(args); err != nil {
		return err
	}

	if *upstreamAddr == "" {
		return fmt.Errorf("--upstream flag is required (e.g. --upstream db-prod.internal:5432)")
	}

	proxy, err := shield.NewShieldProxy(shield.ProxyConfig{
		ListenAddr:     *listenAddr,
		UpstreamAddr:   *upstreamAddr,
		KeepaliveIdle:  *keepaliveIdle,
		KeepaliveIntvl: *keepaliveIntvl,
	})
	if err != nil {
		return fmt.Errorf("failed to start shield proxy: %w", err)
	}
	defer proxy.Close()

	if *jsonOutput {
		status := map[string]interface{}{
			"status":            "running",
			"listen_addr":       proxy.Addr(),
			"upstream_addr":     *upstreamAddr,
			"keepalive_idle_sec": keepaliveIdle.Seconds(),
			"keepalive_intvl_sec": keepaliveIntvl.Seconds(),
		}
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		_ = enc.Encode(status)
	} else {
		fmt.Println("================================================================================")
		fmt.Println("                          NATARMOR SHIELD PROXY                                 ")
		fmt.Println("================================================================================")
		fmt.Printf(" Listening on:              %s\n", proxy.Addr())
		fmt.Printf(" Forwarding upstream to:    %s\n", *upstreamAddr)
		fmt.Printf(" Keepalive Idle Period:     %.0f seconds\n", keepaliveIdle.Seconds())
		fmt.Printf(" Keepalive Probe Interval:  %.0f seconds\n", keepaliveIntvl.Seconds())
		fmt.Println(" Status:                    Active. Press Ctrl+C to terminate.")
		fmt.Println("================================================================================")
	}

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, os.Interrupt, syscall.SIGTERM)
	<-sigCh

	return nil
}
