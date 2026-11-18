package sentry

import (
	"fmt"

	"github.com/OGAbhinavMaurya/natarmor/pkg/sysctl"
)

// AppAuditReport evaluates an application connection pool against cloud NAT timeout.
type AppAuditReport struct {
	Runtime            string `json:"runtime"`
	Library            string `json:"library"`
	DefaultIdleSeconds int    `json:"default_idle_seconds"`
	Vulnerable         bool   `json:"vulnerable"`
	HazardDeltaSeconds int    `json:"hazard_delta_seconds"`
	Mitigation         string `json:"mitigation"`
}

// AuditResult encapsulates the evaluation of OS sysctls and application pools against cloud limits.
type AuditResult struct {
	Cloud              CloudProvider          `json:"cloud"`
	Sysctl             sysctl.KeepaliveConfig `json:"sysctl"`
	HazardDeltaSeconds int                    `json:"hazard_delta_seconds"`
	Severity           string                 `json:"severity"` // "CRITICAL", "WARNING", "HEALTHY"
	Summary            string                 `json:"summary"`
	AppAudits          []AppAuditReport       `json:"app_audits"`
	Recommendations    []string               `json:"recommendations"`
	KubernetesPodYAML  string                 `json:"kubernetes_pod_yaml"`
}

// AuditKeepalive evaluates OS keepalive settings and application pool defaults against cloud NAT.
func AuditKeepalive(cfg *sysctl.KeepaliveConfig, cloud CloudProvider) *AuditResult {
	if cfg == nil {
		cfg = &sysctl.KeepaliveConfig{
			KeepaliveTimeSeconds:  sysctl.DefaultKeepaliveTime,
			KeepaliveIntvlSeconds: sysctl.DefaultKeepaliveIntvl,
			KeepaliveProbes:       sysctl.DefaultKeepaliveProbes,
			Source:                "fallback_defaults",
		}
	}

	delta := cfg.KeepaliveTimeSeconds - cloud.IdleTimeoutSeconds

	var severity string
	var summary string

	if cfg.KeepaliveTimeSeconds > cloud.IdleTimeoutSeconds {
		severity = "CRITICAL"
		summary = fmt.Sprintf(
			"OS tcp_keepalive_time (%ds) exceeds %s %s timeout (%ds) by %d seconds. Idle connections will be silently dropped before keepalive probes fire.",
			cfg.KeepaliveTimeSeconds, cloud.Name, cloud.Service, cloud.IdleTimeoutSeconds, delta,
		)
	} else if cfg.KeepaliveTimeSeconds > (cloud.IdleTimeoutSeconds - 30) {
		severity = "WARNING"
		summary = fmt.Sprintf(
			"OS tcp_keepalive_time (%ds) is within 30 seconds of %s %s timeout (%ds). Jitter or packet loss may cause silent connection eviction.",
			cfg.KeepaliveTimeSeconds, cloud.Name, cloud.Service, cloud.IdleTimeoutSeconds,
		)
	} else {
		severity = "HEALTHY"
		summary = fmt.Sprintf(
			"OS tcp_keepalive_time (%ds) is safely below %s %s timeout (%ds). Keepalive probes fire before NAT state eviction.",
			cfg.KeepaliveTimeSeconds, cloud.Name, cloud.Service, cloud.IdleTimeoutSeconds,
		)
	}

	// Audit application profiles
	appAudits := make([]AppAuditReport, 0, len(standardAppProfiles))
	for _, app := range standardAppProfiles {
		vulnerable := false
		var appDelta int
		var mitigation string

		if app.DefaultIdleSeconds == 0 {
			// Unbounded
			vulnerable = true
			appDelta = 999999
			mitigation = fmt.Sprintf("Configure explicit socket keepalives or set pool max_idle <= %ds", cloud.IdleTimeoutSeconds-60)
		} else if app.DefaultIdleSeconds > cloud.IdleTimeoutSeconds {
			vulnerable = true
			appDelta = app.DefaultIdleSeconds - cloud.IdleTimeoutSeconds
			mitigation = fmt.Sprintf("Lower idleTimeout from %ds to <= %ds (e.g. %ds)", app.DefaultIdleSeconds, cloud.IdleTimeoutSeconds-30, cloud.IdleTimeoutSeconds/2)
		} else {
			vulnerable = false
			appDelta = app.DefaultIdleSeconds - cloud.IdleTimeoutSeconds
			mitigation = "Pool timeout is already within safe cloud limits"
		}

		appAudits = append(appAudits, AppAuditReport{
			Runtime:            app.Runtime,
			Library:            app.Library,
			DefaultIdleSeconds: app.DefaultIdleSeconds,
			Vulnerable:         vulnerable,
			HazardDeltaSeconds: appDelta,
			Mitigation:         mitigation,
		})
	}

	// Recommendations
	recommendations := make([]string, 0)
	if severity == "CRITICAL" || severity == "WARNING" {
		targetTime := cloud.IdleTimeoutSeconds / 3
		if targetTime > 60 {
			targetTime = 60
		}
		recommendations = append(recommendations,
			fmt.Sprintf("Tune host sysctls: sysctl -w net.ipv4.tcp_keepalive_time=%d net.ipv4.tcp_keepalive_intvl=15 net.ipv4.tcp_keepalive_probes=4", targetTime),
			"In Kubernetes: deploy 'natarmor shield' as a lightweight loopback proxy, or configure securityContext sysctls if permitted by kubelet",
			"For Java HikariCP: set maximumPoolSize idleTimeout <= 120000 (120s)",
			"For Python urllib3: configure HTTPAdapter with socket_options setting TCP_KEEPIDLE=60s",
			"For Node.js undici / fetch: configure Dispatcher keepAliveTimeout <= 60000 (60s)",
		)
	} else {
		recommendations = append(recommendations, "Keepalive parameters are within safe operational limits")
	}

	k8sYAML := fmt.Sprintf(`apiVersion: v1
kind: Pod
metadata:
  name: hardened-app
spec:
  securityContext:
    sysctls:
    - name: net.ipv4.tcp_keepalive_time
      value: "%d"
    - name: net.ipv4.tcp_keepalive_intvl
      value: "15"
    - name: net.ipv4.tcp_keepalive_probes
      value: "4"
  containers:
  - name: app
    image: my-service:latest
`, cloud.IdleTimeoutSeconds/4)

	return &AuditResult{
		Cloud:              cloud,
		Sysctl:             *cfg,
		HazardDeltaSeconds: delta,
		Severity:           severity,
		Summary:            summary,
		AppAudits:          appAudits,
		Recommendations:    recommendations,
		KubernetesPodYAML:  k8sYAML,
	}
}
