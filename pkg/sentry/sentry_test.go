package sentry

import (
	"testing"

	"github.com/OGAbhinavMaurya/natarmor/pkg/sysctl"
)

func TestGetCloudProvider(t *testing.T) {
	// AWS
	pAws, err := GetCloudProvider("aws")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if pAws.IdleTimeoutSeconds != 350 {
		t.Errorf("expected 350s for AWS, got %d", pAws.IdleTimeoutSeconds)
	}

	// Azure
	pAzure, err := GetCloudProvider("azure")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if pAzure.IdleTimeoutSeconds != 240 {
		t.Errorf("expected 240s for Azure, got %d", pAzure.IdleTimeoutSeconds)
	}

	// GCP
	pGcp, err := GetCloudProvider("gcp")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if pGcp.IdleTimeoutSeconds != 600 {
		t.Errorf("expected 600s for GCP, got %d", pGcp.IdleTimeoutSeconds)
	}

	// Invalid
	_, err = GetCloudProvider("invalid_cloud")
	if err == nil {
		t.Fatalf("expected error for invalid cloud provider, got nil")
	}
}

func TestAuditKeepalive_CriticalHazard(t *testing.T) {
	cfg := &sysctl.KeepaliveConfig{
		KeepaliveTimeSeconds:  7200,
		KeepaliveIntvlSeconds: 75,
		KeepaliveProbes:       9,
		Source:                "kernel_proc",
	}

	cloud, _ := GetCloudProvider("aws")
	res := AuditKeepalive(cfg, cloud)

	if res.Severity != "CRITICAL" {
		t.Fatalf("expected CRITICAL severity, got %s", res.Severity)
	}
	if res.HazardDeltaSeconds != (7200 - 350) {
		t.Errorf("expected hazard delta %d, got %d", 7200-350, res.HazardDeltaSeconds)
	}
	if len(res.Recommendations) == 0 {
		t.Errorf("expected recommendations for CRITICAL hazard")
	}

	// Check application audits
	var hikariFound bool
	for _, app := range res.AppAudits {
		if app.Library == "HikariCP (JDBC)" {
			hikariFound = true
			if !app.Vulnerable {
				t.Errorf("expected HikariCP to be marked vulnerable against AWS 350s")
			}
		}
	}
	if !hikariFound {
		t.Errorf("expected HikariCP in app audits")
	}
}

func TestAuditKeepalive_Healthy(t *testing.T) {
	cfg := &sysctl.KeepaliveConfig{
		KeepaliveTimeSeconds:  60,
		KeepaliveIntvlSeconds: 15,
		KeepaliveProbes:       4,
		Source:                "kernel_proc",
	}

	cloud, _ := GetCloudProvider("aws")
	res := AuditKeepalive(cfg, cloud)

	if res.Severity != "HEALTHY" {
		t.Fatalf("expected HEALTHY severity, got %s", res.Severity)
	}
	if res.HazardDeltaSeconds != (60 - 350) {
		t.Errorf("expected hazard delta %d, got %d", 60-350, res.HazardDeltaSeconds)
	}
}
