package sentry

import (
	"fmt"
	"strings"
)

// CloudProvider represents a cloud provider's stateful NAT / LB timeout characteristics.
type CloudProvider struct {
	ID                 string `json:"id"`
	Name               string `json:"name"`
	Service            string `json:"service"`
	IdleTimeoutSeconds int    `json:"idle_timeout_seconds"`
	SilentDrop         bool   `json:"silent_drop"` // Evicts without sending TCP RST or FIN
	DocumentationURL   string `json:"documentation_url"`
}

// AppProfile models connection pool lifetime and idle timeouts for popular runtimes.
type AppProfile struct {
	Runtime            string `json:"runtime"`
	Library            string `json:"library"`
	DefaultIdleSeconds int    `json:"default_idle_seconds"` // 0 indicates unbounded / indefinite
	Description        string `json:"description"`
}

var providers = map[string]CloudProvider{
	"aws": {
		ID:                 "aws",
		Name:               "Amazon Web Services",
		Service:            "NAT Gateway / Network Load Balancer",
		IdleTimeoutSeconds: 350,
		SilentDrop:         true,
		DocumentationURL:   "https://docs.aws.amazon.com/vpc/latest/userguide/vpc-nat-gateway.html#nat-gateway-limits",
	},
	"azure": {
		ID:                 "azure",
		Name:               "Microsoft Azure",
		Service:            "Virtual Network NAT / Azure Load Balancer",
		IdleTimeoutSeconds: 240,
		SilentDrop:         true,
		DocumentationURL:   "https://learn.microsoft.com/en-us/azure/virtual-network/nat-gateway/nat-gateway-resource#idle-timeout",
	},
	"gcp": {
		ID:                 "gcp",
		Name:               "Google Cloud Platform",
		Service:            "Cloud NAT / Cloud Load Balancing",
		IdleTimeoutSeconds: 600,
		SilentDrop:         true,
		DocumentationURL:   "https://cloud.google.com/nat/docs/overview#specs-timeouts",
	},
}

var standardAppProfiles = []AppProfile{
	{
		Runtime:            "Java",
		Library:            "HikariCP (JDBC)",
		DefaultIdleSeconds: 600,
		Description:        "Connection pool default idleTimeout is 600s (10 minutes), exceeding AWS 350s and Azure 240s limits",
	},
	{
		Runtime:            "Python",
		Library:            "urllib3 / requests",
		DefaultIdleSeconds: 0, // Unbounded
		Description:        "Connection pool holds idle sockets indefinitely without keepalives unless custom transport configured",
	},
	{
		Runtime:            "Node.js",
		Library:            "undici / fetch",
		DefaultIdleSeconds: 600,
		Description:        "Default keepAliveTimeout is often 10 minutes (600s), vulnerable to silent AWS/Azure NAT eviction",
	},
	{
		Runtime:            "Go",
		Library:            "net/http DefaultTransport",
		DefaultIdleSeconds: 90,
		Description:        "Default IdleConnTimeout is 90s, safely below cloud NAT thresholds",
	},
}

// GetCloudProvider returns the cloud provider configuration for a given key.
func GetCloudProvider(name string) (CloudProvider, error) {
	key := strings.ToLower(strings.TrimSpace(name))
	if key == "" {
		key = "aws" // Default to AWS NAT Gateway
	}

	p, exists := providers[key]
	if !exists {
		return CloudProvider{}, fmt.Errorf("unknown cloud provider '%s' (supported: aws, azure, gcp)", name)
	}

	return p, nil
}

// AllCloudProviders returns a slice of all supported cloud provider timeout models.
func AllCloudProviders() []CloudProvider {
	return []CloudProvider{
		providers["aws"],
		providers["azure"],
		providers["gcp"],
	}
}

// StandardAppProfiles returns common application connection pool profiles.
func StandardAppProfiles() []AppProfile {
	return standardAppProfiles
}
