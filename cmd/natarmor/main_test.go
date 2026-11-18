package main

import (
	"bytes"
	"io"
	"net"
	"os"
	"testing"
)

func TestMain_Usage(t *testing.T) {
	oldStdout := os.Stdout
	r, w, _ := os.Pipe()
	os.Stdout = w

	printUsage()

	w.Close()
	os.Stdout = oldStdout

	var buf bytes.Buffer
	io.Copy(&buf, r)
	output := buf.String()

	if !bytes.Contains([]byte(output), []byte("natarmor - Cloud NAT Gateway idle timeout sentry")) {
		t.Fatalf("unexpected usage output: %s", output)
	}
	if !bytes.Contains([]byte(output), []byte("audit")) || !bytes.Contains([]byte(output), []byte("shield")) {
		t.Fatalf("expected audit and shield commands in usage: %s", output)
	}
}

func TestRunAudit_HumanAndJSON(t *testing.T) {
	// 1. Human format
	oldStdout := os.Stdout
	r, w, _ := os.Pipe()
	os.Stdout = w

	err := runAudit([]string{"--cloud", "aws"})

	w.Close()
	os.Stdout = oldStdout

	if err != nil {
		t.Fatalf("runAudit human format failed: %v", err)
	}

	var buf bytes.Buffer
	io.Copy(&buf, r)
	output := buf.String()

	if !bytes.Contains([]byte(output), []byte("NATARMOR AUDIT REPORT")) {
		t.Fatalf("expected NATARMOR AUDIT REPORT header, got: %s", output)
	}

	// 2. JSON format
	r2, w2, _ := os.Pipe()
	os.Stdout = w2

	err = runAudit([]string{"--cloud", "azure", "--json"})

	w2.Close()
	os.Stdout = oldStdout

	if err != nil {
		t.Fatalf("runAudit json format failed: %v", err)
	}

	var buf2 bytes.Buffer
	io.Copy(&buf2, r2)
	output2 := buf2.String()

	if !bytes.Contains([]byte(output2), []byte("\"idle_timeout_seconds\": 240")) {
		t.Fatalf("expected JSON output with azure idle timeout, got: %s", output2)
	}
}

func TestRunDoctor_OfflineMockTarget(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to start mock listener: %v", err)
	}
	defer ln.Close()

	oldStdout := os.Stdout
	r, w, _ := os.Pipe()
	os.Stdout = w

	err = runDoctor([]string{"--target", ln.Addr().String(), "--cloud", "aws", "--json"})

	w.Close()
	os.Stdout = oldStdout

	if err != nil {
		t.Fatalf("runDoctor failed: %v", err)
	}

	var buf bytes.Buffer
	io.Copy(&buf, r)
	output := buf.String()

	if !bytes.Contains([]byte(output), []byte("\"reachable\": true")) {
		t.Fatalf("expected reachable true in json doctor report, got: %s", output)
	}
}

func TestRunShield_Validation(t *testing.T) {
	// Missing upstream should return error
	err := runShield([]string{"--listen", "127.0.0.1:8080"})
	if err == nil {
		t.Fatalf("expected error for missing --upstream, got nil")
	}
}

func TestRunAudit_InvalidCloud(t *testing.T) {
	err := runAudit([]string{"--cloud", "unknown_provider_123"})
	if err == nil {
		t.Fatalf("expected error for invalid cloud provider, got nil")
	}
}
