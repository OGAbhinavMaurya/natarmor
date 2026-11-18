package shield

import (
	"bytes"
	"io"
	"net"
	"testing"
	"time"
)

func startMockEchoServer(t *testing.T) (net.Listener, string) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to start mock echo listener: %v", err)
	}

	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				_, _ = io.Copy(c, c)
			}(conn)
		}
	}()

	return ln, ln.Addr().String()
}

func TestShieldProxy_EndToEndForwarding(t *testing.T) {
	echoLn, echoAddr := startMockEchoServer(t)
	defer echoLn.Close()

	proxy, err := NewShieldProxy(ProxyConfig{
		ListenAddr:     "127.0.0.1:0",
		UpstreamAddr:   echoAddr,
		KeepaliveIdle:  50 * time.Millisecond,
		KeepaliveIntvl: 20 * time.Millisecond,
	})
	if err != nil {
		t.Fatalf("failed to create shield proxy: %v", err)
	}
	defer proxy.Close()

	client, err := net.Dial("tcp", proxy.Addr())
	if err != nil {
		t.Fatalf("failed to connect to shield proxy: %v", err)
	}
	defer client.Close()

	testPayload := []byte("hello cloud nat gateway keepalive shield!")
	if _, err := client.Write(testPayload); err != nil {
		t.Fatalf("failed to write payload: %v", err)
	}

	buf := make([]byte, len(testPayload))
	if _, err := io.ReadFull(client, buf); err != nil {
		t.Fatalf("failed to read echoed payload: %v", err)
	}

	if !bytes.Equal(buf, testPayload) {
		t.Errorf("expected echoed %q, got %q", testPayload, buf)
	}

	stats := proxy.Stats()
	if stats.TotalConnections != 1 {
		t.Errorf("expected 1 total connection, got %d", stats.TotalConnections)
	}
	if stats.BytesForwarded < int64(len(testPayload)*2) {
		t.Errorf("expected at least %d bytes forwarded, got %d", len(testPayload)*2, stats.BytesForwarded)
	}
}

func TestShieldProxy_InvalidUpstream(t *testing.T) {
	_, err := NewShieldProxy(ProxyConfig{
		ListenAddr:   "127.0.0.1:0",
		UpstreamAddr: "", // Empty
	})
	if err == nil {
		t.Fatalf("expected error for empty upstream, got nil")
	}
}
