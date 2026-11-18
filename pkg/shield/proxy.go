package shield

import (
	"errors"
	"fmt"
	"io"
	"net"
	"sync"
	"sync/atomic"
	"time"
)

// Default keepalive thresholds for the shield proxy
const (
	DefaultKeepaliveIdle  = 60 * time.Second
	DefaultKeepaliveIntvl = 15 * time.Second
)

// ProxyConfig defines the configuration parameters for the loopback shield proxy.
type ProxyConfig struct {
	ListenAddr     string        `json:"listen_addr"`
	UpstreamAddr   string        `json:"upstream_addr"`
	KeepaliveIdle  time.Duration `json:"keepalive_idle"`
	KeepaliveIntvl time.Duration `json:"keepalive_intvl"`
}

// ProxyStats holds operational metrics for the shield proxy.
type ProxyStats struct {
	ActiveConnections int64 `json:"active_connections"`
	TotalConnections  int64 `json:"total_connections"`
	BytesForwarded    int64 `json:"bytes_forwarded"`
}

// ShieldProxy intercepts TCP connections and forces low-interval TCP keepalive probes.
type ShieldProxy struct {
	cfg         ProxyConfig
	ln          net.Listener
	mu          sync.RWMutex
	running     bool
	activeConns int64
	totalConns  int64
	bytesFwd    int64
}

type countingReader struct {
	r       io.Reader
	counter *int64
}

func (cr *countingReader) Read(p []byte) (int, error) {
	n, err := cr.r.Read(p)
	if n > 0 {
		atomic.AddInt64(cr.counter, int64(n))
	}
	return n, err
}

// NewShieldProxy initializes a new loopback shield proxy.
func NewShieldProxy(cfg ProxyConfig) (*ShieldProxy, error) {
	if cfg.UpstreamAddr == "" {
		return nil, errors.New("upstream address cannot be empty")
	}
	if cfg.ListenAddr == "" {
		cfg.ListenAddr = "127.0.0.1:0" // Dynamic port by default
	}
	if cfg.KeepaliveIdle <= 0 {
		cfg.KeepaliveIdle = DefaultKeepaliveIdle
	}
	if cfg.KeepaliveIntvl <= 0 {
		cfg.KeepaliveIntvl = DefaultKeepaliveIntvl
	}

	ln, err := net.Listen("tcp", cfg.ListenAddr)
	if err != nil {
		return nil, fmt.Errorf("failed to bind listen address %s: %w", cfg.ListenAddr, err)
	}

	p := &ShieldProxy{
		cfg:     cfg,
		ln:      ln,
		running: true,
	}

	go p.acceptLoop()

	return p, nil
}

// Addr returns the resolved local address the proxy is listening on.
func (p *ShieldProxy) Addr() string {
	if p.ln == nil {
		return ""
	}
	return p.ln.Addr().String()
}

// Stats returns a snapshot of proxy operational metrics.
func (p *ShieldProxy) Stats() ProxyStats {
	return ProxyStats{
		ActiveConnections: atomic.LoadInt64(&p.activeConns),
		TotalConnections:  atomic.LoadInt64(&p.totalConns),
		BytesForwarded:    atomic.LoadInt64(&p.bytesFwd),
	}
}

// Close stops the listener and terminates the proxy.
func (p *ShieldProxy) Close() error {
	p.mu.Lock()
	defer p.mu.Unlock()

	if !p.running {
		return nil
	}
	p.running = false
	if p.ln != nil {
		return p.ln.Close()
	}
	return nil
}

func (p *ShieldProxy) acceptLoop() {
	for {
		clientConn, err := p.ln.Accept()
		if err != nil {
			p.mu.RLock()
			running := p.running
			p.mu.RUnlock()
			if !running {
				return
			}
			continue
		}

		atomic.AddInt64(&p.activeConns, 1)
		atomic.AddInt64(&p.totalConns, 1)

		go p.handleConnection(clientConn)
	}
}

func (p *ShieldProxy) handleConnection(clientConn net.Conn) {
	defer func() {
		clientConn.Close()
		atomic.AddInt64(&p.activeConns, -1)
	}()

	dialer := net.Dialer{
		Timeout:   10 * time.Second,
		KeepAlive: p.cfg.KeepaliveIdle,
	}

	upstreamConn, err := dialer.Dial("tcp", p.cfg.UpstreamAddr)
	if err != nil {
		return
	}
	defer upstreamConn.Close()

	// Configure explicit TCP keepalive options on upstream socket
	if tcpUpstream, ok := upstreamConn.(*net.TCPConn); ok {
		_ = tcpUpstream.SetKeepAlive(true)
		_ = tcpUpstream.SetKeepAlivePeriod(p.cfg.KeepaliveIdle)
	}

	// Also ensure client side has keepalive enabled
	if tcpClient, ok := clientConn.(*net.TCPConn); ok {
		_ = tcpClient.SetKeepAlive(true)
		_ = tcpClient.SetKeepAlivePeriod(p.cfg.KeepaliveIdle)
	}

	var wg sync.WaitGroup
	wg.Add(2)

	// Stream 1: client -> upstream
	go func() {
		defer wg.Done()
		_, _ = io.Copy(upstreamConn, &countingReader{r: clientConn, counter: &p.bytesFwd})
		if tcpUpstream, ok := upstreamConn.(*net.TCPConn); ok {
			_ = tcpUpstream.CloseWrite()
		}
	}()

	// Stream 2: upstream -> client
	go func() {
		defer wg.Done()
		_, _ = io.Copy(clientConn, &countingReader{r: upstreamConn, counter: &p.bytesFwd})
		if tcpClient, ok := clientConn.(*net.TCPConn); ok {
			_ = tcpClient.CloseWrite()
		}
	}()

	wg.Wait()
}
