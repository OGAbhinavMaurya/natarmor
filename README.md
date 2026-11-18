<div align="center">

# natarmor

**Cloud NAT Gateway idle timeout sentry, keepalive auditor, and connection shield.**

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Go Version](https://img.shields.io/badge/Go-1.22+-00ADD8?logo=go&logoColor=white)](go.mod)
[![Zero Dependencies](https://img.shields.io/badge/Dependencies-Zero%20(Pure%20Go)-green)](#)

<p align="center">
  <a href="#the-problem">The problem</a> •
  <a href="#how-it-works">How it works</a> •
  <a href="#architecture">Architecture</a> •
  <a href="#comparison">Comparison</a> •
  <a href="#installation">Installation</a> •
  <a href="#usage">Usage</a> •
  <a href="#license">License</a>
</p>

</div>

## The problem

Cloud managed NAT services (AWS NAT Gateway, AWS Network Load Balancer, Azure Virtual Network NAT) enforce strict, unalterable connection tracking idle timeouts. On AWS NAT Gateway, if a TCP flow remains idle for 350 seconds (240 seconds on Azure), the NAT translation state entry is silently discarded. Neither the client nor the server receives a `TCP RST` or `TCP FIN` packet:

```
  Client Container (K8s)                     AWS NAT Gateway                        Remote Server (DB / API)
         |                                          |                                           |
         |  Sends query, connection enters pool     |                                           |
         |----------------------------------------->|------------------------------------------>|
         |  Response received                       |                                           |
         |<-----------------------------------------|<------------------------------------------|
         |                                          |                                           |
         |  Connection idle in pool (> 350 seconds) |                                           |
         |  Linux kernel default keepalive: 7200s   |                                           |
         |                                          |  [350s idle timer expires]                |
         |                                          |  Silent eviction of conntrack entry       |
         |                                          |  (No RST or FIN sent to either endpoint)  |
         |                                          |                                           |
         |  Client attempts to reuse connection     |                                           |
         |----------------------------------------->|                                           |
         |  TCP RST / ECONNRESET (Broken pipe)      |                                           |
         |<-----------------------------------------|  (Translation state gone, packet dropped) |
         |                                          |                                           |
         |  Server push / notification              |                                           |
         |                                          | <-----------------------------------------|
         |  Silent blackhole: packet dropped!       |                                           |
         |  (Client hangs indefinitely)             |                                           |
```

This creates severe operational disruptions:

1. **The 7,200-second Linux sysctl trap**: The Linux kernel defaults to `net.ipv4.tcp_keepalive_time = 7200` (2 hours). The operating system does not send its first keepalive probe until 2 hours of inactivity have elapsed. Because the cloud NAT gateway evicts the connection at 350 seconds, connections are severed 6,850 seconds before the kernel ever attempts to verify their state.
2. **The Kubernetes sysctl barrier**: In Kubernetes clusters, `net.ipv4.tcp_keepalive_*` sysctls are categorized as unsafe sysctls. Kubelet blocks them by default. Enabling them requires configuring `--allowed-unsafe-sysctls` on every worker node, which is prohibited in many managed cloud environments (AWS EKS, GCP GKE, Azure AKS).
3. **Asymmetric drop failures**: When a client application attempts to reuse a dead pooled connection, the NAT gateway cannot resolve the translation mapping and returns a `TCP RST` (`ECONNRESET`, `Broken pipe`). Conversely, when a remote server attempts an asynchronous push (such as PostgreSQL `LISTEN/NOTIFY`, Server-Sent Events, or webhook streaming), the packet hits the NAT public IP, finds no translation entry, and is discarded. The client hangs indefinitely awaiting data.
4. **Library configuration drift**: Connection pool defaults vary widely across programming runtimes. Java HikariCP defaults to 600s `idleTimeout` (exceeding AWS 350s limits), Python `urllib3` retains pooled sockets indefinitely without keepalives, and Node.js `undici` defaults to 600s idle limits.

### Why existing approaches fail

- **Modifying host sysctls**: Changing `net.ipv4.tcp_keepalive_time` on host nodes modifies socket behavior globally across all containers, often violating cluster security policies.
- **Application code patches**: Rewriting connection pool configurations across dozens of microservices and runtimes is error-prone, requiring coordinated redeployments and maintenance.
- **Sidecar proxies (Envoy/Istio)**: Full service mesh sidecars add substantial CPU and memory overhead per pod just to maintain socket keepalives.

## How it works

`natarmor` provides comprehensive auditing and loopback protection:

```
  Client Application                       natarmor shield                       AWS NAT Gateway
         |                                        |                                     |
         |  Connects to localhost:5432            |                                     |
         |--------------------------------------->|  Dials upstream target              |
         |                                        |------------------------------------>|
         |                                        |  Sets SO_KEEPALIVE = 1              |
         |                                        |  Sets TCP_KEEPIDLE = 60s            |
         |                                        |  Sets TCP_KEEPINTVL = 15s           |
         |                                        |                                     |
         |  Bi-directional data stream            |  Bi-directional data stream         |
         |<======================================>|<===================================>|
         |                                        |                                     |
         |  Connection idle for 60 seconds        |                                     |
         |                                        |  Sends TCP keepalive probe          |
         |                                        |------------------------------------>|
         |                                        |  [NAT conntrack table refreshed!]   |
         |                                        |  <----------------------------------|
```

1. **System and container audit**: `natarmor audit` inspects local sysctl parameters (`/proc/sys/net/ipv4/tcp_keepalive_*`) and scores eviction risks against AWS (350s), Azure (240s), and GCP (600s) limits. It benchmarks common application runtime pool defaults (HikariCP, urllib3, undici, Go net/http) and generates ready-to-apply Kubernetes manifests.
2. **Diagnostic target probing**: `natarmor doctor` connects to a remote endpoint, measures connection latency, inspects system keepalive configuration, and reports whether idle sockets to that target are subject to silent NAT drop.
3. **Transparent keepalive loopback shield**: `natarmor shield` operates as a lightweight TCP proxy on loopback (`127.0.0.1:<port>`). It intercepts connections and enforces low-interval TCP keepalive probes (`TCP_KEEPIDLE=60s`, `TCP_KEEPINTVL=15s`) on the upstream socket. Translation state entries in the intermediate NAT gateway are kept permanently active without modifying host node sysctls or rewriting application source code.

## Architecture

`natarmor` is written in pure Go with zero external dependencies.

```
natarmor/
├── cmd/
│   └── natarmor/
│       ├── main.go             # CLI interface: audit, doctor, shield commands
│       └── main_test.go        # Command-line integration tests
├── pkg/
│   ├── sysctl/
│   │   ├── sysctl.go           # /proc/sys/net/ipv4/tcp_keepalive_* reader and parser
│   │   └── sysctl_test.go      # Mock sysctl parsing and fallback tests
│   ├── sentry/
│   │   ├── cloud.go            # Multi-cloud NAT timeout models (AWS, Azure, GCP)
│   │   ├── audit.go            # Hazard evaluator and Kubernetes patch generator
│   │   └── sentry_test.go      # Sentry evaluation and hazard scoring tests
│   └── shield/
│       ├── proxy.go            # Loopback proxy with forced keepalive socket options
│       └── proxy_test.go       # End-to-end proxy forwarding and socket tests
├── go.mod
└── README.md
```

## Comparison

| Capability | Linux Default | Application Pool Tuning | K8s Unsafe Sysctls | natarmor |
| :--- | :--- | :--- | :--- | :--- |
| **Keepalive idle time** | 7,200s (2 hours) | Varies by library | Node-dependent | 60s (Proactive) |
| **AWS NAT survival** | Fails (Evicted at 350s) | Inconsistent | Yes (if privileged) | Guaranteed |
| **Azure NAT survival** | Fails (Evicted at 240s) | Inconsistent | Yes (if privileged) | Guaranteed |
| **Kubernetes privilege** | Unprivileged | Unprivileged | Requires privileged node | Unprivileged (User space) |
| **Application code changes** | None | Required per service | None | None |
| **Dependencies** | None | Library-dependent | Kubelet flags | Pure Go (single binary) |

## Installation

### From source

```bash
git clone https://github.com/OGAbhinavMaurya/natarmor.git
cd natarmor
go build -o natarmor ./cmd/natarmor
```

### Pre-built binary

Download the compiled binary for your architecture from the GitHub releases page.

## Usage

### Audit mode

Audit host and container keepalive sysctl configuration against cloud NAT limits:

```bash
# Audit against AWS NAT Gateway (350s limit)
natarmor audit --cloud aws

# Audit against Azure Virtual Network NAT (240s limit)
natarmor audit --cloud azure

# Output report in JSON format for automated CI/CD checks
natarmor audit --cloud aws --json
```

Example output:

```text
================================================================================
                           NATARMOR AUDIT REPORT                                
================================================================================
 Cloud Provider:            Amazon Web Services (NAT Gateway / Network Load Balancer)
 NAT Idle Timeout:          350 seconds (Silent Eviction: true)
 System tcp_keepalive_time: 7200 seconds (Source: kernel_proc)
 Hazard Delta:              +6850 seconds
 Status:                    [CRITICAL]
 Summary:                   OS tcp_keepalive_time (7200s) exceeds Amazon Web Services NAT Gateway / Network Load Balancer timeout (350s) by 6850 seconds. Idle connections will be silently dropped before keepalive probes fire.
--------------------------------------------------------------------------------
 Application Connection Pool Audit:
   * [VULNERABLE] Java     HikariCP (JDBC)           (Default: 600s) -> Lower idleTimeout from 600s to <= 320s (e.g. 175s)
   * [VULNERABLE] Python   urllib3 / requests        (Default: 0s)   -> Configure explicit socket keepalives or set pool max_idle <= 290s
   * [VULNERABLE] Node.js  undici / fetch            (Default: 600s) -> Lower idleTimeout from 600s to <= 320s (e.g. 175s)
   * [SAFE      ] Go       net/http DefaultTransport (Default: 90s)  -> Pool timeout is already within safe cloud limits
--------------------------------------------------------------------------------
 Recommendations:
   * Tune host sysctls: sysctl -w net.ipv4.tcp_keepalive_time=60 net.ipv4.tcp_keepalive_intvl=15 net.ipv4.tcp_keepalive_probes=4
   * In Kubernetes: deploy 'natarmor shield' as a lightweight loopback proxy, or configure securityContext sysctls if permitted by kubelet
   * For Java HikariCP: set maximumPoolSize idleTimeout <= 120000 (120s)
   * For Python urllib3: configure HTTPAdapter with socket_options setting TCP_KEEPIDLE=60s
   * For Node.js undici / fetch: configure Dispatcher keepAliveTimeout <= 60000 (60s)
================================================================================
```

### Doctor mode

Probe a remote endpoint to check reachability and evaluate eviction vulnerability:

```bash
natarmor doctor --target db-primary.internal:5432 --cloud aws
```

Example output:

```text
================================================================================
                          NATARMOR DOCTOR REPORT                                
================================================================================
 Probe Target:              db-primary.internal:5432
 Cloud NAT Threshold:       350 seconds (Amazon Web Services)
 Endpoint Reachable:        true (Latency: 2ms)
 OS Keepalive Idle Time:    7200 seconds
 Silent Drop Risk:          true
 Diagnosis:                 Socket connections to db-primary.internal:5432 crossing 350s idle will be silently dropped by Amazon Web Services NAT Gateway before OS keepalive (7200s) triggers
================================================================================
```

### Shield mode

Run a transparent loopback proxy enforcing 60s idle keepalives to an upstream database or API:

```bash
natarmor shield --listen 127.0.0.1:5432 --upstream db-primary.internal:5432 --keepalive-idle 60s --keepalive-intvl 15s
```

Example output:

```text
================================================================================
                          NATARMOR SHIELD PROXY                                 
================================================================================
 Listening on:              127.0.0.1:5432
 Forwarding upstream to:    db-primary.internal:5432
 Keepalive Idle Period:     60 seconds
 Keepalive Probe Interval:  15 seconds
 Status:                    Active. Press Ctrl+C to terminate.
================================================================================
```

## License

This project is licensed under the MIT License. See the [LICENSE](LICENSE) file for details.
