# 🦈 Wireshark Playbook — Network Security Field Guide

> A practical, real-world reference for network engineers and security analysts.  
> Built from 3.6 years of enterprise troubleshooting experience across Citrix NetScaler, Cisco ASA, WAF, and SSL environments.

---

## 📋 Table of Contents

1. [Essential Display Filters](#1-essential-display-filters)
2. [SSL/TLS Troubleshooting](#2-ssltls-troubleshooting)
3. [TCP Issues](#3-tcp-issues)
4. [DNS Analysis](#4-dns-analysis)
5. [HTTP/HTTPS Analysis](#5-httphttps-analysis)
6. [Citrix NetScaler Scenarios](#6-citrix-netscaler-scenarios)
7. [Firewall & Security Analysis](#7-firewall--security-analysis)
8. [Performance & Latency](#8-performance--latency)
9. [Real-World RCA Scenarios](#9-real-world-rca-scenarios)
10. [Quick Reference Cheatsheet](#10-quick-reference-cheatsheet)

---

## 1. Essential Display Filters

These are the filters used daily in enterprise support. Learn these first.

| Filter | What It Does |
|---|---|
| `ip.addr == 192.168.1.1` | Show all traffic to/from a specific IP |
| `ip.src == 192.168.1.1` | Only traffic FROM this IP |
| `ip.dst == 192.168.1.1` | Only traffic TO this IP |
| `tcp.port == 443` | Filter HTTPS traffic |
| `tcp.port == 80` | Filter HTTP traffic |
| `!(arp or dns or icmp)` | Remove noise — hide ARP, DNS, ICMP |
| `tcp.flags.reset == 1` | Show all TCP RST packets (connection resets) |
| `tcp.flags.syn == 1 and tcp.flags.ack == 0` | Show only SYN packets (new connection attempts) |
| `frame contains "error"` | Search raw packet data for the word "error" |

---

## 2. SSL/TLS Troubleshooting

SSL issues are one of the most common problems in enterprise environments — especially with NetScaler, WAF, and VPN.

### 2.1 Filter SSL Handshake Traffic
```
tls.handshake
```
Use this to see all TLS Client Hello, Server Hello, Certificate, and Finished messages.

### 2.2 Find SSL Handshake Failures
```
tls.alert_message
```
This shows TLS alert messages. Common alerts you'll see:

| Alert | Meaning |
|---|---|
| `handshake_failure (40)` | Cipher mismatch — client and server can't agree on encryption |
| `certificate_unknown (46)` | Client doesn't trust the server certificate |
| `bad_certificate (42)` | Certificate is malformed or invalid |
| `protocol_version (70)` | TLS version mismatch (e.g. client sends TLS 1.0, server requires 1.2+) |

### 2.3 Check What TLS Version is Being Used
```
tls.handshake.version
```
Filter for only TLS 1.2:
```
tls.record.version == 0x0303
```
Filter for TLS 1.3:
```
tls.record.version == 0x0304
```

### 2.4 Find Certificate Details
```
tls.handshake.type == 11
```
This isolates the Certificate message so you can inspect the cert being presented by the server.

### 💡 Real Scenario
> **Problem:** Users getting SSL errors connecting to a NetScaler VIP.  
> **Filter used:** `tls.alert_message`  
> **Finding:** Server sending `handshake_failure` — trace showed client was offering only TLS 1.2, but NetScaler was configured to require TLS 1.3 minimum.  
> **Fix:** Updated SSL profile on NetScaler to allow TLS 1.2 temporarily, then pushed client updates.

---

## 3. TCP Issues

### 3.1 The Most Important TCP Filters

```
tcp.analysis.flags
```
This single filter catches ALL TCP anomalies flagged by Wireshark — retransmissions, zero windows, out-of-order packets, duplicate ACKs. Start every troubleshooting session with this.

### 3.2 Retransmissions
```
tcp.analysis.retransmission
```
High retransmissions = packet loss somewhere in the path. Check the source IP — is it the client, server, or a middlebox like a load balancer?

### 3.3 Zero Window — Session Hanging
```
tcp.analysis.zero_window
```
Zero window means the receiving side's buffer is full — it's telling the sender to stop. This causes sessions to hang or time out. Common in slow application servers behind a NetScaler LB.

### 3.4 Connection Resets
```
tcp.flags.reset == 1
```
Then check: **who is sending the RST?**
- If the server sends RST → application rejected the connection
- If a middlebox sends RST → firewall (ASA) or load balancer policy blocking it
- If the client sends RST → client closed abruptly (often a timeout)

### 3.5 Three-Way Handshake Verification
```
tcp.flags.syn == 1
```
Look for:
- SYN with no SYN-ACK response → server/firewall dropping packets
- SYN-ACK with no ACK → client not responding (asymmetric routing)
- Repeated SYNs → client retrying because it's not getting through

### 💡 Real Scenario
> **Problem:** Application sessions dropping randomly every ~30 minutes.  
> **Filter used:** `tcp.analysis.zero_window` followed by `tcp.flags.reset == 1`  
> **Finding:** Server hitting zero window, then NetScaler sending RST after its connection timeout expired.  
> **Fix:** Increased NetScaler client idle timeout from 30min to 60min, and worked with app team to fix memory leak causing buffer exhaustion.

---

## 4. DNS Analysis

### 4.1 Show All DNS Traffic
```
dns
```

### 4.2 Show Only DNS Queries (not responses)
```
dns.flags.response == 0
```

### 4.3 Show Only DNS Responses
```
dns.flags.response == 1
```

### 4.4 Find DNS Errors
```
dns.flags.rcode != 0
```
Common error codes:

| Code | Meaning |
|---|---|
| `1` | Format Error |
| `2` | Server Failure (SERVFAIL) |
| `3` | NXDOMAIN — name doesn't exist |
| `5` | Refused |

### 4.5 Find Slow DNS Responses
Use Statistics → DNS to see response time distribution. Any query over 500ms is a problem.

### 💡 Real Scenario
> **Problem:** Users reporting intermittent failures reaching internal application.  
> **Filter used:** `dns.flags.rcode != 0`  
> **Finding:** NXDOMAIN responses for the app's internal FQDN — DNS record had been accidentally deleted during a maintenance window.  
> **Fix:** Re-added the DNS A record.

---

## 5. HTTP/HTTPS Analysis

### 5.1 Filter All HTTP Traffic
```
http
```

### 5.2 Filter by HTTP Method
```
http.request.method == "POST"
http.request.method == "GET"
```

### 5.3 Find HTTP Errors
```
http.response.code >= 400
```
Common codes to watch for:

| Code | Meaning |
|---|---|
| `400` | Bad Request |
| `401` | Unauthorized |
| `403` | Forbidden — often a WAF block |
| `404` | Not Found |
| `500` | Internal Server Error |
| `502` | Bad Gateway — load balancer can't reach backend |
| `503` | Service Unavailable — backend down or overloaded |

### 5.4 Find Specific URL Requests
```
http.request.uri contains "login"
```

### 5.5 WAF-Related Filter
When troubleshooting Citrix WAF blocks:
```
http.response.code == 403
```
Then look at the response body — WAF violation details are often embedded in the HTML response.

---

## 6. Citrix NetScaler Scenarios

These are scenarios specific to NetScaler ADC environments — from real enterprise support cases.

### 6.1 Verifying Load Balancer Health Checks
Filter health check probes from NetScaler SNIP to backend servers:
```
ip.src == <SNIP_IP> and tcp.flags.syn == 1
```
If you see SYNs going out but no SYN-ACK returning, the backend server is down or a firewall is blocking.

### 6.2 SSL Offload Verification
When NetScaler is doing SSL offload, traffic from NetScaler to backend should be plain HTTP (port 80). Verify:
```
ip.src == <SNIP_IP> and tcp.port == 80
```
If you see port 443 here, SSL is NOT being offloaded — check the LB service configuration.

### 6.3 Content Switching Troubleshooting
To verify which backend a request is going to, look at the destination IP in the packet after the NetScaler receives the client request. The SNIP will initiate a new connection to the correct backend.

### 6.4 Rewrite Policy Verification
Capture on the client-facing side and server-facing side separately. Compare HTTP headers — if a Rewrite policy is working, you'll see the modified header on the server-side capture but not the client-side.

---

## 7. Firewall & Security Analysis

### 7.1 Detecting Port Scans
```
tcp.flags.syn == 1 and tcp.flags.ack == 0 and ip.src == <suspicious_IP>
```
Multiple SYNs to different ports from the same source = port scan.

### 7.2 Detecting Brute Force Login Attempts
```
http.request.method == "POST" and http.request.uri contains "login"
```
Look for rapid repeated POSTs from the same source IP.

### 7.3 ICMP Flood / Ping Sweep
```
icmp and ip.src == <suspicious_IP>
```

### 7.4 Asymmetric Routing Detection
If you see TCP sessions where SYN and SYN-ACK are present but the connection never completes, suspect asymmetric routing — packets are returning via a different path than they left.

---

## 8. Performance & Latency

### 8.1 Measure Round Trip Time
Use **Statistics → TCP Stream Graphs → Round Trip Time** to visualize latency per stream.

### 8.2 Find High Latency Conversations
```
tcp.analysis.ack_rtt > 0.2
```
This shows TCP streams where ACK round trip time exceeds 200ms. Adjust the threshold based on your environment's baseline.

### 8.3 Throughput Analysis
Use **Statistics → Throughput** on a specific TCP stream to see if transfer speeds drop at specific points — useful for finding bandwidth bottlenecks.

### 8.4 Finding the Slowest Conversations
Go to **Statistics → Conversations → TCP tab** → sort by Duration. The longest connections are your candidates for investigation.

---

## 9. Real-World RCA Scenarios

### Scenario 1: Application Timing Out for Remote Users Only
- **Capture location:** Client-side and NetScaler SNIP-side
- **Filters:** `tcp.analysis.retransmission`, `tcp.analysis.zero_window`
- **Finding:** High retransmissions only on WAN path, not LAN. RTT > 300ms on WAN links causing NetScaler idle timeout to fire before transaction completed.
- **Fix:** Increased NetScaler client timeout, enabled TCP buffering profile for WAN clients.

### Scenario 2: SSL VPN Users Getting Kicked Off Every Hour
- **Filters:** `tls.alert_message`, `tcp.flags.reset == 1`
- **Finding:** RST sent by ASA exactly at 3600 seconds (1 hour) — matched the ASA's default session timeout.
- **Fix:** Increased ASA VPN session timeout and enabled keepalives on the VPN client profile.

### Scenario 3: WAF Blocking Legitimate Traffic
- **Filters:** `http.response.code == 403`
- **Finding:** WAF blocking POST requests containing special characters in form fields — legitimate data being flagged as SQL injection.
- **Fix:** Created WAF relaxation rule for the specific URL pattern after confirming with app team it was safe.

### Scenario 4: Intermittent 502 Bad Gateway from NetScaler
- **Filters:** `tcp.flags.reset == 1`, `ip.src == <SNIP_IP>`
- **Finding:** Backend server sending RST to NetScaler SNIP immediately on connection — app service had crashed on one of three backend servers. NetScaler was round-robin load balancing into the broken server.
- **Fix:** Disabled failed server in NetScaler LB, restarted app service, re-enabled after health check passed.

---

## 10. Quick Reference Cheatsheet

```
# ── BASIC ──────────────────────────────────────────
ip.addr == X.X.X.X          # Filter by IP
tcp.port == 443              # Filter by port
!(arp or dns or icmp)        # Remove noise

# ── TCP PROBLEMS ───────────────────────────────────
tcp.analysis.flags           # All TCP anomalies
tcp.analysis.retransmission  # Retransmissions
tcp.analysis.zero_window     # Zero window (session hang)
tcp.flags.reset == 1         # Connection resets (RST)
tcp.flags.syn == 1 and tcp.flags.ack == 0  # New connections only

# ── SSL/TLS ────────────────────────────────────────
tls.handshake                # All TLS handshake messages
tls.alert_message            # TLS failures/alerts
tls.handshake.type == 11     # Server certificate

# ── DNS ────────────────────────────────────────────
dns.flags.rcode != 0         # DNS errors
dns.flags.response == 0      # Queries only

# ── HTTP ───────────────────────────────────────────
http.response.code >= 400    # HTTP errors
http.response.code == 403    # Forbidden / WAF blocks
http.response.code == 502    # Bad gateway (LB → backend issue)

# ── SECURITY ───────────────────────────────────────
tcp.flags.syn == 1 and tcp.flags.ack == 0 and ip.src == X.X.X.X  # Port scan
http.request.method == "POST" and http.request.uri contains "login"  # Brute force
```

---

## About This Playbook

Built by **Kruthik K V** — Network Security Engineer with 3.6 years of enterprise support experience across Citrix NetScaler ADC, Cisco ASA, WAF, and SSL VPN environments.

📧 kruthik.39t@gmail.com  
🔗 [LinkedIn](https://www.linkedin.com/in/kruthik-k-v-3115ba21a)  
🔗 [GitHub Profile](https://github.com/Kruthik-NetworkSecurity)
