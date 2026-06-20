<div align="center">

<h1>🛡️ SSH Fortress</h1>

<p><strong>Advanced modular SSH hardening, brute-force protection, and SIEM integration</strong></p>

<p>
  <img src="https://img.shields.io/badge/Python-3.10%2B-blue?style=for-the-badge&logo=python" />
  <img src="https://img.shields.io/badge/Platform-Linux-lightgrey?style=for-the-badge&logo=linux" />
  <img src="https://img.shields.io/badge/License-Proprietary-red?style=for-the-badge" />
  <img src="https://img.shields.io/badge/Status-Active-green?style=for-the-badge" />
</p>

<p>
  <img src="https://img.shields.io/badge/nftables-kernel%20level%20blocking-orange?style=flat-square" />
  <img src="https://img.shields.io/badge/SIEM-Elasticsearch%20%7C%20Splunk%20%7C%20Syslog-blue?style=flat-square" />
  <img src="https://img.shields.io/badge/Alerts-Telegram%20%7C%20Email%20%7C%20Discord%20%7C%20Slack-purple?style=flat-square" />
</p>

</div>

---

## What is SSH Fortress?

SSH Fortress is a **production-ready SSH security framework** that does everything you'd normally need 3-4 separate tools to do:

- Hardens your SSH daemon to **CIS Level 2 / NSA** standards automatically
- Detects and bans brute-force attackers **before** they exhaust your auth attempts
- Forwards every SSH event to your **SIEM** (Elasticsearch, Splunk, Syslog, Kafka)
- Alerts you instantly on **Telegram, Email, Discord, or Slack** when something happens
- Detects **anomalies** — impossible travel, IP sprays, unusual login hours, root attempts
- **Audits your SSH keys** for weak, old, or duplicate entries
- Checks incoming IPs against **AbuseIPDB** and pre-bans known attackers

Everything is modular — enable only what you need, configure everything from a single YAML file.

---

## Features

### 🔒 SSH Hardening
- Rewrites `/etc/ssh/sshd_config` to CIS Benchmark Level 2 + NSA SSH Security Guide
- Validates with `sshd -t` and auto-reverts on failure — zero downtime risk
- Removes weak host keys (DSA, ECDSA) and regenerates Ed25519 + RSA-4096
- Purges DH moduli smaller than 3072 bits
- Strong cipher-only policy: ChaCha20, AES-256-GCM, ETM MACs only
- Configures PAM with `pam_faillock` account lockout
- Full backup before every change

### 🚫 Brute Force Protection
- **O(1) per-event decision** — in-process hash map, never touches disk on the hot path
- Progressive banning: ban doubles per repeat offence (1h → 2h → 4h → ... → 24h max)
- Syncs bans to **nftables kernel set** for zero-cost packet drops
- Optional **fail2ban** integration for extra redundancy
- Whitelist by IP or CIDR
- Manual `ban` / `unban` via CLI

### 🔥 Rate Limiting
- **nftables** (preferred) or **iptables** backend
- Per-IP new-connection rate cap with burst allowance
- SYN flood protection + SYN cookies
- Kernel-level drops — no userspace overhead per packet

### 🌍 Geographic Blocking
- MaxMind GeoLite2-Country integration
- Allow-list mode (only listed countries can connect) or block-list mode
- Private IPs always bypass geo checks

### 🚪 Port Knocking
- Optional TCP/UDP knock sequence — hides the SSH port entirely
- Opens SSH only for the specific IP that completed the sequence
- Auto-closes after a configurable timeout

### 📡 SIEM Integration (5 backends)

| Backend | Protocol | Format |
|---|---|---|
| Elasticsearch | HTTPS bulk API | ECS JSON |
| Splunk | HEC (HTTP Event Collector) | JSON |
| Syslog | UDP / TCP / TLS | CEF · RFC5424 · JSON |
| Apache Kafka | SASL / SSL | JSON |
| Webhook | HTTP POST | JSON |

- All backends run in **separate threads** with queues and backpressure
- Configurable batch size and flush interval
- Exponential backoff retry on failure
- ECS-compatible field naming (works with Elastic Security out of the box)

### 🔔 Alert Channels

| Channel | What triggers it |
|---|---|
| **Telegram** | Login success, brute force ban, root attempt, anomalies, failed login |
| **Email** | Login success, brute force ban, root attempt, anomalies, daily digest |
| **Discord** | Login success, brute force ban, root attempt, anomalies |
| **Slack** | All security events |
| **PagerDuty** | Critical events |
| **Webhook** | All events |

Features:
- Per-channel cooldown (won't spam your phone at 3am)
- Configurable silent hours (Telegram)
- Beautiful **HTML email templates** with coloured headers
- Discord **rich embeds** with coloured sidebars
- **Daily summary email** (scheduled at your chosen hour)

### 📊 Anomaly Detection

| Anomaly | Trigger |
|---|---|
| IP Spray | > 20 unique IPs within 60 seconds |
| Unusual Hours | Login outside 08:00–18:00 |
| Impossible Travel | Same user from 2+ countries within 1 hour |
| Auth Failure Spike | > 10 failures per minute |
| Root Attempt | Any `root` login attempt |

### 🔑 SSH Key Audit
- Scans all `authorized_keys` files across all system users
- Flags: DSA keys (broken), RSA < 4096 bits, ECDSA < 521 bits
- Detects duplicate keys reused across multiple accounts
- Optional auto-revocation of non-compliant keys
- Daily audit via systemd timer

### 🌐 IP Reputation (AbuseIPDB)
- Checks connecting IPs against AbuseIPDB before any auth attempt
- Pre-bans IPs with confidence score above threshold (default: 80)
- 24-hour in-memory cache — no repeated API calls for the same IP
- Free API key at [abuseipdb.com](https://www.abuseipdb.com)

### 📈 Statistics Tracker
- Counts: total attempts, successes, failures, bans, root attempts, anomalies
- Per-IP breakdown: failure count, ban count, first/last seen
- Top attackers list
- Session peak tracking
- Persisted to JSON every 30 seconds

---

## Quick Start

### Requirements
- Python 3.10+
- Linux (Ubuntu 22.04+, Debian 12+, RHEL 8/9, Rocky 8/9, AlmaLinux 8/9)
- Root access
- nftables or iptables
- Optional: fail2ban, MaxMind GeoLite2 DB

### Install

```bash
git clone https://github.com/mobinert/ssh-fortress.git
cd ssh-fortress

sudo bash scripts/install.sh
```

The installer will:
1. Install system dependencies (Python, nftables, fail2ban, rsyslog)
2. Create a Python virtualenv with all required packages
3. Copy config to `/etc/ssh-fortress/settings.yaml`
4. Install and start the systemd service
5. Apply initial hardening

### Configure

```bash
sudo nano /etc/ssh-fortress/settings.yaml
```

Key settings to configure:

```yaml
# Telegram alerts
alerting:
  telegram:
    enabled: true
    bot_token: "1234567890:ABCdef..."   # from @BotFather
    chat_id: "123456789"                # from @userinfobot

# Email alerts
  email:
    enabled: true
    smtp_host: smtp.gmail.com
    smtp_port: 587
    username: "you@gmail.com"
    password: "your-app-password"       # Gmail: use App Password
    from_addr: "you@gmail.com"
    to_addrs:
      - "you@gmail.com"

# AbuseIPDB reputation check
ip_reputation:
  enabled: true
  abuseipdb_api_key: "your-key-here"

# SIEM — Elasticsearch
siem:
  backends:
    elasticsearch:
      enabled: true
      hosts:
        - "https://your-elastic:9200"
      api_key: "your-api-key"
```

### Start

```bash
sudo systemctl restart ssh-fortress
sudo systemctl status ssh-fortress
```

---

## CLI Reference

```
# Apply hardening (preview first with --dry-run)
sudo python main.py harden --dry-run
sudo python main.py harden

# Start daemon (monitoring + brute-force + SIEM + alerts)
sudo python main.py run

# CIS compliance audit of current sshd_config
sudo python main.py audit

# Live status (health + active sessions)
sudo python main.py status

# Event statistics + top attackers
sudo python main.py stats

# Manual IP management
sudo python main.py ban 1.2.3.4 --duration 86400
sudo python main.py unban 1.2.3.4

# SSH key audit
sudo python main.py keys audit

# Test your notification channels
sudo python main.py test telegram
sudo python main.py test email
```

---

## Project Structure

```
ssh-fortress/
├── main.py                              # CLI + daemon wiring
├── requirements.txt
├── setup.py
│
├── config/
│   ├── settings.yaml                   # Central config — all modules read this
│   ├── sshd_config.hardened            # Hardened sshd_config reference
│   ├── fail2ban/
│   │   ├── jail.local                  # fail2ban jail with progressive banning
│   │   └── sshd-fortress.conf          # Custom filter (covers all fail patterns)
│   └── siem/
│       ├── filebeat.yml                # Filebeat config for Elastic stack
│       ├── logstash-ssh.conf           # Logstash pipeline (parse + enrich + route)
│       └── rsyslog-siem.conf           # rsyslog: JSON local log + CEF remote forward
│
├── modules/
│   ├── core/
│   │   ├── config_manager.py           # YAML loader, dotted-key access, template vars
│   │   └── logger.py                   # Structured JSON logger, coloured console
│   │
│   ├── hardening/
│   │   ├── ssh_config.py               # sshd_config writer + CIS auditor
│   │   ├── crypto_policy.py            # Host key management + moduli cleanup
│   │   └── pam_config.py               # PAM faillock + optional 2FA
│   │
│   ├── protection/
│   │   ├── brute_force.py              # In-process tracker, progressive banning
│   │   ├── rate_limiter.py             # nftables/iptables rate limit + SYN flood
│   │   ├── geo_blocker.py              # MaxMind country allow/block list
│   │   ├── port_knocker.py             # TCP/UDP knock sequence daemon
│   │   └── ip_reputation.py            # AbuseIPDB pre-ban check
│   │
│   ├── logging/
│   │   ├── log_parser.py               # Pure-regex auth.log parser → SSHEvent
│   │   ├── log_aggregator.py           # inotify/poll log tail, handler fan-out
│   │   └── siem_forwarder.py           # 5 SIEM backends (ES/Splunk/Syslog/Kafka/Webhook)
│   │
│   ├── monitoring/
│   │   ├── session_monitor.py          # Live session tracking → sessions.json
│   │   ├── anomaly_detector.py         # IP spray, travel, hours, spikes, root
│   │   └── health_checker.py           # sshd / nftables / fail2ban / disk / SIEM health
│   │
│   ├── alerting/
│   │   ├── alert_manager.py            # Rate-limited Slack/PagerDuty/Webhook routing
│   │   ├── telegram_notifier.py        # Telegram Bot API (async queue, silent hours)
│   │   ├── email_notifier.py           # HTML email (login/ban/anomaly/daily digest)
│   │   └── discord_notifier.py         # Discord webhook with rich embeds
│   │
│   ├── key_management/
│   │   └── key_auditor.py              # authorized_keys scanner (weak/old/dup keys)
│   │
│   └── stats/
│       └── stats_tracker.py            # Event counters, top attackers, daily reset
│
├── scripts/
│   ├── install.sh                      # Full install (Ubuntu/Debian/RHEL/Rocky)
│   ├── setup_2fa.sh                    # Google Authenticator TOTP per-user setup
│   └── rotate_keys.sh                  # Ed25519 key rotation helper
│
└── systemd/
    ├── ssh-fortress.service            # Systemd service (hardened, resource-limited)
    └── ssh-fortress-monitor.timer      # Daily key audit timer
```

---

## Architecture

```
 /var/log/auth.log
        │
        ▼
 ┌──────────────────────────────────────┐
 │     LogAggregator  (inotify/poll)    │
 │     LogParser  →  SSHEvent (typed)   │
 └──────────────┬───────────────────────┘
                │  SSHEvent
                ▼
 ┌──────────────────────────────────────────────────────────────┐
 │                   Handler Fan-out                            │
 │                                                              │
 │  BruteForceProtector  ──→  nftables banned_ips set           │
 │         │                  fail2ban (optional)               │
 │         ▼                                                    │
 │  AlertRouter                                                 │
 │    ├── TelegramNotifier  ──→  Telegram Bot                   │
 │    ├── EmailNotifier     ──→  SMTP (HTML emails)             │
 │    ├── DiscordNotifier   ──→  Discord Webhook                │
 │    ├── AlertManager      ──→  Slack / PagerDuty / Webhook    │
 │    └── StatsTracker      ──→  stats.json                     │
 │                                                              │
 │  SIEMForwarder                                               │
 │    ├── Elasticsearch  (bulk API, batched)                    │
 │    ├── Splunk HEC     (batched)                              │
 │    ├── Syslog         (CEF / RFC5424 / JSON)                 │
 │    ├── Kafka          (batched, async)                       │
 │    └── Webhook        (JSON POST)                            │
 │                                                              │
 │  SessionMonitor   ──→  sessions.json                         │
 │  AnomalyDetector  ──→  AlertRouter                           │
 │  IPReputationChecker ──→  AbuseIPDB API (cached 24h)         │
 └──────────────────────────────────────────────────────────────┘
```

---

## Telegram Setup (Step by Step)

1. Open Telegram, search for **@BotFather**
2. Send `/newbot` and follow the instructions
3. Copy the **bot token** (looks like `1234567890:ABCdefGHI...`)
4. Search for **@userinfobot**, send `/start` — it will show your **chat_id**
5. Edit `settings.yaml`:

```yaml
alerting:
  telegram:
    enabled: true
    bot_token: "YOUR_BOT_TOKEN_HERE"
    chat_id: "YOUR_CHAT_ID_HERE"
```

6. Test it:

```bash
sudo python main.py test telegram
```

You'll get a message in Telegram instantly.

---

## Email Setup (Gmail Example)

1. Enable 2FA on your Google account
2. Go to **Google Account → Security → App passwords**
3. Generate an App Password for "Mail"
4. Edit `settings.yaml`:

```yaml
alerting:
  email:
    enabled: true
    smtp_host: smtp.gmail.com
    smtp_port: 587
    use_tls: true
    username: "you@gmail.com"
    password: "xxxx xxxx xxxx xxxx"   # App Password (spaces OK)
    from_addr: "you@gmail.com"
    to_addrs:
      - "you@gmail.com"
    daily_report: true
    daily_report_hour: 8
```

5. Test:

```bash
sudo python main.py test email
```

---

## Hardened sshd_config (Applied Automatically)

| Setting | Value | Reason |
|---|---|---|
| `PermitRootLogin` | `no` | No direct root SSH |
| `PasswordAuthentication` | `no` | Keys only |
| `MaxAuthTries` | `3` | Limit attempts per connection |
| `LoginGraceTime` | `30` | 30s to authenticate |
| `X11Forwarding` | `no` | Attack surface reduction |
| `AllowTcpForwarding` | `no` | Prevent tunneling |
| `Compression` | `no` | CVE history (CRIME-like) |
| `LogLevel` | `VERBOSE` | Full key fingerprint logging |
| `Ciphers` | ChaCha20, AES-GCM only | No CBC, no RC4 |
| `MACs` | ETM only | No encrypt-and-MAC |
| `KexAlgorithms` | Curve25519, DH-SHA512 only | No RSA KEX |

---

## FAQ

**Q: Will SSH Fortress lock me out?**
A: No. It validates with `sshd -t` before applying any config change and auto-reverts on failure. Always test in a new terminal before closing your existing session.

**Q: Do I need Elasticsearch/Splunk?**
A: No. All SIEM backends are optional. The syslog backend is always on as a fallback. Telegram and email work completely independently.

**Q: Does it work on containers/VMs?**
A: Yes, but nftables may need `NET_ADMIN` capability in containers. The brute-force module works anywhere.

**Q: What's the performance impact?**
A: Near zero. inotify-driven log tailing uses 0 CPU when idle. Brute-force decisions are O(1). SIEM forwarding is async with backpressure queues. The service is capped at 20% CPU / 256 MB RAM in the systemd unit.

---

## License


MIT License — see [LICENSE](LICENSE) for details.

---

<div align="center">
  <sub>Built by <a href="https://github.com/mobinert">Mobin Erteghaie</a></sub>
</div>
