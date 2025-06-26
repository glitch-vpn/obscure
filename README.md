# Obscure - Real-time Log Anonymizer

High-performance log anonymization daemon for VPN infrastructure. Processes logs in real-time using FIFO pipes without storing original data on disk.

## Features

- **Real-time processing** via FIFO pipes (50-100 MB/s throughput)
- **Zero disk storage** of original logs
- **Multi-protocol support**: Nginx, Xray, OpenVPN, WireGuard, AmneziaWG
- **Custom log formats** with regex templates
- **IP address hashing** with salt (IPv4/IPv6 detection)
- **Configurable anonymization levels** (low/medium/high)
- **Concurrent processing** with automatic FIFO management

## Quick Start

### 1. Setup
```bash
sudo obscure setup
```

Creates default configuration and FIFO pipes:
- `/var/log/nginx/access.fifo` → `/var/log/vpn-anonymized/nginx_access.log`
- `/var/log/xray/access.fifo` → `/var/log/vpn-anonymized/xray_access.log`
- `/var/log/openvpn/access.fifo` → `/var/log/vpn-anonymized/openvpn_access.log`

### 2. Configure Services
Update your VPN services to write to FIFO pipes:

**Nginx** (`/etc/nginx/nginx.conf`):
```nginx
access_log /var/log/nginx/access.fifo;
```

**Xray** (`/usr/local/etc/xray/config.json`):
```json
{
  "log": {
    "access": "/var/log/xray/access.fifo"
  }
}
```

### 3. Start Daemon
```bash
sudo obscure start
```

## CLI Reference

```
obscure [COMMAND] [OPTIONS]

Commands:
  setup                    Setup FIFOs and config, then exit
    Options:
      --config, -c [path]    Path to config file (default: /etc/obscure/pipes.conf)
      --salt, -s [string]    Salt for hashing

  start                    Start log processing daemon
    Options:
      --config, -c [path]    Path to config file (default: /etc/obscure/pipes.conf)
      --salt, -s [string]    Salt for hashing
      --daemon, -d           Start process as daemon (default: true)
      --level, -l [level]    Anonymization level: low, medium, high (default: high)
```

## Configuration

Example `pipes.conf`:
```json
{
  "pipes": [
    {
      "input": "/var/log/nginx/access.fifo",
      "output": "/var/log/vpn-anonymized/nginx_access.log",
      "type": "nginx-access"
    },
    {
      "input": "/var/log/custom/app.fifo",
      "output": "/var/log/vpn-anonymized/app.log",
      "type": "manual",
      "input_template": "{\"user\":\\s?\"(?P<username>[a-zA-Z_0-9]+)\"\\s?}",
      "output_template": "user: {{salt .username}}"
    },
    {
      "input": "/var/log/json/app.fifo",
      "output": "/var/log/vpn-anonymized/json_app.log",
      "type": "manual",
      "format": "json",
      "anonymize_fields": ["username", "email", "name", "password", "secret"],
      "salt_fields": ["ip", "key", "token"]
    }
  ]
}
```

## Supported Log Types

### Built-in Types
- `nginx-access` - Nginx access logs
- `nginx-stream` - Nginx stream logs  
- `xray` - Xray proxy logs
- `openvpn` - OpenVPN logs
- `wireguard` - WireGuard logs
- `amneziawg` - AmneziaWG logs

### Manual Type
For custom log formats using regex templates:

```json
{
  "type": "manual",
  "input_template": "(?P<ip>\\d+\\.\\d+\\.\\d+\\.\\d+) (?P<user>\\w+)",
  "output_template": "{{salt .ip}} {{anonymize .user}}"
}
```

### JSON Format
For JSON log processing with field-based anonymization:

```json
{
  "type": "manual",
  "format": "json",
  "anonymize_fields": ["username", "email", "name"],
  "salt_fields": ["ip", "key", "token"]
}
```

**Format Options:**
- `"plain"` (default) - Uses existing text processing
- `"json"` - Parses JSON and processes fields by substring matching

**JSON Field Configuration:**
- `anonymize_fields` - Field substrings to replace with `[REDACTED]`
- `salt_fields` - Field substrings to hash with salt

## Template Functions

- `{{salt .field}}` - Hash field with salt (returns raw hex)
- `{{anonymize .field}}` - Replace with `[HIDDEN]`
- `{{.field}}` - Keep field unchanged

## Anonymization Examples

### IP Addresses
```
192.168.1.100 → [IPv4:f9927a12318f]
2001:db8::1   → [IPv6:a8b3c2d1e4f5]
```

### Nginx Access Log
```
# Original
192.168.1.100 [25/Dec/2024:15:30:45 +0000] "GET /api/users?id=123 HTTP/1.1" 200 1234 "https://evil.com" "Mozilla/5.0"

# Anonymized (high level)
[IPv4:f9927a12318f] [ANONYMIZED_TIME] "GET /api/users?[PARAM]=[REDACTED] HTTP/1.1" 200 1234 "[REDACTED]" "[REDACTED]"
```

### Xray Log
```
# Original  
2024/12/25 15:30:45 [Info] VLESS user: john@evil.com from 192.168.1.100:54321

# Anonymized
[ANONYMIZED_TIME] [Info] VLESS user: [user_REDACTED] from [IPv4:f9927a12318f]:54321
```

### Custom Template
```
# Input
{"username": "alice"}

# Template
"input_template": "{\"username\":\\s?\"(?P<username>[a-zA-Z_0-9]+)\"\\s?}",
"output_template": "user: {{salt .username}}"

# Output
user: b794385f2d1e
```

### JSON Processing
```
# Input JSON
{"username": "alice", "password": "secret123", "client_ip": "192.168.1.100", "action": "login"}

# Configuration
"format": "json",
"anonymize_fields": ["username", "pass"],
"salt_fields": ["ip"]

# Output JSON
{"username":"[REDACTED]","password":"[REDACTED]","client_ip":"[IPv4:f9927a12318f]","action":"login"}
```

## Performance

Benchmarks on Intel i7-13650HX:
- **IP hashing**: 88M ops/sec (13.47 ns/op, 0 allocs)
- **Nginx processing**: 302k lines/sec (4.1 μs/line)
- **Manual templates**: 372k lines/sec (2.95 μs/line)

Real-world throughput: **50-100 MB/s** for mixed log processing.

## Security Features

- **Salted hashing** prevents rainbow table attacks
- **No original data storage** on disk
- **Configurable anonymization levels**:
  - `low` - Keep timestamps, anonymize IPs/users
  - `medium` - Anonymize timestamps to hour precision
  - `high` - Full timestamp anonymization
- **Localhost preservation** (127.0.0.1, ::1 unchanged)

## Installation

### From Source
```bash
git clone https://github.com/glitch-vpn/obscure.git
cd obscure
go build -o obscure .
sudo cp obscure /usr/local/bin/
```

### Systemd Service
```ini
[Unit]
Description=Obscure VPN Log Anonymizer
After=network.target

[Service]
Type=simple
User=root
ExecStart=/usr/local/bin/obscure start
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
```

## Troubleshooting

### FIFO Issues
```bash
# Check FIFO exists
ls -la /var/log/nginx/access.fifo

# Test FIFO manually
echo "test log line" > /var/log/nginx/access.fifo
```

### Permission Issues
```bash
# Ensure proper permissions
sudo chown root:root /usr/local/bin/obscure
sudo chmod 755 /usr/local/bin/obscure
sudo mkdir -p /var/log/vpn-anonymized
sudo chmod 755 /var/log/vpn-anonymized
```

### Debug Mode
```bash
# Run with verbose logging
obscure start --level low
```

## Architecture

```
┌─────────────┐    FIFO     ┌─────────────┐    File    ┌─────────────┐
│   Service   │ ──────────> │   Obscure   │ ─────────> │ Anonymized  │
│ (Nginx/etc) │             │   Daemon    │            │    Logs     │
└─────────────┘             └─────────────┘            └─────────────┘
                                   │
                                   ▼
                            ┌─────────────┐
                            │ Config File │
                            │ pipes.conf  │
                            └─────────────┘
```
