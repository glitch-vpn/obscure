# Privacy Log Processor

High-performance VPN log anonymization tool written in Go.

## Features

- **Multi-protocol support**: nginx, Xray, WireGuard, AmneziaWG, OpenVPN
- **High performance**: 50-100 MB/s throughput with parallel processing
- **Privacy-first**: IP hashing, timestamp anonymization, credential removal
- **Zero memory leaks**: Optimized buffering and goroutine management
- **Configurable**: Multiple anonymization levels (low, medium, high)

## Supported Log Types

| Protocol | Log Type | Features |
|----------|----------|----------|
| nginx | `nginx-access` | IP, User-Agent, Referer anonymization |
| nginx | `nginx-stream` | SNI hiding, IP hashing |
| Xray | `xray` | UUID, REALITY keys, Shadowsocks credentials |
| WireGuard | `wireguard` | Peer keys, interface names |
| AmneziaWG | `amneziawg` | Obfuscation parameters, peer keys |
| OpenVPN | `openvpn` | Certificate names, client IPs |

## Performance

- **Throughput**: 50-100 MB/s on modern servers
- **Concurrency**: Automatic multi-core utilization
- **Memory**: Minimal footprint with streaming processing
- **Caching**: IP hash caching for repeated anonymization

## Usage

```bash
# Basic usage
./privacy_log_processor -input /var/log/nginx/access.log -type nginx-access -salt "your-salt" -level high

# With output file
./privacy_log_processor -input /var/log/xray/access.log -output /tmp/anonymized.log -type xray -salt "secret" -level medium

# Benchmark mode
./privacy_log_processor -benchmark
```

## Anonymization Levels

- **low**: Keep timestamps, anonymize IPs only
- **medium**: Anonymize IPs and round timestamps
- **high**: Full anonymization (default)

## Build

```bash
go build -o privacy_log_processor main.go
```

## Cross-compilation

```bash
# Linux AMD64
GOOS=linux GOARCH=amd64 go build -o privacy_log_processor-linux-amd64 main.go

# Linux ARM64
GOOS=linux GOARCH=arm64 go build -o privacy_log_processor-linux-arm64 main.go
```

## Examples

### Nginx Access Log
**Before:**
```
192.168.1.100 [25/Dec/2024:15:30:45] "GET /secret?user=john HTTP/1.1" 200 1234 "https://evil.com" "Mozilla/5.0"
```

**After:**
```
[IPv4:a1b2c3d4e5f6] [ANONYMIZED_TIME] "GET /secret?[PARAM]=[REDACTED] HTTP/1.1" 200 1234 "[REDACTED]" "[REDACTED]"
```

### Xray VLESS Log
**Before:**
```
2024/12/25 15:30:45 [Info] VLESS user: 12345678-1234-1234-1234-123456789abc from 192.168.1.100:54321
```

**After:**
```
[ANONYMIZED_TIME] [Info] VLESS user: [UUID_REDACTED] from [IPv4:a1b2c3d4e5f6]:54321
```

## License

MIT License # obscure
