# Managed Network Scanner

A high-performance Python3 network scanner designed for penetration testing and security assessments. Efficiently handles large network ranges (including /16 subnets) with intelligent resource management and real-time results display.

## Features

- **🚀 High Performance**: Multi-threaded scanning with configurable concurrency limits
- **🎯 Smart Targeting**: Initial ping sweep to identify live hosts before detailed scanning
- **📊 Real-time Results**: Live display of scan findings as they are discovered
- **💾 Multiple Output Formats**: Saves results in XML, text, and grepable formats (-oA equivalent)
- **🔍 Comprehensive Detection**: Service version detection and script scanning (-sC -sV equivalent)
- **⚡ Resource Management**: Built-in rate limiting and timeout controls
- **🛡️ Network Friendly**: Configurable delays to prevent network overwhelming
- **🔄 Graceful Interruption**: Saves partial results if scan is interrupted

## Requirements

- Python 3.6+
- Nmap installed and accessible in PATH
- Appropriate network permissions for scanning target ranges

### Installing Dependencies

**Ubuntu/Debian:**
```bash
sudo apt update
sudo apt install nmap python3
```

**CentOS/RHEL/Fedora:**
```bash
sudo yum install nmap python3
# or for newer versions:
sudo dnf install nmap python3
```

**macOS:**
```bash
brew install nmap python3
```

## Installation

1. Download the scanner script:
```bash
git clone the repo
```

2. Make it executable:
```bash
chmod +x n3t-R4ng3r.py
```

## Usage

### Basic Syntax
```bash
python3 n3t-R4ng3r.py -r <NETWORK_RANGE> [OPTIONS]
```

### Required Arguments
- `-r, --range`: Network range to scan (CIDR notation)

### Optional Arguments
- `--threads`: Maximum concurrent threads (default: 50, max: 200)
- `--delay`: Delay between scans in seconds (default: 0.1)

### Examples

**Basic subnet scan:**
```bash
python3 n3t-R4ng3r.py -r 192.168.1.0/24
```

**Large network range with custom threading:**
```bash
python3 n3t-R4ng3r.py -r 10.0.0.0/16 --threads 30 --delay 0.2
```

**Conservative scan for sensitive environments:**
```bash
python3 n3t-R4ng3r.py -r 172.16.0.0/12 --threads 10 --delay 0.5
```

**Very large range (Class A):**
```bash
python3 n3t-R4ng3r.py -r 10.0.0.0/8 --threads 20 --delay 0.3
```

## Output Files

The scanner automatically saves results in multiple formats using the pattern `<range>-network.*`:

| File Extension | Format | Description |
|---------------|---------|-------------|
| `.xml` | XML | Machine-readable format for parsing |
| `.nmap` | Text | Human-readable detailed results |
| `.gnmap` | Grepable | Easy to grep and filter results |

**Example output files for range `192.168.1.0/24`:**
- `192-168-1-0_24-network.xml`
- `192-168-1-0_24-network.nmap`
- `192-168-1-0_24-network.gnmap`

## Performance Tuning

### Thread Configuration

| Network Size | Recommended Threads | Use Case |
|-------------|-------------------|----------|
| /24 (254 hosts) | 50-100 | Standard scanning |
| /20 (4,094 hosts) | 30-50 | Medium networks |
| /16 (65,534 hosts) | 20-30 | Large networks |
| /12 or larger | 10-20 | Very large networks |

### Delay Settings

| Environment | Recommended Delay | Description |
|------------|------------------|-------------|
| Internal Lab | 0.05s | Fast scanning |
| Corporate Network | 0.1s (default) | Balanced approach |
| Client Network | 0.2-0.5s | Conservative scanning |
| Internet Targets | 0.5-1.0s | Very conservative |

## Scanning Process

The scanner follows a two-phase approach:

### Phase 1: Host Discovery
- Performs fast ping sweep (-sn) across the entire range
- Identifies live hosts using ICMP and TCP SYN probes
- Reduces scan time by focusing only on responsive targets

### Phase 2: Detailed Scanning
- Comprehensive port scan (-p-) on live hosts only
- Service version detection (-sV)
- Default script scanning (-sC)
- Real-time result display and logging

## Sample Output

```
[*] Starting managed network scan
[*] Target: 192.168.1.0/24
[*] Max threads: 50
[*] Output: 192-168-1-0_24-network.*
[*] Starting ping sweep on 192.168.1.0/24
[*] Scanning 256 potential hosts...
[+] Found 12 live hosts
[*] Starting detailed scans on 12 hosts
[*] Using 12 concurrent threads
[*] Scanning 192.168.1.1 (1/12)

============================================================
[+] RESULTS for 192.168.1.1
============================================================
PORT     STATE SERVICE    VERSION
22/tcp   open  ssh        OpenSSH 8.2p1 Ubuntu 4ubuntu0.5
80/tcp   open  http       Apache httpd 2.4.41
443/tcp  open  ssl/https  Apache httpd 2.4.41
|_http-server-header: Apache/2.4.41 (Ubuntu)
|_ssl-date: TLS randomness does not represent time

[+] 192.168.1.1 - Open ports: 22/tcp, 80/tcp, 443/tcp
============================================================
```

## Error Handling

The scanner includes comprehensive error handling for:

- **Invalid network ranges**: Validates CIDR notation before scanning
- **Missing dependencies**: Checks for nmap installation
- **Network timeouts**: Configurable timeout values
- **Permission issues**: Clear error messages for access problems
- **Interrupted scans**: Saves partial results on Ctrl+C

## Security Considerations

### Legal Notice
**⚠️ WARNING**: Only scan networks you own or have explicit permission to test. Unauthorized network scanning may violate local laws and regulations.

### Best Practices
- Always obtain written authorization before scanning
- Start with small ranges to test performance
- Use conservative settings in production environments
- Monitor network impact during scanning
- Respect rate limiting and timeout settings

## Troubleshooting

### Common Issues

**"nmap is not installed or not in PATH"**
```bash
# Install nmap using your package manager
sudo apt install nmap  # Ubuntu/Debian
sudo yum install nmap   # CentOS/RHEL
```

**"Permission denied" errors**
```bash
# Some scans require root privileges
sudo python3 n3t-R4ng3r.py -r 192.168.1.0/24
```

**High CPU/Memory usage**
```bash
# Reduce thread count and increase delay
python3 n3t-R4ng3r.py -r 10.0.0.0/16 --threads 10 --delay 0.5
```

**Scan appears stuck**
- Large ranges naturally take time
- Check system resources (CPU, memory, network)
- Consider reducing thread count
- Monitor progress messages

### Performance Optimization

For optimal performance:
1. **Start small**: Test with /24 ranges first
2. **Monitor resources**: Watch CPU and memory usage
3. **Adjust threading**: Reduce threads if system becomes unresponsive
4. **Network capacity**: Consider your network bandwidth
5. **Target environment**: Use conservative settings for production networks

## Contributing

Contributions are welcome! Please:
1. Fork the repository
2. Create a feature branch
3. Test your changes thoroughly
4. Submit a pull request with detailed description

## License

This project is licensed under the MIT License - see the LICENSE file for details.

## Changelog

### v1.0.0
- Initial release
- Multi-threaded scanning
- Real-time result display
- Multiple output formats
- Comprehensive error handling

## Support

For issues, questions, or contributions:
- Create an issue on GitHub
- Review existing documentation
- Check troubleshooting section

---

**Remember**: Always scan responsibly and ethically. This tool is designed for authorized security testing only.
