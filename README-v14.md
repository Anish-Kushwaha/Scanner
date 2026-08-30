# Anish Scanner v14.0.0

Nmap-style authorized TCP reconnaissance engine for the Scanner project.

## Highlights

- TCP connect scanning across individual ports and ranges
- Timing profiles `-T0` through `-T5`
- Configurable concurrency and connection timeouts
- Basic service-name mapping and safe banner probing
- Optional reverse DNS
- JSON and CSV result export
- IPv4 hostname resolution

## Examples

```bash
python Source-Code/nmap_style_scanner.py 192.168.1.1 -p 22,80,443
python Source-Code/nmap_style_scanner.py example.com -p 1-1024 -T3 -r
python Source-Code/nmap_style_scanner.py 10.0.0.10 -p 80,443,8080 -oJ scan.json -oC scan.csv
```

Only scan systems and networks for which you have explicit authorization. This module uses normal TCP connect behavior rather than raw-packet or stealth scanning.
