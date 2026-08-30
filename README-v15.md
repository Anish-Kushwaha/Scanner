# Scanner v15.0.0 — Nmap-inspired network engine

Scanner v15 is a larger modular replacement for the earlier 216-line prototype. It focuses on authorized, non-destructive TCP assessment and builds on the existing Scanner project's reconnaissance and web-analysis components.

## Highlights

- TCP connect scanning across individual ports and ranges
- Built-in high-value port set plus `-F` fast mode
- Timing profiles `-T0` through `-T5`
- Configurable timeout, concurrency, and retries
- Service-name mapping and safe banner identification
- HTTP/HTTPS HEAD probing on common web ports
- TLS negotiation and certificate metadata collection
- Reverse DNS for discovered open services
- Product/version hints from banners and HTTP headers
- Basic operating-system family hinting from observed evidence
- JSON, CSV, and grepable output formats
- Async scanning with bounded concurrency
- Explicit authorization warning and no raw-packet stealth/exploitation logic

## Examples

```bash
python Source-Code/Scanner-v15.py scanme.example -p 22,80,443
python Source-Code/Scanner-v15.py scanme.example -p 1-1024 -T3
python Source-Code/Scanner-v15.py 192.0.2.10 -F -T4 --rdns
python Source-Code/Scanner-v15.py example.test -p 80,443,8080,8443 -oJ result.json -oC result.csv -oG result.gnmap
```

Only scan systems for which you have permission. v15 intentionally uses TCP connect scanning and non-destructive service probes rather than stealth/raw-packet techniques or exploitation.
