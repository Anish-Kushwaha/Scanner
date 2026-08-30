#!/usr/bin/env python3
"""Scanner v15 - modular Nmap-inspired network assessment framework.

Authorized use only. Safe by design: TCP connect scanning and non-destructive
service identification; no stealth/raw packets, exploitation, credential theft,
persistence, or destructive payloads.
"""
from __future__ import annotations

import argparse
import asyncio
import csv
import ipaddress
import json
import os
import platform
import re
import socket
import ssl
import statistics
import struct
import subprocess
import sys
import time
from collections import Counter
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Iterable

VERSION = "15.0.0"

TIMING = {
    0: {"timeout": 5.0, "concurrency": 5, "retries": 3},
    1: {"timeout": 3.0, "concurrency": 10, "retries": 2},
    2: {"timeout": 2.0, "concurrency": 25, "retries": 2},
    3: {"timeout": 1.25, "concurrency": 60, "retries": 1},
    4: {"timeout": 0.75, "concurrency": 120, "retries": 1},
    5: {"timeout": 0.50, "concurrency": 250, "retries": 1},
}

TOP_PORTS = [
    1,7,9,13,17,19,20,21,22,23,25,26,37,43,53,67,68,69,80,81,88,110,111,119,
    123,135,137,138,139,143,161,389,443,445,465,514,515,587,631,636,873,902,
    989,990,993,995,1025,1433,1521,1723,1883,2049,2375,2376,2379,2380,3000,
    3128,3306,3389,4000,5000,5001,5432,5601,5672,5900,5984,5985,5986,6379,
    6443,7001,7002,8000,8008,8009,8080,8081,8088,8089,8443,8888,9000,9090,
    9091,9200,9300,11211,15672,27017,27018,28017,50000
]

SERVICE_MAP = {
    20:"ftp-data",21:"ftp",22:"ssh",23:"telnet",25:"smtp",53:"dns",69:"tftp",
    80:"http",88:"kerberos",110:"pop3",111:"rpcbind",119:"nntp",123:"ntp",
    135:"msrpc",139:"netbios-ssn",143:"imap",161:"snmp",389:"ldap",443:"https",
    445:"microsoft-ds",465:"smtps",514:"shell-syslog",587:"submission",631:"ipp",
    636:"ldaps",873:"rsync",993:"imaps",995:"pop3s",1433:"mssql",1521:"oracle",
    1723:"pptp",1883:"mqtt",2049:"nfs",2375:"docker",2379:"etcd",2380:"etcd-peer",
    3306:"mysql",3389:"rdp",5432:"postgresql",5601:"kibana",5672:"amqp",5900:"vnc",
    5984:"couchdb",5985:"winrm-http",5986:"winrm-https",6379:"redis",6443:"kubernetes",
    7001:"weblogic",7002:"weblogic-ssl",8000:"http-alt",8008:"http-alt",8009:"ajp",
    8080:"http-proxy",8081:"http-alt",8088:"http-alt",8443:"https-alt",8888:"http-alt",
    9000:"http-alt",9090:"http-alt",9091:"http-alt",9200:"elasticsearch",9300:"es-transport",
    11211:"memcached",15672:"rabbitmq-mgmt",27017:"mongodb",28017:"mongodb-http",50000:"db2"
}

HTTP_PORTS = {80,81,443,8000,8008,8009,8080,8081,8088,8089,8443,8888,9000,9090,9091,9200}
TLS_PORTS = {443,465,636,853,993,995,2376,5986,8443}

PROBES: dict[int, bytes] = {
    21: b"\r\n",
    22: b"\r\n",
    23: b"\r\n",
    25: b"EHLO scanner.local\r\n",
    110: b"CAPA\r\n",
    143: b"a001 CAPABILITY\r\n",
    587: b"EHLO scanner.local\r\n",
    3306: b"\x0a",
    6379: b"*1\r\n$4\r\nPING\r\n",
    11211: b"version\r\n",
}

USER_AGENT = "Anish-Scanner/15.0 (+authorized-security-assessment)"

@dataclass(slots=True)
class PortResult:
    port: int
    state: str
    service: str
    protocol: str = "tcp"
    banner: str = ""
    product: str = ""
    version: str = ""
    latency_ms: float = 0.0
    tls: bool = False
    tls_version: str = ""
    certificate_subject: str = ""
    certificate_issuer: str = ""
    certificate_expiry: str = ""
    reverse_dns: str = ""
    error: str = ""
    evidence: list[str] = field(default_factory=list)

@dataclass(slots=True)
class HostResult:
    target: str
    ip: str
    hostname: str = ""
    scanned_at: str = ""
    os_family_hint: str = ""
    ports: list[PortResult] = field(default_factory=list)
    summary: dict[str, int] = field(default_factory=dict)
    warnings: list[str] = field(default_factory=list)


def parse_ports(spec: str) -> list[int]:
    result: set[int] = set()
    for token in spec.split(","):
        token = token.strip()
        if not token:
            continue
        if "-" in token:
            left, right = token.split("-", 1)
            a, b = int(left), int(right)
            if a > b:
                a, b = b, a
            if a < 1 or b > 65535:
                raise ValueError("Port range must be within 1-65535")
            result.update(range(a, b + 1))
        else:
            port = int(token)
            if not 1 <= port <= 65535:
                raise ValueError("Port must be within 1-65535")
            result.add(port)
    if not result:
        raise ValueError("No ports supplied")
    return sorted(result)


def resolve_target(target: str) -> tuple[str, str]:
    value = target.strip()
    try:
        ip = ipaddress.ip_address(value)
        return value, str(ip)
    except ValueError:
        pass
    host = value
    if "://" in host:
        host = host.split("://", 1)[1]
    host = host.split("/", 1)[0]
    try:
        infos = socket.getaddrinfo(host, None, family=socket.AF_UNSPEC, type=socket.SOCK_STREAM)
    except socket.gaierror as exc:
        raise ValueError(f"Unable to resolve target {target}: {exc}") from exc
    if not infos:
        raise ValueError(f"Unable to resolve target {target}")
    ipv4 = next((x for x in infos if x[0] == socket.AF_INET), infos[0])
    return host, ipv4[4][0]


def service_name(port: int) -> str:
    if port in SERVICE_MAP:
        return SERVICE_MAP[port]
    try:
        return socket.getservbyport(port, "tcp")
    except OSError:
        return "unknown"


def clean_banner(text: str) -> str:
    text = text.replace("\x00", " ").replace("\r", " ").replace("\n", " ")
    return " ".join(text.split())[:800]


def parse_product_version(banner: str) -> tuple[str, str]:
    patterns = [
        (r"OpenSSH[_ -]([0-9.]+)", "OpenSSH"),
        (r"nginx/?([0-9.]*)", "nginx"),
        (r"Apache/?([0-9.]*)", "Apache httpd"),
        (r"Microsoft-IIS/?([0-9.]*)", "Microsoft IIS"),
        (r"vsftpd[ /]([0-9.]+)", "vsftpd"),
        (r"PostgreSQL[^0-9]*([0-9]+(?:\.[0-9]+)+)", "PostgreSQL"),
        (r"Redis server v?([0-9]+(?:\.[0-9]+)+)", "Redis"),
        (r"MongoDB/?(?:[ /])?([0-9]+(?:\.[0-9]+)+)", "MongoDB"),
        (r"MySQL[^0-9]*([0-9]+(?:\.[0-9]+)+)", "MySQL"),
    ]
    for pattern, product in patterns:
        match = re.search(pattern, banner, re.I)
        if match:
            return product, match.group(1)
    return "", ""


def infer_os(results: list[PortResult]) -> str:
    text = " ".join((x.banner or "").lower() for x in results)
    if any(x in text for x in ["microsoft-iis", "windows", "microsoft ftp", "winrm"]):
        return "Windows-like"
    if any(x in text for x in ["openssh", "ubuntu", "debian", "centos", "red hat", "nginx", "apache"]):
        return "Unix/Linux-like"
    return "Unknown"


async def reverse_dns(ip: str) -> str:
    loop = asyncio.get_running_loop()
    try:
        host, _, _ = await loop.run_in_executor(None, socket.gethostbyaddr, ip)
        return host
    except Exception:
        return ""


async def tcp_connect(ip: str, port: int, timeout: float):
    started = time.perf_counter()
    reader = writer = None
    try:
        reader, writer = await asyncio.wait_for(asyncio.open_connection(ip, port), timeout=timeout)
        latency = (time.perf_counter() - started) * 1000
        return reader, writer, latency, "open", ""
    except asyncio.TimeoutError:
        return None, None, (time.perf_counter() - started) * 1000, "filtered/timeout", "timeout"
    except ConnectionRefusedError:
        return None, None, (time.perf_counter() - started) * 1000, "closed", "refused"
    except OSError as exc:
        return None, None, (time.perf_counter() - started) * 1000, "error", str(exc)


def tls_certificate_details(der: bytes) -> tuple[str, str, str]:
    if not der:
        return "", "", ""
    try:
        pem = ssl.DER_cert_to_PEM_cert(der)
        # Public stdlib decoding of DER is limited; use temporary in-memory
        # context where possible and return compact evidence rather than parsing
        # ASN.1 manually.
        cert_file = None
        import tempfile
        with tempfile.NamedTemporaryFile(mode="w", suffix=".pem", delete=False) as handle:
            handle.write(pem)
            cert_file = handle.name
        try:
            decoded = ssl._ssl._test_decode_cert(cert_file)
        finally:
            os.unlink(cert_file)
        subject = ", ".join("=".join(pair) for part in decoded.get("subject", []) for pair in part)
        issuer = ", ".join("=".join(pair) for part in decoded.get("issuer", []) for pair in part)
        expiry = decoded.get("notAfter", "")
        return subject, issuer, expiry
    except Exception:
        return "", "", ""


async def tls_probe(host: str, ip: str, port: int, timeout: float):
    context = ssl.create_default_context()
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE
    try:
        raw_reader, raw_writer = await asyncio.wait_for(asyncio.open_connection(ip, port), timeout=timeout)
        loop = asyncio.get_running_loop()
        transport = raw_writer.transport
        protocol = transport.get_protocol()
        tls_transport = await asyncio.wait_for(loop.start_tls(transport, protocol, context, server_side=False, server_hostname=host), timeout=timeout)
        # start_tls returns a transport; asyncio StreamReader/Writer wrapping is not portable,
        # so we close after negotiating and retrieve certificate from the SSL object.
        ssl_obj = tls_transport.get_extra_info("ssl_object")
        der = ssl_obj.getpeercert(binary_form=True) if ssl_obj else b""
        version = ssl_obj.version() if ssl_obj else ""
        subject, issuer, expiry = tls_certificate_details(der)
        raw_writer.close()
        try:
            await raw_writer.wait_closed()
        except Exception:
            pass
        return version, subject, issuer, expiry, ""
    except Exception as exc:
        return "", "", "", "", str(exc)


async def http_probe(host: str, ip: str, port: int, timeout: float, https: bool = False):
    scheme = "https" if https else "http"
    context = ssl.create_default_context()
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE
    reader = writer = None
    try:
        if https:
            reader, writer = await asyncio.wait_for(asyncio.open_connection(ip, port, ssl=context, server_hostname=host), timeout=timeout)
        else:
            reader, writer = await asyncio.wait_for(asyncio.open_connection(ip, port), timeout=timeout)
        request = (
            f"HEAD / HTTP/1.1\r\nHost: {host}\r\nUser-Agent: {USER_AGENT}\r\n"
            "Connection: close\r\nAccept: */*\r\n\r\n"
        ).encode("ascii", "ignore")
        writer.write(request)
        await writer.drain()
        data = await asyncio.wait_for(reader.read(8192), timeout=min(timeout, 3.0))
        text = data.decode("iso-8859-1", "replace")
        lines = text.splitlines()
        headers: dict[str, str] = {}
        status_line = lines[0] if lines else ""
        for line in lines[1:]:
            if ":" in line:
                key, value = line.split(":", 1)
                headers[key.strip().lower()] = value.strip()
        return {
            "status": status_line,
            "server": headers.get("server", ""),
            "powered_by": headers.get("x-powered-by", ""),
            "location": headers.get("location", ""),
            "headers": headers,
            "evidence": clean_banner(" ".join(lines[:12]))
        }
    except Exception as exc:
        return {"status":"", "server":"", "powered_by":"", "location":"", "headers":{}, "evidence":"", "error":str(exc)}
    finally:
        if writer:
            writer.close()
            try:
                await writer.wait_closed()
            except Exception:
                pass


async def banner_probe(host: str, ip: str, port: int, timeout: float):
    reader = writer = None
    try:
        reader, writer, latency, state, error = await tcp_connect(ip, port, timeout)
        if state != "open":
            return "", "", "", latency, state, error
        probe = PROBES.get(port, b"\r\n")
        writer.write(probe.replace(b"{host}", host.encode("idna", "ignore")))
        await writer.drain()
        data = await asyncio.wait_for(reader.read(4096), timeout=min(timeout, 2.5))
        banner = clean_banner(data.decode("utf-8", "replace"))
        product, version = parse_product_version(banner)
        return banner, product, version, latency, state, ""
    except asyncio.TimeoutError:
        return "", "", "", 0.0, "open", "banner timeout"
    except Exception as exc:
        return "", "", "", 0.0, "open", str(exc)
    finally:
        if writer:
            writer.close()
            try:
                await writer.wait_closed()
            except Exception:
                pass


async def scan_one(host: str, ip: str, port: int, timeout: float, retries: int, semaphore: asyncio.Semaphore, do_tls: bool):
    async with semaphore:
        last = None
        for _ in range(max(1, retries)):
            last = await banner_probe(host, ip, port, timeout)
            if last[4] in {"open", "closed"}:
                break
        banner, product, version, latency, state, error = last
        result = PortResult(port=port, state=state, service=service_name(port), banner=banner,
                            product=product, version=version, latency_ms=latency, error=error)
        if state != "open":
            return result
        if port in HTTP_PORTS:
            use_tls = port in TLS_PORTS
            info = await http_probe(host, ip, port, timeout, https=use_tls)
            if info.get("server"):
                result.product, result.version = parse_product_version(info["server"])
                result.evidence.append(f"Server: {info['server']}")
            if info.get("powered_by"):
                result.evidence.append(f"X-Powered-By: {info['powered_by']}")
            if info.get("status"):
                result.evidence.append(info["status"])
            if info.get("location"):
                result.evidence.append(f"Location: {info['location']}")
            result.banner = clean_banner(info.get("evidence") or banner)
        if do_tls and port in TLS_PORTS:
            tls_version, subject, issuer, expiry, tls_error = await tls_probe(host, ip, port, timeout)
            if tls_version:
                result.tls = True
                result.tls_version = tls_version
                result.certificate_subject = subject
                result.certificate_issuer = issuer
                result.certificate_expiry = expiry
                result.evidence.append(f"TLS: {tls_version}")
            elif tls_error:
                result.evidence.append(f"TLS probe: {tls_error}")
        return result


async def scan(target: str, ports: Iterable[int], concurrency: int, timeout: float, retries: int, rdns: bool, do_tls: bool) -> HostResult:
    hostname, ip = resolve_target(target)
    limiter = asyncio.Semaphore(max(1, min(concurrency, 500)))
    tasks = [asyncio.create_task(scan_one(hostname, ip, p, timeout, retries, limiter, do_tls)) for p in ports]
    results: list[PortResult] = []
    for task in asyncio.as_completed(tasks):
        result = await task
        if result.state == "open":
            results.append(result)
            print(f"OPEN  {result.port:5d}/tcp  {result.service:16s} {result.product} {result.version} {result.banner[:100]}")
    if rdns:
        name = await reverse_dns(ip)
        for result in results:
            result.reverse_dns = name
    results.sort(key=lambda x: x.port)
    counts = Counter(x.state for x in results)
    return HostResult(target=target, ip=ip, hostname=hostname,
                      scanned_at=datetime.now(timezone.utc).isoformat(),
                      os_family_hint=infer_os(results), ports=results,
                      summary=dict(counts))


def render_text(host: HostResult):
    print("\nNmap-inspired scan report")
    print(f"Scanner: Anish Scanner v{VERSION}")
    print(f"Target:  {host.target}")
    print(f"Address: {host.ip}")
    print(f"OS hint: {host.os_family_hint}")
    print("PORT      STATE       SERVICE            PRODUCT/VERSION")
    print("-" * 74)
    for result in host.ports:
        pv = " ".join(x for x in [result.product, result.version] if x)
        print(f"{result.port:<9} {result.state:<11} {result.service:<18} {pv}")
    print(f"\nOpen TCP ports: {len(host.ports)}")


def write_json(path: Path, host: HostResult):
    path.write_text(json.dumps(asdict(host), indent=2), encoding="utf-8")


def write_csv(path: Path, host: HostResult):
    rows = [asdict(x) for x in host.ports]
    if not rows:
        path.write_text("port,state,service,protocol,banner,product,version,latency_ms,tls,tls_version,certificate_subject,certificate_issuer,certificate_expiry,reverse_dns,error,evidence\n", encoding="utf-8")
        return
    fields = list(rows[0].keys())
    with path.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=fields)
        writer.writeheader()
        for row in rows:
            row["evidence"] = " | ".join(row.get("evidence", []))
            writer.writerow(row)


def write_gnmap(path: Path, host: HostResult):
    open_ports = ",".join(f"{x.port}/open/{x.service}" for x in host.ports)
    path.write_text(f"Host: {host.target} ({host.ip})\tPorts: {open_ports}\n", encoding="utf-8")


def build_parser():
    parser = argparse.ArgumentParser(prog="scanner-v15", description="Nmap-inspired authorized TCP scanner")
    parser.add_argument("target", help="Authorized IPv4/hostname target")
    parser.add_argument("-p", "--ports", default=",".join(map(str, TOP_PORTS)), help="ports, comma lists and ranges")
    parser.add_argument("-F", "--fast", action="store_true", help="scan built-in top-port set")
    parser.add_argument("-T", "--timing", type=int, choices=range(6), default=3, metavar="0-5")
    parser.add_argument("--timeout", type=float)
    parser.add_argument("--concurrency", type=int)
    parser.add_argument("--retries", type=int)
    parser.add_argument("--rdns", action="store_true", help="resolve reverse DNS for open ports")
    parser.add_argument("--no-tls", action="store_true", help="skip TLS probes")
    parser.add_argument("-oJ", "--json", type=Path)
    parser.add_argument("-oC", "--csv", type=Path)
    parser.add_argument("-oG", "--gnmap", type=Path)
    return parser


def main():
    args = build_parser().parse_args()
    profile = TIMING[args.timing]
    timeout = args.timeout if args.timeout is not None else profile["timeout"]
    concurrency = args.concurrency if args.concurrency is not None else profile["concurrency"]
    retries = args.retries if args.retries is not None else profile["retries"]
    if timeout <= 0 or concurrency <= 0 or retries <= 0:
        raise SystemExit("timeout, concurrency and retries must be positive")
    ports = parse_ports(",".join(map(str, TOP_PORTS)) if args.fast else args.ports)
    print(f"Anish Scanner v{VERSION} | Nmap-inspired TCP connect mode")
    print(f"Target={args.target} ports={len(ports)} timing=T{args.timing} concurrency={concurrency}")
    print("Authorized targets only; non-destructive probes enabled.")
    host = asyncio.run(scan(args.target, ports, concurrency, timeout, retries, args.rdns, not args.no_tls))
    render_text(host)
    if args.json:
        write_json(args.json, host)
        print(f"JSON written: {args.json}")
    if args.csv:
        write_csv(args.csv, host)
        print(f"CSV written: {args.csv}")
    if args.gnmap:
        write_gnmap(args.gnmap, host)
        print(f"Grepable output written: {args.gnmap}")


if __name__ == "__main__":
    main()
