#!/usr/bin/env python3
"""Nmap-style authorized network scanner for the Scanner project.

Features: TCP connect scanning, configurable port ranges, service/banner probes,
reverse DNS, JSON/CSV output, IPv4 validation, concurrency limits and timeouts.
This implementation intentionally uses connect scans rather than stealth/raw-packet
techniques so it remains portable and explicit about network access.
"""

from __future__ import annotations

import argparse
import asyncio
import csv
import ipaddress
import json
import socket
import ssl
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Iterable

DEFAULT_PORTS = (
    "20-23,25,53,67-69,80,88,110,111,123,135,137-139,143,161,389,443,445,465,514,587,631,636,873,993,995,1025,1433,1521,1723,1883,2049,2375,2379-2380,3000,3128,3306,3389,5000,5432,5601,5672,5900,5985-5986,6379,6443,7001-7002,8000,8008-8009,8080,8081,8088,8443,8888,9000,9090,9200,11211,15672,27017"
)

SERVICE_PROBES = {
    21: b"\r\n",
    22: b"\r\n",
    25: b"EHLO scanner.local\r\n",
    80: b"GET / HTTP/1.0\r\nHost: {host}\r\nUser-Agent: Scanner-v14\r\nConnection: close\r\n\r\n",
    110: b"CAPA\r\n",
    143: b"a001 CAPABILITY\r\n",
    443: b"GET / HTTP/1.0\r\nHost: {host}\r\nUser-Agent: Scanner-v14\r\nConnection: close\r\n\r\n",
    587: b"EHLO scanner.local\r\n",
    993: b"\r\n",
    995: b"\r\n",
    3306: b"\x0a",
    6379: b"*1\r\n$4\r\nPING\r\n",
}


@dataclass(slots=True)
class ScanResult:
    host: str
    ip: str
    port: int
    state: str
    service: str = "unknown"
    banner: str = ""
    reverse_dns: str = ""
    latency_ms: float = 0.0
    error: str = ""


def parse_ports(spec: str) -> list[int]:
    ports: set[int] = set()
    for token in spec.split(","):
        token = token.strip()
        if not token:
            continue
        if "-" in token:
            a, b = token.split("-", 1)
            start, end = int(a), int(b)
            if start > end:
                start, end = end, start
            ports.update(range(start, end + 1))
        else:
            ports.add(int(token))
    valid = sorted(p for p in ports if 1 <= p <= 65535)
    if not valid:
        raise ValueError("No valid ports supplied")
    return valid


def resolve_target(target: str) -> tuple[str, str]:
    value = target.strip()
    try:
        ip = str(ipaddress.ip_address(value))
        return value, ip
    except ValueError:
        pass
    host = value.split(":", 1)[0]
    infos = socket.getaddrinfo(host, None, family=socket.AF_INET, type=socket.SOCK_STREAM)
    if not infos:
        raise ValueError(f"Could not resolve target: {target}")
    return host, infos[0][4][0]


def service_name(port: int) -> str:
    try:
        return socket.getservbyport(port, "tcp")
    except OSError:
        return {
            80: "http", 443: "https", 8080: "http-proxy", 8443: "https-alt",
            3306: "mysql", 5432: "postgresql", 6379: "redis", 27017: "mongodb",
            3389: "rdp", 22: "ssh", 21: "ftp", 25: "smtp", 53: "domain",
        }.get(port, "unknown")


async def reverse_dns(ip: str) -> str:
    loop = asyncio.get_running_loop()
    try:
        result = await loop.run_in_executor(None, socket.gethostbyaddr, ip)
        return result[0]
    except OSError:
        return ""


async def probe_banner(reader: asyncio.StreamReader, writer: asyncio.StreamWriter, host: str, port: int, timeout: float) -> str:
    payload = SERVICE_PROBES.get(port)
    if payload:
        payload = payload.replace(b"{host}", host.encode("idna", "ignore"))
        writer.write(payload)
        await writer.drain()
    try:
        data = await asyncio.wait_for(reader.read(2048), timeout=min(timeout, 2.5))
        text = data.decode("utf-8", errors="replace").replace("\x00", " ")
        return " ".join(text.split())[:500]
    except (asyncio.TimeoutError, ConnectionError):
        return ""


async def scan_port(target: str, ip: str, port: int, timeout: float, semaphore: asyncio.Semaphore) -> ScanResult:
    async with semaphore:
        started = asyncio.get_running_loop().time()
        writer = None
        try:
            reader, writer = await asyncio.wait_for(asyncio.open_connection(ip, port), timeout=timeout)
            banner = await probe_banner(reader, writer, target, port, timeout)
            latency = (asyncio.get_running_loop().time() - started) * 1000
            return ScanResult(target, ip, port, "open", service_name(port), banner, "", latency)
        except asyncio.TimeoutError:
            return ScanResult(target, ip, port, "filtered/timeout", service_name(port), latency_ms=(asyncio.get_running_loop().time() - started) * 1000)
        except ConnectionRefusedError:
            return ScanResult(target, ip, port, "closed", service_name(port), latency_ms=(asyncio.get_running_loop().time() - started) * 1000)
        except OSError as exc:
            return ScanResult(target, ip, port, "error", service_name(port), error=str(exc), latency_ms=(asyncio.get_running_loop().time() - started) * 1000)
        finally:
            if writer is not None:
                writer.close()
                try:
                    await writer.wait_closed()
                except Exception:
                    pass


async def scan(target: str, ports: Iterable[int], concurrency: int, timeout: float, rdns: bool) -> list[ScanResult]:
    host, ip = resolve_target(target)
    limiter = asyncio.Semaphore(max(1, min(concurrency, 500)))
    tasks = [scan_port(host, ip, port, timeout, limiter) for port in ports]
    results: list[ScanResult] = []
    for task in asyncio.as_completed(tasks):
        result = await task
        if result.state == "open":
            if rdns:
                result.reverse_dns = await reverse_dns(result.ip)
            results.append(result)
            print(f"OPEN  {result.port:5d}/tcp  {result.service:16s} {result.banner}")
    return sorted(results, key=lambda r: r.port)


def write_json(path: Path, target: str, results: list[ScanResult]) -> None:
    payload = {
        "scanner": "Anish Scanner Nmap-style TCP",
        "version": "14.0.0",
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "target": target,
        "open_ports": [asdict(x) for x in results],
    }
    path.write_text(json.dumps(payload, indent=2), encoding="utf-8")


def write_csv(path: Path, results: list[ScanResult]) -> None:
    rows = [asdict(x) for x in results]
    with path.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=list(ScanResult.__annotations__.keys()))
        writer.writeheader()
        writer.writerows(rows)


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(description="Nmap-style authorized TCP connect scanner")
    p.add_argument("target", help="IPv4 address or hostname you are authorized to scan")
    p.add_argument("-p", "--ports", default=DEFAULT_PORTS, help="Ports, ranges and comma lists")
    p.add_argument("-T", "--timing", type=int, choices=range(0, 6), default=3, metavar="0-5", help="Timing profile")
    p.add_argument("--timeout", type=float, default=None, help="Per-connection timeout in seconds")
    p.add_argument("--concurrency", type=int, default=None, help="Maximum simultaneous connections")
    p.add_argument("-r", "--resolve", action="store_true", help="Resolve reverse DNS for open hosts")
    p.add_argument("-oJ", "--json", type=Path, help="Write JSON results")
    p.add_argument("-oC", "--csv", type=Path, help="Write CSV results")
    return p


def main() -> None:
    args = build_parser().parse_args()
    timing = {
        0: (5.0, 5), 1: (3.0, 10), 2: (2.0, 25), 3: (1.25, 60), 4: (0.75, 120), 5: (0.5, 250)
    }[args.timing]
    timeout = args.timeout if args.timeout is not None else timing[0]
    concurrency = args.concurrency if args.concurrency is not None else timing[1]
    ports = parse_ports(args.ports)
    print(f"Starting Scanner v14.0.0 | target={args.target} | ports={len(ports)} | concurrency={concurrency}")
    results = asyncio.run(scan(args.target, ports, concurrency, timeout, args.resolve))
    print(f"\nScan complete: {len(results)} open TCP ports")
    if args.json:
        write_json(args.json, args.target, results)
        print(f"JSON: {args.json}")
    if args.csv:
        write_csv(args.csv, results)
        print(f"CSV: {args.csv}")


if __name__ == "__main__":
    main()
