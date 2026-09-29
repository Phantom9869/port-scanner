# port_scanner.py
import errno
import json
import socket
import sys
import threading
import ipaddress
import argparse
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from pathlib import Path

# ── Constants ─────────────────────────────────────────────────────────

DEFAULT_TIMEOUT = 1.0
DEFAULT_THREADS = 300
THREADS_CAP     = 500

# ── Port profiles ─────────────────────────────────────────────────────

PROFILES: dict[str, list[int]] = {
    "top20": [21, 22, 23, 25, 53, 80, 110, 111, 135, 139,
              143, 443, 445, 993, 995, 1723, 3306, 3389, 5900, 8080],
    "top100": sorted({
        21, 22, 23, 25, 53, 80, 88, 110, 111, 119, 123, 135, 139, 143,
        161, 194, 389, 443, 445, 465, 514, 515, 587, 631, 636, 873,
        993, 995, 1080, 1194, 1433, 1521, 1723, 2049, 2082, 2083,
        2086, 2087, 2095, 2096, 3306, 3389, 4444, 5000, 5432, 5900,
        6379, 6667, 7001, 7070, 8000, 8008, 8080, 8443, 8888, 9090,
        9200, 9300, 10000, 27017,
    }),
    "web":  [80, 443, 8000, 8008, 8080, 8443, 8888, 9090, 9443],
    "db":   [1433, 1521, 3306, 5432, 6379, 9200, 27017, 28015],
    "mail": [25, 110, 143, 465, 587, 993, 995],
}

# ── Risk hints ────────────────────────────────────────────────────────

RISK_HINTS: dict[int, str] = {
    21:    "FTP — cleartext credentials; check for anonymous login",
    22:    "SSH — ensure key-auth only, password auth disabled",
    23:    "Telnet — cleartext protocol; replace with SSH",
    25:    "SMTP — check for open relay misconfiguration",
    53:    "DNS — test for zone transfer (AXFR) exposure",
    80:    "HTTP — no encryption; consider redirecting to HTTPS",
    110:   "POP3 — cleartext; prefer POP3S (port 995)",
    111:   "RPCBind — commonly exploited for NFS attacks",
    135:   "RPC/DCOM — high-value Windows attack surface",
    139:   "NetBIOS — legacy SMB; disable if unused",
    143:   "IMAP — cleartext; prefer IMAPS (port 993)",
    161:   "SNMP — default community strings often unchanged",
    445:   "SMB — patch for EternalBlue (MS17-010)",
    1433:  "MSSQL — database port; should not be internet-facing",
    1521:  "Oracle DB — should not be internet-facing",
    3306:  "MySQL — should not be internet-facing",
    3389:  "RDP — common brute-force target; restrict to VPN",
    4444:  "⚠  Common Metasploit/reverse shell default — investigate",
    5432:  "PostgreSQL — should not be internet-facing",
    5900:  "VNC — ensure strong authentication is configured",
    6379:  "Redis — often runs without authentication by default",
    8080:  "HTTP alt — may be proxy, dev server, or admin panel",
    9200:  "Elasticsearch — often unauthenticated by default",
    27017: "MongoDB — often unauthenticated by default",
}

# ── Enums ─────────────────────────────────────────────────────────────

class PortState(Enum):
    OPEN     = "open"
    CLOSED   = "closed"    # TCP RST received — host actively refused
    FILTERED = "filtered"  # Timeout — firewall likely dropped the packet

# ── Data ──────────────────────────────────────────────────────────────

@dataclass
class PortResult:
    port:    int
    state:   PortState
    service: str = ""
    banner:  str = ""

    @property
    def risk_hint(self) -> str:
        return RISK_HINTS.get(self.port, "")

    def to_dict(self) -> dict:
        return {
            "port": self.port, "state": self.state.value,
            "service": self.service, "banner": self.banner,
            "risk_hint": self.risk_hint,
        }

@dataclass
class ScanResult:
    target:      str
    target_ip:   str
    ports:       list[int]        # actual list scanned — may be non-contiguous
    started_at:  datetime = field(default_factory=datetime.now)
    finished_at: datetime | None = None
    results:     list[PortResult] = field(default_factory=list)

    @property
    def open_ports(self)     -> list[PortResult]:
        return [r for r in self.results if r.state == PortState.OPEN]
    @property
    def closed_ports(self)   -> list[PortResult]:
        return [r for r in self.results if r.state == PortState.CLOSED]
    @property
    def filtered_ports(self) -> list[PortResult]:
        return [r for r in self.results if r.state == PortState.FILTERED]

    @property
    def elapsed(self) -> float:
        return (self.finished_at - self.started_at).total_seconds() if self.finished_at else 0.0

    def to_dict(self) -> dict:
        return {
            "target": self.target, "target_ip": self.target_ip,
            "ports_scanned": len(self.ports),
            "started_at":    self.started_at.isoformat(),
            "finished_at":   self.finished_at.isoformat() if self.finished_at else None,
            "elapsed_s":     round(self.elapsed, 2),
            "summary": {
                "open":     len(self.open_ports),
                "closed":   len(self.closed_ports),
                "filtered": len(self.filtered_ports),
            },
            "open_ports": [r.to_dict() for r in self.open_ports],
        }

    def save(self, path: str) -> None:
        """Infer format from extension — .json or plain text for everything else."""
        p = Path(path)
        content = (json.dumps(self.to_dict(), indent=2)
                   if p.suffix.lower() == ".json"
                   else self._as_text())
        p.write_text(content)
        print(f"  Report saved → '{path}'")

    def _as_text(self) -> str:
        lines = [
            "Port Scan Report",
            f"Target   : {self.target} ({self.target_ip})",
            f"Elapsed  : {self.elapsed:.2f}s",
            f"Open={len(self.open_ports)}  Closed={len(self.closed_ports)}  Filtered={len(self.filtered_ports)}",
            "", f"{'PORT':<8} {'SERVICE':<14} BANNER", "─" * 60,
        ]
        for r in self.open_ports:
            lines.append(f"{r.port:<8} {r.service:<14} {r.banner}")
            if r.risk_hint:
                lines.append(f"{'':8} ⚠  {r.risk_hint}")
        return "\n".join(lines)

# ── Scanning helpers ──────────────────────────────────────────────────

def _get_service(port: int) -> str:
    try:
        return socket.getservbyport(port, "tcp")
    except OSError:
        return "?"

def _grab_banner(ip: str, port: int, timeout: float) -> str:
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(timeout)
            s.connect((ip, port))
            try:
                raw = s.recv(1024)
            except socket.timeout:
                s.send(b"HEAD / HTTP/1.0\r\n\r\n")
                raw = s.recv(1024)
            banner = raw.decode(errors="ignore").strip()
            return banner.splitlines()[0][:80] if banner else ""
    except Exception:
        return ""

_CONN_REFUSED = {errno.ECONNREFUSED, 10061}  # 10061 = WSAECONNREFUSED on Windows

def _scan_one(ip: str, port: int, timeout: float) -> PortResult:
    """Scan one TCP port. Distinguishes open / closed (RST) / filtered (timeout)."""
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.settimeout(timeout)
        err = s.connect_ex((ip, port))

    if err == 0:
        return PortResult(
            port=port, state=PortState.OPEN,
            service=_get_service(port),
            banner=_grab_banner(ip, port, timeout),
        )
    state = PortState.CLOSED if err in _CONN_REFUSED else PortState.FILTERED
    return PortResult(port=port, state=state)

# ── Resolution helpers ────────────────────────────────────────────────

def _resolve_ports(
    profile: str | None       = None,
    start:   int | None       = None,
    end:     int | None       = None,
    ports:   list[int] | None = None,
) -> list[int]:
    if profile:
        if profile not in PROFILES:
            raise ValueError(f"Unknown profile '{profile}'. Valid: {list(PROFILES)}")
        return list(PROFILES[profile])
    if ports:
        for p in ports:
            if not (1 <= p <= 65535):
                raise ValueError(f"Port {p} out of range 1–65535.")
        return sorted(set(ports))
    if start is not None and end is not None:
        if not (1 <= start <= end <= 65535):
            raise ValueError("Ports must satisfy 1 ≤ start ≤ end ≤ 65535.")
        return list(range(start, end + 1))
    raise ValueError("Specify --profile, --ports, or --range.")

def _resolve_targets(target: str) -> list[tuple[str, str]]:
    """Accept hostname, single IP, or CIDR. Returns [(display_name, ip), …]."""
    try:
        net   = ipaddress.ip_network(target, strict=False)
        hosts = list(net.hosts()) or [net.network_address]
        return [(str(h), str(h)) for h in hosts]
    except ValueError:
        pass
    try:
        ip = socket.gethostbyname(target)
        return [(target, ip)]
    except socket.gaierror as exc:
        raise ValueError(f"Could not resolve '{target}': {exc}") from exc

# ── Core ──────────────────────────────────────────────────────────────

_lock = threading.Lock()

def _scan_host(
    display:       str,
    ip:            str,
    port_list:     list[int],
    timeout:       float,
    max_threads:   int,
    show_filtered: bool = False,
) -> ScanResult:
    scan  = ScanResult(target=display, target_ip=ip, ports=port_list)
    total = len(port_list)
    _print_header(scan, total)

    done = 0
    with ThreadPoolExecutor(max_workers=min(max_threads, total, THREADS_CAP)) as pool:
        futures = {pool.submit(_scan_one, ip, p, timeout): p for p in port_list}
        for future in as_completed(futures):
            result = future.result()
            done  += 1
            with _lock:
                scan.results.append(result)
                if result.state == PortState.OPEN:
                    svc = f"({result.service})" if result.service != "?" else ""
                    print(f"  [OPEN]     {result.port:<6} {svc}")
                elif result.state == PortState.FILTERED and show_filtered:
                    print(f"  [FILTERED] {result.port}")
                pct = int(done / total * 100)
                print(f"  {done}/{total}  ({pct}%)…", end="\r", flush=True)

    print()
    scan.finished_at = datetime.now()
    scan.results.sort(key=lambda r: r.port)
    _print_summary(scan)
    return scan

def scan_network(
    cidr:        str,
    port_list:   list[int],
    timeout:     float = DEFAULT_TIMEOUT,
    max_threads: int   = DEFAULT_THREADS,
) -> list[ScanResult]:
    """
    Scan every host in a CIDR block.
    Hosts are scanned sequentially; ports within each host are threaded.
    Returns only results with at least one open port.
    """
    targets = _resolve_targets(cidr)
    w = 58
    print(f"\n{'─'*w}")
    print(f"  Network Scan : {cidr}")
    print(f"  Hosts        : {len(targets)}")
    print(f"  Ports each   : {len(port_list)}")
    print(f"{'─'*w}\n")

    live: list[ScanResult] = []
    for i, (display, ip) in enumerate(targets, 1):
        print(f"  [{i}/{len(targets)}] {ip}")
        try:
            r = _scan_host(display, ip, port_list, timeout, max_threads)
            if r.open_ports:
                live.append(r)
        except Exception as e:
            print(f"  [SKIP] {ip}: {e}")

    print(f"\n{'─'*w}")
    print(f"  Network scan complete — {len(live)}/{len(targets)} hosts with open ports")
    for r in live:
        ports_str = ", ".join(str(p.port) for p in r.open_ports)
        print(f"    {r.target_ip:<18} open: {ports_str}")
    print(f"{'─'*w}\n")
    return live

# ── Display ───────────────────────────────────────────────────────────

def _print_header(scan: ScanResult, total: int) -> None:
    w = 58
    print(f"\n{'─'*w}")
    print(f"  Target  : {scan.target}  ({scan.target_ip})")
    print(f"  Ports   : {total} port(s)")
    print(f"  Started : {scan.started_at.strftime('%Y-%m-%d %H:%M:%S')}")
    print(f"{'─'*w}\n")

def _print_summary(scan: ScanResult) -> None:
    w = 58
    print(f"\n{'─'*w}")
    print(f"  Done in {scan.elapsed:.2f}s")
    print(f"  open={len(scan.open_ports)}  "
          f"closed={len(scan.closed_ports)}  "
          f"filtered={len(scan.filtered_ports)}")

    if scan.open_ports:
        print(f"\n  {'PORT':<8} {'SERVICE':<14} BANNER")
        print(f"  {'─'*50}")
        for r in scan.open_ports:
            print(f"  {r.port:<8} {r.service:<14} {r.banner}")
            if r.risk_hint:
                print(f"  {'':8} ⚠  {r.risk_hint}")
    print(f"{'─'*w}\n")

# ── CLI ───────────────────────────────────────────────────────────────

if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        prog="scan",
        description="TCP port scanner — threaded, with banner grabbing, "
                    "risk hints, profiles, and CIDR support",
    )
    parser.add_argument("target",
                        help="IP, hostname, or CIDR block (e.g. 192.168.1.0/24)")

    pg = parser.add_mutually_exclusive_group(required=True)
    pg.add_argument("--profile", choices=list(PROFILES),
                    help=f"Named port set: {list(PROFILES)}")
    pg.add_argument("--range",  nargs=2, type=int, metavar=("START", "END"),
                    help="Port range  (e.g. --range 1 1024)")
    pg.add_argument("--ports",  nargs="+", type=int, metavar="PORT",
                    help="Explicit ports  (e.g. --ports 22 80 443)")

    parser.add_argument("-t", "--timeout",      type=float, default=DEFAULT_TIMEOUT,
                        help=f"Per-port timeout in seconds (default {DEFAULT_TIMEOUT})")
    parser.add_argument("-T", "--threads",      type=int,   default=DEFAULT_THREADS,
                        help=f"Thread pool size (default {DEFAULT_THREADS})")
    parser.add_argument("--show-filtered",      action="store_true",
                        help="Print filtered (timed-out) ports during scan")
    parser.add_argument("-o", "--output",       default=None,
                        help="Save report; format inferred from extension (.json or .txt)")

    args = parser.parse_args()
    try:
        port_list = _resolve_ports(
            args.profile,
            *(args.range or (None, None)),
            args.ports,
        )
        targets = _resolve_targets(args.target)

        if len(targets) > 1:
            results = scan_network(args.target, port_list, args.timeout, args.threads)
            if args.output and results:
                results[0].save(args.output)
        else:
            display, ip = targets[0]
            result = _scan_host(display, ip, port_list,
                                args.timeout, args.threads, args.show_filtered)
            if args.output:
                result.save(args.output)
    except ValueError as e:
        print(f"\n  Error: {e}", file=sys.stderr)
        sys.exit(1)
    except KeyboardInterrupt:
        print("\n  Scan interrupted.")
        sys.exit(0)
