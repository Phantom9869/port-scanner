# port_scanner.py
import socket
import sys
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field
from datetime import datetime


@dataclass
class PortResult:
    port:    int
    state:   str        
    service: str = ""
    banner:  str = ""

@dataclass
class ScanResult:
    target:      str
    target_ip:   str
    start_port:  int
    end_port:    int
    started_at:  datetime = field(default_factory=datetime.now)
    finished_at: datetime | None = None
    results:     list[PortResult] = field(default_factory=list)

    @property
    def open_ports(self) -> list[PortResult]:
        return [r for r in self.results if r.state == "open"]

    @property
    def elapsed(self) -> float:
        return (self.finished_at - self.started_at).total_seconds() if self.finished_at else 0.0



def _get_service(port: int) -> str:
    """Return the well-known service name for a port, or '?' if unknown."""
    try:
        return socket.getservbyport(port, "tcp")
    except OSError:
        return "?"

def _grab_banner(ip: str, port: int, timeout: float) -> str:
    """
    Try to grab a one-line banner from an open port.
    First waits for a push banner (SSH, FTP, SMTP), then falls back
    to an HTTP probe if nothing arrives.
    """
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(timeout)
            s.connect((ip, port))
            try:
                raw = s.recv(1024)                          # catches push banners (SSH, FTP…)
            except socket.timeout:
                s.send(b"HEAD / HTTP/1.0\r\n\r\n")        
                raw = s.recv(1024)
            banner = raw.decode(errors="ignore").strip()
            return banner.splitlines()[0][:80] if banner else ""
    except Exception:
        return ""

def _scan_one(ip: str, port: int, timeout: float) -> PortResult:
    """Scan a single TCP port. Uses a per-socket timeout (not the global default)."""
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.settimeout(timeout)                               
        open_ = s.connect_ex((ip, port)) == 0

    if not open_:
        return PortResult(port=port, state="closed")

    return PortResult(
        port=port,
        state="open",
        service=_get_service(port),
        banner=_grab_banner(ip, port, timeout),
    )


_lock = threading.Lock()

def scan_ports(
    target:      str,
    start_port:  int,
    end_port:    int,
    timeout:     float = 1.0,
    max_threads: int   = 200,
    save_to:     str | None = None,
) -> ScanResult:
    """
    Scan TCP ports [start_port, end_port] on target using a thread pool.

    Args:
        target:      Hostname or IP address to scan.
        start_port:  First port in range.
        end_port:    Last port in range (inclusive).
        timeout:     Per-port connection timeout in seconds.
        max_threads: Thread-pool size — controls scan speed.
        save_to:     Optional path to write a plain-text report.

    Returns:
        ScanResult with all open ports, services, and banners.
    """
    # Validate
    if not (1 <= start_port <= end_port <= 65535):
        raise ValueError("Ports must satisfy 1 ≤ start ≤ end ≤ 65535.")

    try:
        target_ip = socket.gethostbyname(target)
    except socket.gaierror as exc:
        raise ValueError(f"Could not resolve '{target}': {exc}") from exc

    total = end_port - start_port + 1
    scan  = ScanResult(target=target, target_ip=target_ip,
                       start_port=start_port, end_port=end_port)

    _print_header(scan, total)

    # Threaded scan
    done = 0
    with ThreadPoolExecutor(max_workers=min(max_threads, total)) as pool:
        futures = {
            pool.submit(_scan_one, target_ip, port, timeout): port
            for port in range(start_port, end_port + 1)
        }
        for future in as_completed(futures):
            result = future.result()
            done  += 1
            with _lock:
                scan.results.append(result)
                if result.state == "open":
                    svc = f"({result.service})" if result.service != "?" else ""
                    print(f"  [OPEN] {result.port:<6} {svc}")
                if done % 50 == 0 or done == total:
                    print(f"  {done}/{total} scanned…", end="\r")

    print()
    scan.finished_at = datetime.now()
    scan.results.sort(key=lambda r: r.port)

    _print_summary(scan)

    if save_to:
        _save_report(scan, save_to)

    return scan

# --- Output ---

def _print_header(scan: ScanResult, total: int) -> None:
    w = 52
    print(f"\n{'─'*w}")
    print(f"  Target  : {scan.target}  ({scan.target_ip})")
    print(f"  Ports   : {scan.start_port}–{scan.end_port}  ({total} ports)")
    print(f"  Started : {scan.started_at.strftime('%Y-%m-%d %H:%M:%S')}")
    print(f"{'─'*w}\n")

def _print_summary(scan: ScanResult) -> None:
    open_ = scan.open_ports
    w = 52
    print(f"\n{'─'*w}")
    print(f"  Finished in {scan.elapsed:.2f}s  |  {len(open_)} open port(s)")
    if open_:
        print(f"\n  {'PORT':<8} {'SERVICE':<12} BANNER")
        print(f"  {'─'*46}")
        for r in open_:
            print(f"  {r.port:<8} {r.service:<12} {r.banner}")
    print(f"{'─'*w}\n")

def _save_report(scan: ScanResult, path: str) -> None:
    with open(path, "w") as f:
        f.write("Port Scan Report\n")
        f.write(f"Target   : {scan.target} ({scan.target_ip})\n")
        f.write(f"Range    : {scan.start_port}–{scan.end_port}\n")
        f.write(f"Started  : {scan.started_at}\n")
        f.write(f"Finished : {scan.finished_at}\n")
        f.write(f"Elapsed  : {scan.elapsed:.2f}s\n\n")
        f.write(f"{'PORT':<8} {'SERVICE':<12} BANNER\n")
        f.write(f"{'─'*46}\n")
        for r in scan.open_ports:
            f.write(f"{r.port:<8} {r.service:<12} {r.banner}\n")
    print(f"  Report saved → '{path}'")

# --- Entry point ---

if __name__ == "__main__":
    try:
        target  = input("Target IP or hostname  : ").strip()
        start   = int(input("Start port             : "))
        end     = int(input("End port               : "))
        timeout = float(input("Timeout per port [1.0] : ") or 1.0)
        threads = int(input("Max threads    [200]   : ") or 200)
        outfile = input("Save report to (blank = skip): ").strip() or None

        scan_ports(target, start, end, timeout=timeout, max_threads=threads, save_to=outfile)

    except ValueError as e:
        print(f"Error: {e}")
        sys.exit(1)
    except KeyboardInterrupt:
        print("\nScan interrupted.")
        sys.exit(0)
