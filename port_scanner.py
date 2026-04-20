# port_scanner.py
import socket
import sys
from datetime import datetime

def scan_ports(target, start_port, end_port):
    print(f"\n{'='*40}")
    print(f"Scanning Target: {target}")
    print(f"Scanning started at: {datetime.now()}")
    print(f"{'='*40}\n")

    try:
        target_ip = socket.gethostbyname(target)
    except socket.gaierror:
        print("Hostname could not be resolved.")
        sys.exit()

    open_ports = []

    for port in range(start_port, end_port + 1):
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        socket.setdefaulttimeout(1)
        result = s.connect_ex((target_ip, port))
        if result == 0:
            print(f"[OPEN] Port {port}")
            open_ports.append(port)
        s.close()

    print(f"\nScan complete. {len(open_ports)} open port(s) found.")

if __name__ == "__main__":
    target = input("Enter target IP or hostname: ")
    start = int(input("Enter start port: "))
    end = int(input("Enter end port: "))
    scan_ports(target, start, end)
