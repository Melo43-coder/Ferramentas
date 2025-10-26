# port_scanner.py
# Port scanner simples - roda em localhost por padrão
# Exemplo: python port_scanner.py --target 127.0.0.1 --start 20 --end 1024

import socket
from concurrent.futures import ThreadPoolExecutor, as_completed
import argparse
from utils import print_banner, log, safe_sleep


def scan_port(host, port, timeout=0.5):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(timeout)
    try:
        s.connect((host, port))
        s.close()
        return port, True
    except Exception:
        return port, False


def run_scan(host, start=1, end=1024, workers=100, timeout=0.5):
    log(f'Starting TCP scan on {host}:{start}-{end} (workers={workers})')
    open_ports = []
    with ThreadPoolExecutor(max_workers=workers) as ex:
        futures = {ex.submit(scan_port, host, p, timeout): p for p in range(start, end + 1)}
        for fut in as_completed(futures):
            port, is_open = fut.result()
            if is_open:
                log(f'Porta aberta: {port}')
                open_ports.append(port)
    log(f'Scan complete. {len(open_ports)} open ports found.')
    return open_ports


if __name__ == '__main__':
    print_banner()
    parser = argparse.ArgumentParser(description='Pinó-kyo TCP Port Scanner')
    parser.add_argument('--target', required=False, default='127.0.0.1', help='IP ou hostname (default 127.0.0.1)')
    parser.add_argument('--start', type=int, default=1, help='Porta inicial')
    parser.add_argument('--end', type=int, default=1024, help='Porta final')
    parser.add_argument('--workers', type=int, default=100, help='Threads simultâneas (padrão 100)')
    args = parser.parse_args()

    safe_sleep(0.1)
    run_scan(args.target, args.start, args.end, args.workers)
