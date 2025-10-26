#!/usr/bin/env python3
"""
pino.py - Entrypoint CLI for Pinó-kyo (canivete)

Use como:
  python pino.py port --target 127.0.0.1 --start 1 --end 1024
  python pino.py http --target http://127.0.0.1:8000
  python pino.py dir --target http://127.0.0.1:8000 --wordlist wordlist.txt

Se executado sem argumentos, abre um menu interativo.
"""
import argparse
import sys
import time
from utils import print_banner, log, safe_sleep

# tentamos importar funções dos módulos existentes
try:
    from port_scanner import run_scan
except Exception:
    run_scan = None

try:
    from http_enum import fetch_headers
except Exception:
    fetch_headers = None

try:
    from dir_bruteforce import check_paths, load_wordlist
except Exception:
    check_paths = None
    load_wordlist = None


def cli_port(args):
    if run_scan is None:
        log('Módulo port_scanner não encontrado ou falha ao importar')
        return
    run_scan(args.target, args.start, args.end, args.workers, timeout=0.5)


def cli_http(args):
    if fetch_headers is None:
        log('Módulo http_enum não encontrado ou falha ao importar')
        return
    res = fetch_headers(args.target)
    if res:
        log(f"Status: {res['status_code']}  Final URL: {res['final_url']}")
        log('Headers:')
        for k, v in res['headers'].items():
            print(f"{k}: {v}")
        if res['title']:
            log(f"Page title: {res['title']}")


def cli_dir(args):
    if check_paths is None or load_wordlist is None:
        log('Módulo dir_bruteforce não encontrado ou falha ao importar')
        return
    paths = load_wordlist(args.wordlist)
    results = check_paths(args.target, paths, delay=args.delay)
    log(f'Directory brute-force complete. {len(results)} results found.')


def interactive_menu():
    print_banner()
    print('Pinó-kyo - Menu (selecione a ferramenta)')
    options = ['Port scanner', 'HTTP enumerator', 'Directory brute-force', 'Sair']
    for i, o in enumerate(options, 1):
        print(f' {i}) {o}')
    choice = input('\nEscolha (número): ').strip()
    if choice == '1':
        target = input('Target (ex: 127.0.0.1): ').strip() or '127.0.0.1'
        start = int(input('Start port (default 1): ').strip() or '1')
        end = int(input('End port (default 1024): ').strip() or '1024')
        workers = int(input('Threads (default 100): ').strip() or '100')
        cli_port(argparse.Namespace(target=target, start=start, end=end, workers=workers))
    elif choice == '2':
        target = input('Target URL (ex: http://127.0.0.1:8000): ').strip()
        cli_http(argparse.Namespace(target=target))
    elif choice == '3':
        target = input('Base URL (ex: http://127.0.0.1:8000): ').strip()
        wordlist = input('Wordlist path (default wordlist.txt): ').strip() or 'wordlist.txt'
        delay = float(input('Delay entre requests (segundos) (default 0.25): ').strip() or '0.25')
        cli_dir(argparse.Namespace(target=target, wordlist=wordlist, delay=delay))
    else:
        print('Saindo...')


def main():
    print_banner()
    parser = argparse.ArgumentParser(prog='pino', description='Pinó-kyo - Swiss-army CLI for pentest tools')
    sub = parser.add_subparsers(dest='cmd')

    p_port = sub.add_parser('port', help='TCP port scanner')
    p_port.add_argument('--target', required=False, default='127.0.0.1')
    p_port.add_argument('--start', type=int, default=1)
    p_port.add_argument('--end', type=int, default=1024)
    p_port.add_argument('--workers', type=int, default=100)

    p_http = sub.add_parser('http', help='HTTP enumerator (headers + title)')
    p_http.add_argument('--target', required=True)

    p_dir = sub.add_parser('dir', help='Directory brute-force')
    p_dir.add_argument('--target', required=True)
    p_dir.add_argument('--wordlist', default='wordlist.txt')
    p_dir.add_argument('--delay', type=float, default=0.25)

    args = parser.parse_args()

    if not args.cmd:
        # interactive
        try:
            interactive_menu()
        except KeyboardInterrupt:
            print('\nInterrupted by user')
        return

    if args.cmd == 'port':
        cli_port(args)
    elif args.cmd == 'http':
        cli_http(args)
    elif args.cmd == 'dir':
        cli_dir(args)
    else:
        parser.print_help()


if __name__ == '__main__':
    main()
