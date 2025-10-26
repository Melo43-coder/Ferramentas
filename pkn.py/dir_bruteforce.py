# dir_bruteforce.py
# Diretory bruteforce básico. Use wordlist pequena e delays!
# Exemplo: python dir_bruteforce.py --target http://127.0.0.1:8000 --wordlist wordlist.txt

import requests
import argparse
import time
from utils import print_banner, log, safe_sleep, normalize_target


def load_wordlist(path):
    with open(path, 'r', encoding='utf-8') as f:
        return [l.strip() for l in f if l.strip()]


def check_paths(base_url, paths, delay=0.2, timeout=5):
    found = []
    for p in paths:
        url = base_url.rstrip('/') + '/' + p.lstrip('/')
        try:
            r = requests.get(url, timeout=timeout, allow_redirects=False)
            if r.status_code < 400:
                log(f'Found: {url} (status: {r.status_code})')
                found.append((url, r.status_code))
            else:
                # status 4xx/5xx - likely not found or error
                pass
        except Exception as e:
            log(f'Error requesting {url} -> {e}')
        time.sleep(delay)
    return found


if __name__ == '__main__':
    print_banner()
    parser = argparse.ArgumentParser(description='Pinó-kyo directory bruteforce')
    parser.add_argument('--target', required=True, help='Base URL alvo (ex: http://127.0.0.1:8000)')
    parser.add_argument('--wordlist', required=False, default='wordlist.txt', help='Caminho da wordlist')
    parser.add_argument('--delay', type=float, default=0.25, help='Delay entre requests (segundos)')
    args = parser.parse_args()

    base = normalize_target(args.target)
    paths = load_wordlist(args.wordlist)
    safe_sleep(0.1)
    results = check_paths(base, paths, args.delay)
    log(f'Directory brute-force complete. {len(results)} results found.')
