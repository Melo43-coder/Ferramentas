# http_enum.py
# HTTP enumerator - busca headers e faz fingerprinting simples
# Exemplo: python http_enum.py --target http://127.0.0.1:8000

import requests
import argparse
from bs4 import BeautifulSoup
from utils import print_banner, log, safe_sleep, normalize_target


DEFAULT_HEADERS = {'User-Agent': 'Pino-kyo/1.0 (+https://example.local)'}


def fetch_headers(url, timeout=6):
    log(f'Fetching headers for {url}')
    try:
        r = requests.get(url, headers=DEFAULT_HEADERS, timeout=timeout, allow_redirects=True)
        info = {
            'status_code': r.status_code,
            'final_url': r.url,
            'headers': dict(r.headers),
            'title': None,
        }
        try:
            soup = BeautifulSoup(r.text, 'html.parser')
            title = soup.title.string.strip() if soup.title else None
            info['title'] = title
        except Exception:
            info['title'] = None
        return info
    except Exception as e:
        log(f'Error fetching {url} -> {e}')
        return None


if __name__ == '__main__':
    print_banner()
    parser = argparse.ArgumentParser(description='Pinó-kyo HTTP enumerator')
    parser.add_argument('--target', required=True, help='URL alvo (ex: http://127.0.0.1:8000)')
    args = parser.parse_args()

    target = normalize_target(args.target)
    safe_sleep(0.1)
    res = fetch_headers(target)
    if res:
        log(f"Status: {res['status_code']}  Final URL: {res['final_url']}")
        log('Headers:')
        for k, v in res['headers'].items():
            print(f"{k}: {v}")
        if res['title']:
            log(f"Page title: {res['title']}")
