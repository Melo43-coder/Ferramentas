# utils.py
# Funções utilitárias: banner, simple logger, safe sleep, parse URL

import time
import sys
import argparse
from datetime import datetime
from urllib.parse import urlparse

BANNER = r"""
  ____  _                  _    _  _   _  __  __
 |  _ \(_) ___  _ __   ___| | _| || | | |/ _|/ _|
 | |_) | |/ _ \| '_ \ / _ \ |/ / || |_| | |_| |_ 
 |  __/| | (_) | | | |  __/   <|__   _| |  _|  _|
 |_|   |_|\___/|_| |_|\___|_|\_\  |_|   |_| |_|  

   ____  _             _  _  __
  |  _ \| |_   _  __ _| || |/ _|
  | |_) | | | | |/ _` | || | |_ 
  |  __/| | |_| | (_| |__   _|  \
  |_|   |_|\__,_|\__,_|  |_| |_| Pinó-kyo
"""


def print_banner():
    print(BANNER)


def now():
    return datetime.now().strftime('%Y-%m-%d %H:%M:%S')


def log(msg):
    print(f"[{now()}] {msg}")


def safe_sleep(seconds):
    try:
        time.sleep(seconds)
    except KeyboardInterrupt:
        log('Sleep interrupted by user')


def normalize_target(target):
    # If a bare IP or hostname is provided, return as-is.
    # If a URL is provided, ensure scheme exists.
    parsed = urlparse(target)
    if parsed.scheme == '':
        return target
    return target
