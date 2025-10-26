#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
HADES - Scanner simples de SQLi/XSS
Uso:
  python hades.py http://alvo/path.php param --sqli
  python hades.py http://alvo/path.php param --xss
  python hades.py http://alvo/path.php param --sqli --xss
"""

import argparse
from modules import scanner
import sys

BANNER = r"""
  _    _   _    ____  _____  _____ 
 | |  | | / \  |  _ \| ____|| ____|
 | |  | |/ _ \ | | | |  _|  |  _|  
 | |__| / ___ \| |_| | |___ | |___ 
  \____/_/   \_\____/|_____||_____|

   ██████╗  █████╗ ██████╗ ███████╗
  ██╔════╝ ██╔══██╗██╔══██╗██╔════╝
  ██║  ███╗███████║██████╔╝█████╗  
  ██║   ██║██╔══██║██╔══██╗██╔══╝  
  ╚██████╔╝██║  ██║██║  ██║███████╗
   ╚═════╝ ╚═╝  ╚═╝╚═╝  ╚═╝╚══════╝

                 .-.
                (o o)
                | O \
                 \   \
                  `~~~'
            H A D E S   —   P E N T E S T

    Scanner simples de SQLi & XSS — use com responsabilidade.
"""

def print_banner():
    print(BANNER)
    print("-> Modo de uso: --sqli para SQL Injection, --xss para Cross-Site Scripting")
    print("-> Lembre-se: execute somente em ambientes autorizados!\n")

def main():
    print_banner()
    parser = argparse.ArgumentParser(prog="HADES", description="HADES - Scanner simples de SQLi/XSS")
    parser.add_argument("url", help="URL alvo (ex: http://exemplo.com/page.php)")
    parser.add_argument("param", help="Parâmetro vulnerável (ex: id)")
    parser.add_argument("--sqli", action="store_true", help="Executar scan SQLi")
    parser.add_argument("--xss", action="store_true", help="Executar scan XSS")
    parser.add_argument("--timeout", type=int, default=10, help="Timeout em segundos para requests (padrão 10s)")
    parser.add_argument("--threads", type=int, default=1, help="Threads para execução (futuro)")
    args = parser.parse_args()

    if not args.sqli and not args.xss:
        print("[!] Nenhum scan selecionado. Use --sqli ou --xss")
        sys.exit(1)

    # passa o timeout via variável global (se quiser propagar para modules)
    # scanner.TEAM_OPTIONS = {...}  # deixei como comentário pra você adaptar

    if args.sqli:
        scanner.sqli_scan(args.url, args.param)
    if args.xss:
        scanner.xss_scan(args.url, args.param)

if __name__ == "__main__":
    main()
