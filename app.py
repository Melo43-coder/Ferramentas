# -*- coding: utf-8 -*-
import socket
from datetime import datetime
import sys
import threading

# -------------------- CORES --------------------
RED = '\033[91m'
GREEN = '\033[92m'
YELLOW = '\033[93m'
BLUE = '\033[94m'
CYAN = '\033[96m'
RESET = '\033[0m'

# -------------------- BANNER ASCII (usar fr-string para preservar backslashes) --------------------
banner = fr"""
{CYAN}
   ___  _     _                 _    _    _           _             
  / _ \| |__ (_) __ _ _ __ ___ | | _| | _(_) __ _  __| | ___  _ __  
 | | | | '_ \| |/ _` | '_ ` _ \| |/ / |/ / |/ _` |/ _` |/ _ \| '_ \ 
 | |_| | | | | | (_| | | | | | |   <|   <| | (_| | (_| | (_) | | | |
  \___/|_| |_|_|\__, |_| |_| |_|_|\_\_|\_\_|\__,_|\__,_|\___/|_| |_|
                 |___/                                               
          {YELLOW}PORT SCANNER - Achados Únicos{RESET}
"""

print(banner)

# -------------------- FUNÇÃO DE SCAN --------------------
def scan_port(host, port):
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(0.5)
        result = sock.connect_ex((host, port))
        if result == 0:
            print(f"{GREEN}[+] Porta {port} aberta{RESET}")
        else:
            # Opcional: comentar a linha abaixo se quiser menos ruído
            print(f"{RED}[-] Porta {port} fechada{RESET}")
        sock.close()
    except KeyboardInterrupt:
        print(f"\n{RED}[!] Scan interrompido pelo usuário{RESET}")
        sys.exit()
    except socket.gaierror:
        print(f"{RED}[!] Host não encontrado{RESET}")
        sys.exit()
    except socket.error:
        print(f"{RED}[!] Conexão falhou{RESET}")
        sys.exit()

# -------------------- MAIN --------------------
def main():
    host = input(f"{BLUE}Digite o host ou IP: {RESET}")
    ports_input = input(f"{BLUE}Digite as portas (ex: 20-1024 ou 80,443,8080): {RESET}")

    # Determinar quais portas serão escaneadas
    ports = []
    if "-" in ports_input:
        start_port, end_port = map(int, ports_input.split("-"))
        ports = list(range(start_port, end_port + 1))
    else:
        ports = [int(p.strip()) for p in ports_input.split(",")]

    print(f"{YELLOW}Escaneando host {host}...{RESET}")
    start_time = datetime.now()

    threads = []
    for port in ports:
        t = threading.Thread(target=scan_port, args=(host, port))
        threads.append(t)
        t.start()

    for t in threads:
        t.join()

    end_time = datetime.now()
    total_time = end_time - start_time
    print(f"\n{CYAN}Scan finalizado em: {total_time}{RESET}")

if __name__ == "__main__":
    main()
