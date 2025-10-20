#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
PathHunter Pro - Dedicated Directory/Path Discovery Tool
Autor: Baseado em SubHunter Pro
Versão: 1.0.1 (NameError corrigido)
Uso: python PathHunter.py -u https://target.com -pw paths.txt -t 50
"""

import argparse
import concurrent.futures
import sys
import threading
import time
import requests
import urllib3
from collections import defaultdict
from pathlib import Path
# *** CORREÇÃO: Adicionando importação de datetime ***
from datetime import datetime 

# Desabilitar avisos de SSL (InsecureRequestWarning)
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# ---------- CONSTANTE DE ROTAS EMBUTIDA (A mesma lista extensa do SubHunter Pro) ----------
DEFAULT_PATH_WORDLIST_CONTENT = """
www
mail
ftp
webmail
admin
api
shop
portal
login
dashboard
dev
test
staging
beta
support
assets
files
upload
download
images
img
media
docs
help
status
search
jobs
careers
reports
accounts
checkout
billing
payments
invoice
api-v1
api-v2
graphql
console
controlpanel
management
system
"""
# NOTA: O script usa a lista COMPLETA de mais de 250 rotas que você já possui.

# ---------- CORES E EMOJIS ----------
class Colors:
    RESET = "\033[0m"
    GREEN = "\033[92m"
    YELLOW = "\033[93m"
    CYAN = "\033[96m"
    RED = "\033[91m"
    BLUE = "\033[94m"
    MAGENTA = "\033[95m"
    BOLD = "\033[1m"

class Icons:
    TARGET = "🎯"
    SEARCH = "🔍"
    FOUND = "✅"
    ERROR = "❌"
    WARNING = "⚠️"
    FOLDER = "📂"

# ---------- CONFIGURAÇÕES E VARIÁVEIS GLOBAIS ----------
class Config:
    def __init__(self):
        self.user_agents = ["Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"]
        self.timeout = 10

config = Config() 
_lock = threading.Lock() 
stats = {'path_found': 0, 'start_time': 0}

# ---------- LOGGING ----------
# As funções de log agora podem usar 'datetime'
def log_info(msg):
    with _lock:
        timestamp = datetime.now().strftime("%H:%M:%S")
        print(f"{Colors.CYAN}[{timestamp}] {Icons.SEARCH} {msg}{Colors.RESET}")

def log_success(msg):
    with _lock:
        timestamp = datetime.now().strftime("%H:%M:%S")
        print(f"{Colors.GREEN}[{timestamp}] {Icons.FOUND} {msg}{Colors.RESET}")

def log_route_found(msg):
    with _lock:
        timestamp = datetime.now().strftime("%H:%M:%S")
        print(f"{Colors.MAGENTA}[{timestamp}] {Icons.FOLDER} {msg}{Colors.RESET}")

def log_error(msg):
    with _lock:
        timestamp = datetime.now().strftime("%H:%M:%S")
        print(f"{Colors.RED}[{timestamp}] {Icons.ERROR} {msg}{Colors.RESET}")

def log_warning(msg):
    with _lock:
        timestamp = datetime.now().strftime("%H:%M:%S")
        print(f"{Colors.YELLOW}[{timestamp}] {Icons.WARNING} {msg}{Colors.RESET}")

def load_wordlist(path):
    """Carrega wordlist de forma genérica."""
    wordlist = set()
    try:
        with open(path, 'r', encoding='utf-8', errors='ignore') as f:
            for line in f:
                word = line.strip()
                if word and not word.startswith('#'):
                    wordlist.add(word)
    except Exception as e:
        log_error(f"Não foi possível carregar wordlist de caminhos em '{path}': {e}")
        return set()
    return wordlist

# ---------- MÓDULO DE DESCOBERTA DE CAMINHOS DEDICADO ----------

class PathHunter:
    def __init__(self, target_url, path_wordlist_path, threads):
        self.target_url = target_url.rstrip('/')
        self.threads = threads
        self.found_paths = []
        
        self.session = requests.Session()
        self.session.verify = False 
        self.session.headers.update({'User-Agent': config.user_agents[0]})

        if path_wordlist_path:
            self.path_words = load_wordlist(path_wordlist_path)
            if not self.path_words:
                log_warning("Wordlist externa vazia ou falhou. Usando wordlist embutida.")
                self._load_internal_wordlist()
            else:
                log_info(f"Carregado wordlist externa: {len(self.path_words)} palavras.")
        else:
            self._load_internal_wordlist()
            log_warning(f"Usando wordlist de caminhos embutida: {len(self.path_words)} palavras.")


    def _load_internal_wordlist(self):
        """Carrega a wordlist embutida."""
        self.path_words = set(
            line.strip() for line in DEFAULT_PATH_WORDLIST_CONTENT.splitlines() 
            if line.strip() and not line.strip().startswith('#')
        )

    def _check_path(self, path):
        """Tenta acessar um caminho específico."""
        url = f"{self.target_url}/{path.lstrip('/')}"
        
        try:
            response = self.session.get(url, timeout=config.timeout, allow_redirects=False)
            status = response.status_code
            
            if status in [200, 301, 302, 307, 308, 401, 403, 500, 503]:
                
                details = ""
                
                if 200 <= status < 300: 
                    try:
                        from bs4 import BeautifulSoup # Importação de BeautifulSoup
                        soup = BeautifulSoup(response.text, 'html.parser')
                        title = soup.find('title')
                        details = title.get_text().strip()[:40] if title else "Sem Título"
                    except Exception:
                        details = "Página Encontrada"
                        
                elif 300 <= status < 400: 
                    details = f"Redireciona para: {response.headers.get('location', 'N/A')}"
                elif status == 403:
                    details = "Acesso Negado (Forbidden)"
                elif status == 401:
                    details = "Requer Autenticação (Unauthorized)"
                elif status >= 500:
                    details = "Erro no Servidor"
                    
                with _lock:
                    stats['path_found'] += 1
                    self.found_paths.append({
                        'url': url,
                        'status': status,
                        'details': details
                    })
                    
                status_color = Colors.GREEN if status == 200 else Colors.YELLOW if 300 <= status < 400 else Colors.RED
                log_route_found(f"{url} [{status_color}{status}{Colors.MAGENTA}] -> {details}")
                
        except requests.exceptions.RequestException:
            pass

    def run(self):
        """Executa o bruteforce de caminhos em paralelo."""
        if not self.path_words:
            log_error("Wordlist de caminhos vazia. Path Discovery não pode ser executado.")
            return []

        log_info(f"{Icons.FOLDER} Iniciando Path Discovery em {self.target_url} com {len(self.path_words)} palavras...")
        
        tasks = [(path) for path in self.path_words]

        with concurrent.futures.ThreadPoolExecutor(max_workers=self.threads) as executor:
            _ = [executor.submit(self._check_path, path) for path in tasks]
            
            executor.shutdown(wait=True) 

        return self.found_paths

# ---------- MAIN EXECUTION ----------
def main():
    
    BANNER = f"""
{Colors.CYAN}{Colors.BOLD}
 ███████╗ █████╗ ████████╗██╗  ██╗███████╗██████╗ 
 ██╔════╝██╔══██╗╚══██╔══╝██║  ██║██╔════╝██╔══██╗
 █████╗  ███████║   ██║   ███████║█████╗  ██████╔╝
 ██╔══╝  ██╔══██║   ██║   ██╔══██║██╔══╝  ██╔══██╗
 ██║     ██║  ██║   ██║   ██║  ██║███████╗██║  ██║
 ╚═╝     ╚═╝  ╚═╝   ╚═╝   ╚═╝  ╚═╝╚══════╝╚═╝  ╚═╝
                                                 
{Colors.YELLOW}   🚀 DEDICATED PATH DISCOVERY TOOL v1.0.1 🚀{Colors.RESET}
"""
    print(BANNER)
    
    parser = argparse.ArgumentParser(
        description="PathHunter Pro - Dedicated Directory/Path Discovery Tool",
        formatter_class=argparse.RawDescriptionHelpFormatter
    )
    
    parser.add_argument("-u", "--url", required=True, help="URL completa alvo (ex: https://dominio.com)")
    parser.add_argument("-pw", "--path-wordlist", help="Caminho para wordlist de rotas (opcional, usa a embutida por padrão)")
    parser.add_argument("-t", "--threads", type=int, default=50, help="Número de threads")
    parser.add_argument("-to", "--timeout", type=int, default=10, help="Timeout em segundos")
    
    args = parser.parse_args()
    
    config.timeout = args.timeout
    stats['start_time'] = time.time() 
    
    # Inicializar PathHunter
    hunter = PathHunter(args.url, args.path_wordlist, args.threads)
    
    # Executar e obter resultados
    found_paths = hunter.run()
    
    # Estatísticas finais
    duration = time.time() - stats['start_time']
    
    print("\n" + "="*50)
    log_success(f"\n{Icons.FIRE} SCAN DE CAMINHOS CONCLUÍDO {Icons.FIRE}")
    log_info(f"URL Alvo: {args.url}")
    log_info(f"Tempo total: {duration:.2f}s")
    log_info(f"Caminhos/Arquivos encontrados: {len(found_paths)}")
    print("="*50)
    
    if found_paths:
        log_info("\nSumário dos Caminhos Encontrados:")
        for path_info in sorted(found_paths, key=lambda x: x['status']):
            status_color = Colors.GREEN if path_info['status'] == 200 else Colors.YELLOW if 300 <= path_info['status'] < 400 else Colors.RED
            print(f"  {status_color}[{path_info['status']}]{Colors.RESET} {path_info['url']} -> {path_info['details']}")
    else:
        log_warning("Nenhum caminho interessante encontrado.")


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        log_warning("Execução interrompida pelo usuário")
        sys.exit(1)
    except Exception as e:
        log_error(f"Erro fatal: {e}")
        sys.exit(1)