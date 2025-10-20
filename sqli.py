#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
特異点 (Tokuiten) - Log and URL Analyzer
Propósito: Analisar logs de acesso ou uma URL específica para identificar tentativas de SQL Injection.
Uso: 
  1. Analisar Log: python tokuiten_analyzer.py -f access.log
  2. Analisar URL: python tokuiten_analyzer.py -u "https://example.com/page?id=1' or 1=1--"
"""

import argparse
import re
import sys
from collections import defaultdict
from colorama import init, Fore, Style

try:
    from colorama import init, Fore, Style
except ImportError:
    print("❌ Dependências faltando. Instale: pip install colorama")
    sys.exit(1)

# Inicializa colorama
init(autoreset=True)

# ---------- CORES E EMOJIS (CORRIGIDO) ----------
class Colors:
    RESET = Style.RESET_ALL
    GREEN = Fore.GREEN + Style.BRIGHT
    YELLOW = Fore.YELLOW + Style.BRIGHT
    CYAN = Fore.CYAN + Style.BRIGHT
    RED = Fore.RED + Style.BRIGHT

class Icons:
    SHIELD = "🛡️"
    ANALYSIS = "🔍"
    ALERT = "🚨"
    LOG = "📜"
    LINK = "🔗" # Corrigido: Usando a variável LINK dentro da classe Icons
    ERROR_X = "❌" # Novo ícone para erros fatais

# BANNER com o novo nome "特異点 (Tokuiten)"
BANNER = f"""
{Colors.RED}{Style.BRIGHT}
    特  異  点
  (T O K U I T E N)
{Colors.CYAN} 🛡️ ANALISADOR DE PONTOS DE SINGULARIDADE 🛡️{Colors.RESET}
"""

print(BANNER)

# ---------- PADRÕES DE ATAQUE SQLI (DEFENSIVO) ----------
# Padrões comuns de tentativas de injeção SQL encontradas em logs
SQLI_PATTERNS = {
    'UNION_ATTEMPT': [
        r"union\s+select", 
        r"union\s+all"
    ],
    'BLIND_ATTEMPT': [
        r"if\s*\(", 
        r"sleep\s*\(", 
        r"benchmark\s*\(",
        r"waitfor\s+delay"
    ],
    'ERROR_ATTEMPT': [
        r"extractvalue\s*\(", 
        r"updatexml\s*\(",
        r"floor\s*\(rand\s*\("
    ],
    'BASIC_INJECTION': [
        r"'(\s+)?or(\s+)?1=1",
        r'"(\s+)?or(\s+)?1=1',
        r"\'\s*--",
        r"\/\*\s*\'",
        r"admin\'\s*--"
    ]
}

# ---------- FUNÇÕES DE ANÁLISE (CORRIGIDO) ----------

def analyze_input_for_sqli(text: str) -> str | None:
    """Verifica se um texto (linha de log ou URL) contém padrões de SQL Injection."""
    text_lower = text.lower()
    
    # *** CORREÇÃO APLICADA: SQLI_PATTERNS (correto) ***
    for attack_type, patterns in SQLI_PATTERNS.items():
        for pattern in patterns:
            if re.search(pattern, text_lower):
                return attack_type
    return None

def scan_single_url(url: str):
    """Analisa uma única URL fornecida pelo usuário."""
    print(f"{Colors.CYAN}{Icons.ANALYSIS} Iniciando análise de URL:{Colors.RESET}")
    
    print(f"{Icons.LINK} {url}") 
    
    result = analyze_input_for_sqli(url)
    
    print(f"\n{Colors.CYAN}{'='*40}{Colors.RESET}")
    if result:
        print(f"{Colors.RED}{Icons.ALERT} ALERTA DETECTADO!{Colors.RESET}")
        print(f"  {Colors.YELLOW}Tipo de Ataque: {result}{Colors.RESET}")
        print(f"  {Colors.YELLOW}Sugestão Defensiva: Esta URL contém um payload SQLi conhecido. Verifique a sanitização e o uso de Prepared Statements no backend.{Colors.RESET}")
    else:
        print(f"{Colors.GREEN}{Icons.SHIELD} Nenhuma tentativa de SQL Injection básica detectada na URL.{Colors.RESET}")
    print(f"{Colors.CYAN}{'='*40}{Colors.RESET}")


def process_log_file(file_path: str):
    """Lê o arquivo de log e processa cada linha."""
    
    try:
        with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
            log_lines = f.readlines()
    except FileNotFoundError:
        print(f"{Colors.RED}{Icons.ERROR_X} Arquivo de log não encontrado: {file_path}{Colors.RESET}")
        sys.exit(1)
    except Exception as e:
        print(f"{Colors.RED}{Icons.ERROR_X} Erro ao ler o arquivo: {e}{Colors.RESET}")
        sys.exit(1)

    print(f"{Colors.CYAN}{Icons.ANALYSIS} Iniciando análise de {len(log_lines)} linhas de log...{Colors.RESET}")
    
    alerts_found = 0
    summary = defaultdict(int)
    
    for i, line in enumerate(log_lines):
        result = analyze_input_for_sqli(line)
        if result:
            alerts_found += 1
            summary[result] += 1
            
            line_number = i + 1
            print(f"\n{Colors.RED}{Icons.ALERT} ALERTA [Linha {line_number}] - Tipo: {result}{Colors.RESET}")
            print(f"  {Colors.YELLOW}{line.strip()}{Colors.RESET}")
            
    print(f"\n{Colors.CYAN}{'='*40}{Colors.RESET}")
    print(f"{Colors.GREEN}{Icons.SHIELD} Análise de Log Concluída.{Colors.RESET}")
    print(f"{Colors.RED}Total de Tentativas de SQLi Detectadas: {alerts_found}{Colors.RESET}")
    
    if summary:
        print(f"\n{Colors.YELLOW}Resumo por Tipo de Ataque:{Colors.RESET}")
        for attack_type, count in summary.items():
            print(f"  - {attack_type}: {count}")
    else:
        print(f"\n{Colors.GREEN}Nenhuma tentativa de SQL Injection detectada neste log.{Colors.RESET}")


# ---------- MAIN ----------

def main():
    parser = argparse.ArgumentParser(
        description="特異点 (Tokuiten) - Analisador Defensivo de Logs e URL"
    )
    parser.add_argument("-u", "--url", help="URL específica para análise de injeção SQL (função de teste de entrada)")
    parser.add_argument("-f", "--file", help="Caminho para o arquivo de log de acesso (ex: access.log)")
    
    args = parser.parse_args()
    
    if args.url and args.file:
        print(f"{Colors.YELLOW}{Icons.ALERT} Por favor, use -u OU -f, não ambos.{Colors.RESET}")
        sys.exit(1)

    if args.url:
        scan_single_url(args.url)
    elif args.file:
        process_log_file(args.file)
    else:
        print(f"{Colors.RED}{Icons.ERROR_X} É necessário especificar uma URL (-u) ou um arquivo de log (-f).{Colors.RESET}")
        sys.exit(1)

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print(f"\n{Colors.YELLOW}Análise interrompida pelo usuário.{Colors.RESET}")
        sys.exit(0)
    except Exception as e:
        print(f"{Colors.RED}{Icons.ERROR_X} Erro fatal: {e}{Colors.RESET}")
        sys.exit(1)