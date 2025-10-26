#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Olimpo - Ferramenta OSINT simples para terminal
Subcomandos:
  - github   (busca dados públicos de usuário GitHub)
  - shodan   (pesquisa Shodan por query ou consulta host)
  - leaks    (busca e-mails em vazamentos públicos gratuitos em pastes)
  - emailtest (envia um e-mail de teste via SMTP configurado)
Uso:
  python olimpo.py github --user torvalds
  python olimpo.py shodan --query "apache" --key YOUR_KEY
  python olimpo.py shodan --host 8.8.8.8
  python olimpo.py leaks --email example@example.com
  python olimpo.py emailtest --to you@example.com
Configuração (arquivo .env ou variáveis ambiente):
  SHODAN_API_KEY=...
  GMAIL_USER=your@gmail.com
  GMAIL_PASS=your_app_password_or_smtp_password
  GMAIL_TO=alerts@you.com  # opcional, destinatário dos alertas
"""
import os
import sys
import argparse
import requests
import json
import smtplib
import ssl
import time
import re
from urllib.parse import quote_plus, urlparse
from bs4 import BeautifulSoup
from datetime import datetime
from dotenv import load_dotenv

load_dotenv()

# -------------------------
# Banner
# -------------------------
BANNER = r"""
  ____  _ _ _                            
 / __ \(_) | | ___   ___  _ __ ___  ___ 
| |  | | | | |/ _ \ / _ \| '__/ _ \/ __|
| |__| | | | | (_) | (_) | | |  __/\__ \
 \____/|_|_|_|\___/ \___/|_|  \___||___/
                                        
        O L I M P O   —  O S I N T
"""

def print_banner():
    print("\n" + BANNER)
    print("-> Ferramenta OSINT (GitHub / Shodan / Vazamentos públicos)")
    print("-> Use com responsabilidade. (C) Olimpo\n")

# -------------------------
# Constants / Config
# -------------------------
GITHUB_API = "https://api.github.com/users/{}"
SHODAN_SEARCH_API = "https://api.shodan.io/shodan/host/search"
SHODAN_HOST_API = "https://api.shodan.io/shodan/host/{}"
DUCKDUCKGO_HTML = "https://html.duckduckgo.com/html?q={}"
PASTE_SITES = [
    "pastebin.com",
    "ghostbin.com",
    "paste.ee",
    "slexy.org",
    "pastebin.pl",
    "pastebin.ca"
]

GMAIL_USER = os.getenv("GMAIL_USER")
GMAIL_PASS = os.getenv("GMAIL_PASS")
GMAIL_TO = os.getenv("GMAIL_TO", GMAIL_USER)

# -------------------------
# Utils
# -------------------------
def pretty_print_json(data):
    print(json.dumps(data, indent=2, ensure_ascii=False))

def print_header(title):
    print("\n" + "="*60)
    print(title)
    print("-"*60)

def normalize_url(href):
    # DuckDuckGo returns /l/?kh=...&uddg=<encoded_url> in some cases
    if not href:
        return None
    if href.startswith("/l/?kh=") or href.startswith("/y.js"):
        # try to extract uddg param
        m = re.search(r"uddg=(http[^&]+)", href)
        if m:
            return requests.utils.unquote(m.group(1))
        return None
    if href.startswith("/"):
        return None
    return href

# -------------------------
# GitHub
# -------------------------
def github_user(username):
    url = GITHUB_API.format(username)
    headers = {"Accept": "application/vnd.github.v3+json", "User-Agent": "Olimpo-OSINT-Tool"}
    try:
        r = requests.get(url, headers=headers, timeout=15)
    except Exception as e:
        print(f"[!] Erro ao conectar no GitHub: {e}")
        return

    if r.status_code == 200:
        data = r.json()
        print_header(f"GitHub — {username}")
        subset = {
            "login": data.get("login"),
            "name": data.get("name"),
            "company": data.get("company"),
            "blog": data.get("blog"),
            "location": data.get("location"),
            "email": data.get("email"),
            "bio": data.get("bio"),
            "public_repos": data.get("public_repos"),
            "followers": data.get("followers"),
            "following": data.get("following"),
            "created_at": data.get("created_at"),
            "html_url": data.get("html_url")
        }
        pretty_print_json(subset)
    elif r.status_code == 404:
        print(f"[!] Usuário '{username}' não encontrado no GitHub.")
    else:
        print(f"[!] Erro ao consultar GitHub: {r.status_code} - {r.text}")

# -------------------------
# Shodan
# -------------------------
def shodan_search(query, shodan_key):
    if not shodan_key:
        print("[!] SHODAN_API_KEY não fornecida. Defina SHODAN_API_KEY no .env ou use --key.")
        return
    params = {"key": shodan_key, "query": query}
    try:
        r = requests.get(SHODAN_SEARCH_API, params=params, timeout=20)
        if r.status_code == 200:
            data = r.json()
            print_header(f"Shodan — Search: {query} (total: {data.get('total')})")
            for i, match in enumerate(data.get("matches", [])[:10], start=1):
                ip_str = match.get("ip_str")
                port = match.get("port")
                org = match.get("org")
                hostnames = match.get("hostnames")
                product = match.get("product") or (match.get("http") or {}).get("server")
                timestamp = match.get("timestamp")
                snippet = (match.get("data") or "")[:200].replace("\n"," ")
                print(f"[{i}] {ip_str}:{port}  org={org} product={product} ts={timestamp}")
                print(f"     hostnames: {hostnames}")
                print(f"     snippet: {snippet}")
                print("-"*40)
        else:
            print(f"[!] Shodan API error {r.status_code}: {r.text}")
    except Exception as e:
        print(f"[!] Erro na requisição Shodan: {e}")

def shodan_host(ip, shodan_key):
    if not shodan_key:
        print("[!] SHODAN_API_KEY não fornecida. Defina SHODAN_API_KEY no .env ou use --key.")
        return
    url = SHODAN_HOST_API.format(ip)
    params = {"key": shodan_key}
    try:
        r = requests.get(url, params=params, timeout=20)
        if r.status_code == 200:
            data = r.json()
            print_header(f"Shodan — Host: {ip}")
            pretty_print_json({
                "ip": data.get("ip_str"),
                "org": data.get("org"),
                "os": data.get("os"),
                "last_update": data.get("last_update"),
                "ports": data.get("ports"),
                "vulns": data.get("vulns"),
                "hostnames": data.get("hostnames")
            })
            print("\nTop 3 services (raw snippets):")
            for i, service in enumerate(data.get("data", [])[:3], start=1):
                print(f"--- Service #{i} ---")
                print((service.get("data") or "")[:400].replace("\n"," "))
        elif r.status_code == 404:
            print(f"[!] Host {ip} não encontrado no Shodan.")
        else:
            print(f"[!] Shodan API error {r.status_code}: {r.text}")
    except Exception as e:
        print(f"[!] Erro na requisição Shodan (host): {e}")

# -------------------------
# Free paste search (DuckDuckGo)
# -------------------------
def search_pastes_duckduckgo(email, max_results=20):
    """
    Usa DuckDuckGo HTML para buscar o e-mail em domínios de paste.
    Retorna lista de URLs.
    """
    found_urls = []
    # Build combined site query for efficiency
    sites_query = " OR ".join([f"site:{s}" for s in PASTE_SITES])
    q = f'"{email}" ({sites_query})'
    url = DUCKDUCKGO_HTML.format(quote_plus(q))
    headers = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"}
    try:
        r = requests.get(url, headers=headers, timeout=20)
        r.raise_for_status()
        soup = BeautifulSoup(r.text, "html.parser")
        links = soup.find_all("a", href=True)
        for a in links:
            href = a.get("href")
            if not href:
                continue
            norm = normalize_url(href)
            if not norm:
                continue
            parsed = urlparse(norm)
            domain = parsed.netloc.lower()
            for site in PASTE_SITES:
                if site in domain:
                    if norm not in found_urls:
                        found_urls.append(norm)
                        if len(found_urls) >= max_results:
                            return found_urls
        return found_urls
    except Exception as e:
        print(f"[!] Erro ao consultar DuckDuckGo: {e}")
        return found_urls

# Optional: try to fetch snippet of paste (best-effort, may fail)
def fetch_paste_snippet(url, max_len=800):
    try:
        headers = {"User-Agent": "Mozilla/5.0"}
        r = requests.get(url, headers=headers, timeout=12)
        if r.status_code == 200:
            text = r.text
            # remove html tags, show first occurrence including email
            soup = BeautifulSoup(text, "html.parser")
            txt = soup.get_text(separator="\n")
            idx = txt.lower().find("@")
            if idx == -1:
                return txt[:max_len].strip()
            start = max(0, idx - 120)
            return txt[start:start+max_len].strip()
        return None
    except Exception:
        return None

# -------------------------
# Email alert via SMTP (Gmail)
# -------------------------
def send_email_alert(subject, body, to_addr=None):
    to_addr = to_addr or GMAIL_TO or GMAIL_USER
    if not GMAIL_USER or not GMAIL_PASS or not to_addr:
        print("[!] Credenciais Gmail não configuradas (GMAIL_USER / GMAIL_PASS / GMAIL_TO). Ignorando envio de alerta.")
        return False
    try:
        port = 587
        context = ssl.create_default_context()
        server = smtplib.SMTP("smtp.gmail.com", port, timeout=20)
        server.ehlo()
        server.starttls(context=context)
        server.login(GMAIL_USER, GMAIL_PASS)
        msg = f"From: {GMAIL_USER}\r\nTo: {to_addr}\r\nSubject: {subject}\r\n\r\n{body}"
        server.sendmail(GMAIL_USER, to_addr, msg.encode("utf-8"))
        server.quit()
        print(f"[+] Alerta enviado para {to_addr}")
        return True
    except Exception as e:
        print(f"[!] Falha ao enviar e-mail: {e}")
        return False

# -------------------------
# Top-level leak check, with optional email alert
# -------------------------
def check_leaks_and_alert(email):
    print_header(f"Buscando vazamentos públicos para {email}")
    urls = search_pastes_duckduckgo(email, max_results=25)
    if not urls:
        print("⚠️ Nenhum resultado encontrado em pastes públicos.")
        return
    print(f"[!] Encontrado(s): {len(urls)} resultado(s). Mostrando até 5 e salvando relatório simples.")
    report_lines = []
    for i, u in enumerate(urls[:10], start=1):
        print(f"[{i}] {u}")
        snippet = fetch_paste_snippet(u, max_len=600)
        if snippet:
            print("---- snippet ----")
            print(snippet[:600])
        print("-"*40)
        report_lines.append({"url": u, "snippet": snippet})
    # Save a small JSON report
    ts = datetime.utcnow().strftime("%Y%m%dT%H%M%SZ")
    safe_email = re.sub(r"[^a-zA-Z0-9@._-]", "_", email)
    os.makedirs("reports", exist_ok=True)
    report_path = f"reports/{safe_email}_{ts}.json"
    with open(report_path, "w", encoding="utf-8") as fh:
        json.dump({"email": email, "found": len(urls), "results": report_lines}, fh, ensure_ascii=False, indent=2)
    print(f"[+] Relatório salvo em: {report_path}")
    # Send email alert if configured
    if GMAIL_USER and GMAIL_PASS:
        subj = f"[Olimpo] Vazamento detectado para {email} ({len(urls)} hits)"
        body = f"Olimpo detectou {len(urls)} possíve(is) vazamento(s) para {email}.\nRelatório: {os.path.abspath(report_path)}\n\nURLs:\n" + "\n".join(urls[:10])
        send_email_alert(subj, body)
    else:
        print("[i] Credenciais de e-mail não configuradas — não foi enviado alerta por e-mail.")

# -------------------------
# CLI
# -------------------------
def main():
    print_banner()
    parser = argparse.ArgumentParser(prog="Olimpo", description="Olimpo - ferramentas OSINT (GitHub, Shodan, vazamentos gratuitos)")
    sub = parser.add_subparsers(dest="cmd", required=True)

    # github
    g = sub.add_parser("github", help="Buscar dados públicos de usuário GitHub")
    g.add_argument("--user", "-u", required=True, help="Nome de usuário GitHub")

    # shodan
    s = sub.add_parser("shodan", help="Interagir com API Shodan")
    s_group = s.add_mutually_exclusive_group(required=True)
    s_group.add_argument("--query", "-q", help="Query de busca Shodan (ex: 'apache')")
    s_group.add_argument("--host", "-H", help="Consultar host/IP no Shodan")
    s.add_argument("--key", help="SHODAN API key (ou leia do .env)")

    # leaks
    l = sub.add_parser("leaks", help="Buscar e-mails em vazamentos públicos (pastas/pastes)")
    l.add_argument("--email", "-e", required=True, help="Endereço de e-mail para checar")

    # email test
    et = sub.add_parser("emailtest", help="Enviar e-mail de teste (usa GMAIL_USER/GMAIL_PASS)")
    et.add_argument("--to", "-t", help="Destinatário (opcional)")

    args = parser.parse_args()

    # Shodan key safe-get
    shodan_key = getattr(args, "key", None) or os.getenv("SHODAN_API_KEY")

    if args.cmd == "github":
        github_user(args.user)
    elif args.cmd == "shodan":
        if getattr(args, "query", None):
            shodan_search(args.query, shodan_key)
        else:
            shodan_host(args.host, shodan_key)
    elif args.cmd == "leaks":
        check_leaks_and_alert(args.email)
    elif args.cmd == "emailtest":
        to = args.to or GMAIL_TO or GMAIL_USER
        if not to:
            print("[!] Configure GMAIL_USER/GMAIL_PASS e opcionalmente GMAIL_TO no .env para testar.")
        else:
            ok = send_email_alert("[Olimpo] Teste de e-mail", "Este é um teste enviado pelo Olimpo.", to_addr=to)
            if ok:
                print("[+] Teste enviado com sucesso.")
    else:
        parser.print_help()

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n[!] Interrompido pelo usuário.")
        sys.exit(0)
