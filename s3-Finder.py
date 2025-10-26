#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
s3_enum_discover.py - Scanner S3 com modo de descoberta automática (educacional).
Uso responsável: somente alvos com permissão.
"""

import argparse
import requests
from concurrent.futures import ThreadPoolExecutor, as_completed
from urllib.parse import urljoin, urlparse, quote
from bs4 import BeautifulSoup
import re
import time
import shutil
from colorama import Fore, Style, init

init(autoreset=True)

USER_AGENT = "s3-enum-edu/1.1 (+https://example.local/)"
DEFAULT_REGIONS = ["us-east-1","us-west-2","eu-west-1","sa-east-1"]

# ---------- BANNER ----------

def banner():
    print(Fore.CYAN + Style.BRIGHT + r"""
   _____ ____     ______           __           
  / ___// __ \   / ____/___ ______/ /____  _____
  \__ \/ / / /  / __/ / __ `/ ___/ __/ _ \/ ___/
 ___/ / /_/ /  / /___/ /_/ (__  ) /_/  __/ /    
/____/\____/  /_____/\__,_/____/\__/\___/_/     
                                                  
        """ + Fore.BLUE + Style.BRIGHT + "S3-Eyes — AWS S3 Route & Bucket Discovery Tool")
    print(Fore.WHITE + "        Ethical research only • by caique-dev\n" + Style.RESET_ALL)

# ---------- utilidades básicas ----------

def check_url(url, timeout=8):
    headers = {"User-Agent": USER_AGENT}
    try:
        resp = requests.head(url, headers=headers, allow_redirects=True, timeout=timeout)
    except requests.RequestException as e:
        return {"url": url, "status": None, "error": str(e)}
    if resp.status_code == 405:
        try:
            resp = requests.get(url, headers=headers, stream=True, timeout=timeout)
        except requests.RequestException as e:
            return {"url": url, "status": None, "error": str(e)}
    return {"url": url, "status": resp.status_code, "headers": dict(resp.headers)}

def classify_result(res):
    status = res.get("status")
    if status is None:
        return "ERROR"
    if status == 200:
        return "FOUND (200)"
    if status == 403:
        return "EXISTS (403)"
    if status in (301,302,307,308):
        return f"REDIRECT ({status})"
    if 400 <= status < 500:
        return f"CLIENT {status}"
    if 500 <= status < 600:
        return f"SERVER {status}"
    return f"OTHER {status}"

# ---------- construção de URLs S3 ----------
COMMON_PATTERNS = [
    "https://{bucket}.s3.amazonaws.com/{path}",
    "https://s3.amazonaws.com/{bucket}/{path}",
    "https://s3.{region}.amazonaws.com/{bucket}/{path}"
]

def build_s3_candidates(bucket=None, path="", region=None):
    cand = []
    for p in COMMON_PATTERNS:
        if "{bucket}" in p and not bucket:
            continue
        if "{region}" in p:
            regions = [region] if region else DEFAULT_REGIONS
            for r in regions:
                cand.append(p.format(bucket=bucket, path=quote(path, safe="/"), region=r))
        else:
            cand.append(p.format(bucket=bucket, path=quote(path, safe="/")))
    return list(dict.fromkeys(cand))

# ---------- discovery: crawl simples e extração ----------
S3_URL_RE = re.compile(r"(?:https?://[^\s'\"<>]*(?:s3\.amazonaws\.com|\.s3\.amazonaws\.com|amazonaws\.com|s3\.[a-z0-9-]+\.amazonaws\.com))", re.I)

def fetch_text(url, timeout=8):
    headers = {"User-Agent": USER_AGENT}
    try:
        r = requests.get(url, headers=headers, timeout=timeout)
        return r.status_code, r.text
    except Exception as e:
        return None, None

def crawl_for_s3_links(domain, timeout=8):
    found = set()
    base = domain if domain.startswith("http") else "https://" + domain
    endpoints = [base, urljoin(base, "/"), urljoin(base, "/robots.txt"), urljoin(base, "/sitemap.xml")]
    for ep in endpoints:
        status, text = fetch_text(ep, timeout=timeout)
        if not text:
            continue
        for m in S3_URL_RE.findall(text):
            found.add(m.strip().strip('",\''))
        try:
            soup = BeautifulSoup(text, "html.parser")
            for tag in soup.find_all(src=True):
                src = tag.get("src")
                if "amazonaws.com" in src or ".s3." in src:
                    found.add(urljoin(base, src))
            for tag in soup.find_all(href=True):
                href = tag.get("href")
                if "amazonaws.com" in href or ".s3." in href:
                    found.add(urljoin(base, href))
            for script in soup.find_all("script"):
                if script.string:
                    for m in S3_URL_RE.findall(script.string):
                        found.add(m)
        except Exception:
            pass
    return sorted(found)

# ---------- bucket bruteforce ----------
COMMON_BUCKET_WORDS = [
    "backup","backups","assets","static","cdn","files","uploads","media","prod","staging","dev",
    "download","site","www","public","private","logs","archive","images","img","resources"
]

def generate_bucket_candidates_from_domain(domain):
    domain = domain.lower()
    labels = re.sub(r"https?://", "", domain).split("/")[0].split(".")
    core = labels[-2] if len(labels) >= 2 else labels[0]
    candidates = set()
    candidates.add(core)
    candidates.add(core + "-" + "s3")
    candidates.add(core + "-assets")
    candidates.add(core + "-backup")
    candidates.add("www-" + core)
    for w in COMMON_BUCKET_WORDS:
        candidates.add(core + "-" + w)
        candidates.add(w + "-" + core)
    normalized = "-".join(labels)
    candidates.add(normalized)
    return sorted(candidates)

# ---------- worker e fluxo principal ----------
def worker_check(url, timeout):
    r = check_url(url, timeout=timeout)
    return {"url": url, "status": r.get("status"), "tag": classify_result(r), "error": r.get("error")}

def run_checks(candidates, threads=10, timeout=8, pause=0.0):
    results = []
    with ThreadPoolExecutor(max_workers=threads) as ex:
        futures = {ex.submit(worker_check, c, timeout): c for c in candidates}
        try:
            for fut in as_completed(futures):
                r = fut.result()
                results.append(r)
                if r["tag"].startswith(("FOUND","EXISTS","REDIRECT","ERROR")):
                    print(f"{r['tag']}\t{r['url']}")
                if pause:
                    time.sleep(pause)
        except KeyboardInterrupt:
            print("\n[!] Cancelled by user.")
    return results

# ---------- MAIN ----------
def main():
    banner()  # mostra o banner no início
    parser = argparse.ArgumentParser(description="s3_enum_discover - enum S3 + discovery (educacional)")
    g = parser.add_mutually_exclusive_group(required=False)
    g.add_argument("--bucket", help="Nome do bucket S3 (ex: meus-bucket)")
    g.add_argument("--domain", help="Domínio/host a testar (ex: example.com)")
    parser.add_argument("--wordlist", help="Arquivo com caminhos (um por linha).")
    parser.add_argument("--threads", type=int, default=10)
    parser.add_argument("--timeout", type=int, default=8)
    parser.add_argument("--pause", type=float, default=0.0)
    parser.add_argument("--region", help="Região AWS (opcional).")
    parser.add_argument("--discover-domain", help="Tenta descobrir referências S3 no domínio (crawl básico).")
    parser.add_argument("--bruteforce-buckets", action="store_true", help="Gera e testa nomes de bucket a partir do domínio.")
    args = parser.parse_args()

    print("[!] Use somente em alvos com permissão explícita. Uso educacional/legítimo apenas.\n")

    candidates = []

    if args.discover_domain:
        print(f"[+] Crawling {args.discover_domain} for S3 references...")
        found_urls = crawl_for_s3_links(args.discover_domain, timeout=args.timeout)
        print(f"[+] Found {len(found_urls)} explicit S3-like URLs from crawl.")
        for u in found_urls:
            candidates.append(u)

    if args.bucket and args.wordlist:
        with open(args.wordlist, "r", encoding="utf-8", errors="ignore") as f:
            paths = [l.strip() for l in f if l.strip() and not l.strip().startswith("#")]
        for p in paths:
            candidates.extend(build_s3_candidates(bucket=args.bucket, path=p, region=args.region))

    if args.bruteforce_buckets and args.domain:
        print(f"[+] Generating bucket candidates from domain {args.domain}...")
        buckets = generate_bucket_candidates_from_domain(args.domain)
        print(f"[+] Generated {len(buckets)} bucket name candidates. Building URLs (no path).")
        for b in buckets:
            candidates.extend(build_s3_candidates(bucket=b, path="", region=args.region))

    candidates = list(dict.fromkeys(candidates))
    if not candidates:
        print("[!] Nenhum candidato gerado. Forneça --bucket/--domain/--wordlist ou use --discover-domain/--bruteforce-buckets.")
        return

    print(f"[+] Total de URLs candidatas a checar: {len(candidates)}. Iniciando checks com {args.threads} threads...")
    results = run_checks(candidates, threads=args.threads, timeout=args.timeout, pause=args.pause)

    summary = {}
    for r in results:
        summary[r["tag"]] = summary.get(r["tag"], 0) + 1
    print("\n[+] Scan finalizado. Resumo:")
    for k, v in summary.items():
        print(f"  {k}: {v}")

if __name__ == "__main__":
    main()
