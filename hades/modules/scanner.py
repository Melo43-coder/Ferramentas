from modules.utils import send_request, load_wordlist

def sqli_scan(url, param):
    print(f"[HADES] Iniciando scan SQLi em {url}?{param}=...")
    payloads = load_wordlist("wordlists/sqli.txt")
    for p in payloads:
        resp = send_request(url, param, p)
        # Checagem básica (exemplo: mensagens de erro comuns em SQLi)
        if "sql" in resp.lower() or "error" in resp.lower() or "warning" in resp.lower():
            print(f"[!] Possível SQLi detectada com payload: {p}")

def xss_scan(url, param):
    print(f"[HADES] Iniciando scan XSS em {url}?{param}=...")
    payloads = load_wordlist("wordlists/xss.txt")
    for p in payloads:
        resp = send_request(url, param, p)
        # Checagem básica: se o payload refletido no HTML
        if p in resp:
            print(f"[!] Possível XSS detectada com payload: {p}")
