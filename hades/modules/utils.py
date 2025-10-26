import requests

def send_request(url, param, payload):
    """
    Envia request GET com payload em parâmetro
    """
    try:
        r = requests.get(url, params={param: payload}, timeout=10)
        return r.text
    except Exception as e:
        print(f"[!] Erro ao enviar request: {e}")
        return ""

def load_wordlist(path):
    """
    Carrega wordlist e retorna lista de payloads
    """
    try:
        with open(path, "r", encoding="utf-8") as f:
            return [line.strip() for line in f if line.strip()]
    except FileNotFoundError:
        print(f"[!] Wordlist {path} não encontrada.")
        return []
