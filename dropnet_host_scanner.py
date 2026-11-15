#!/usr/bin/env python3
"""DROPNET HOST SCANNER — verificador de hosts fornecidos pelo operador."""
import asyncio
import ipaddress
import ssl
from datetime import datetime
from pathlib import Path

OUT = Path.home() / "storage" / "downloads" / "DROPNET-SCANNER"
MAX_CIDR_HOSTS = 4096
TIMEOUT = 5
C = "\033[36m"; G = "\033[32m"; Y = "\033[33m"; R = "\033[31m"; X = "\033[0m"

def ask(label, default=""):
    value = input(f"{label}" + (f" [{default}]" if default else "") + ": ").strip()
    return value or default

def read_hosts(text):
    result = []
    for item in text.replace(",", "\\n").replace(";", "\\n").splitlines():
        item = item.strip()
        if not item or item.startswith("#"):
            continue
        item = item.replace("https://", "").replace("http://", "").split("/")[0]
        if item and item not in result:
            result.append(item)
    return result

def expand_cidr(value):
    net = ipaddress.ip_network(value.strip(), strict=False)
    if net.num_addresses > MAX_CIDR_HOSTS:
        raise ValueError(f"Faixa com {net.num_addresses} endereços; limite: {MAX_CIDR_HOSTS}.")
    return [str(ip) for ip in net.hosts()] or [str(net.network_address)]

def request_bytes(payload, host):
    raw = payload.strip() or "GET / HTTP/1.1\r\nHost: [host]\r\nConnection: close\r\n\r\n"
    raw = raw.replace("[host]", host).replace("[HOST]", host)
    return raw.replace("\\r", "\r").replace("\\n", "\n").encode("utf-8", "replace")

async def check(host, port, use_sni, sni, payload, sem):
    async with sem:
        try:
            ctx = ssl.create_default_context() if use_sni and port == 443 else None
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(host, port, ssl=ctx,
                    server_hostname=(sni or host) if ctx else None), TIMEOUT)
            writer.write(request_bytes(payload, host))
            await writer.drain()
            try:
                line = (await asyncio.wait_for(reader.readline(), TIMEOUT)).decode("latin-1", "replace").strip()
            except asyncio.TimeoutError:
                line = "SEM RESPOSTA HTTP"
            writer.close()
            try: await writer.wait_closed()
            except Exception: pass
            status = line.split()[1] if line.startswith("HTTP/") and len(line.split()) > 1 else "TCP"
            return host, status, line
        except Exception as exc:
            return host, "ERRO", str(exc)[:120]

async def run(hosts, port, use_sni, sni, payload, workers):
    sem = asyncio.Semaphore(workers)
    log, ok, other = [], [], []
    total = len(hosts)
    print(f"\\nProcessos: 0  Enviados: 0  Finalizados: 0")
    done = 0
    for task in asyncio.as_completed([check(h, port, use_sni, sni, payload, sem) for h in hosts]):
        host, status, detail = await task
        done += 1
        line = f"{host}:{port} | {status} | {detail}"
        log.append(line)
        if status in ("101", "200"):
            ok.append(line); print(f"{G}[{status}] {host}:{port}{X}")
        else:
            other.append(line); print(f"{Y if status != 'ERRO' else R}[{status}] {host}:{port} - {detail}{X}")
        print(f"\\rProcessos: {min(workers, total-done)}  Enviados: {done}  Finalizados: {done}", end="", flush=True)
    print()
    OUT.mkdir(parents=True, exist_ok=True)
    stamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    for suffix, rows in (("log", log), ("101_200", ok), ("outros", other)):
        (OUT / f"dropnet_host_{suffix}_{stamp}.txt").write_text("\\n".join(rows), encoding="utf-8")
    print(f"Resultados salvos em: {OUT}")

def main():
    print(f"{C}========== DROPNET HOST SCANNER =========={X}")
    print("Use somente hosts/redes que você tem autorização para testar.\\n")
    mode = ask("Modo: 1=Lista de Hosts, 2=CIDR Range, 3=TextLine", "1")
    use_sni = ask("Usar SNI? (s/n)", "n").lower() in ("s", "sim", "y")
    if mode == "2":
        try: hosts = expand_cidr(ask("CIDR (ex.: 192.0.2.0/28)"))
        except ValueError as exc:
            print(f"CIDR inválido: {exc}"); input("Enter para voltar..."); return
    else:
        print("Digite hosts separados por vírgula ou um por linha. Termine com FIM.")
        rows = []
        while True:
            row = input()
            if row.strip().upper() == "FIM": break
            rows.append(row)
        hosts = read_hosts("\\n".join(rows))
    if not hosts:
        print("Nenhum host informado."); input("Enter para voltar..."); return
    try:
        port = int(ask("Porta", "443" if use_sni else "80"))
        if not 1 <= port <= 65535: raise ValueError
    except ValueError:
        print("Porta inválida."); input("Enter para voltar..."); return
    sni = ask("SNI (vazio = usar host)", "") if use_sni else ""
    payload = ask("Payload HTTP (Enter = GET padrão)", "")
    try: workers = max(1, min(100, int(ask("Processos simultâneos", "30"))))
    except ValueError: workers = 30
    print(f"\\nHosts: {len(hosts)} | Porta: {port} | SNI: {'SIM' if use_sni else 'NÃO'}")
    input("Pressione Enter para iniciar...")
    try: asyncio.run(run(hosts, port, use_sni, sni, payload, workers))
    except KeyboardInterrupt: print("\\nVerificação interrompida.")
    input("\\nEnter para voltar ao menu...")

if __name__ == "__main__":
    main()
