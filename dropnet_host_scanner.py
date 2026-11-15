#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""DROPNET HOST SCANNER - painel TUI para testes em destinos autorizados."""
import asyncio
import ipaddress
import os
import re
import shutil
import socket
import ssl
import sys
from datetime import datetime
from pathlib import Path

OUT = Path.home() / "storage" / "downloads" / "DROPNET-SCANNER"
MAX_CIDR_HOSTS = 256
TIMEOUT = 5
C = "\033[96m"; G = "\033[92m"; Y = "\033[93m"; R = "\033[91m"; M = "\033[95m"; W = "\033[97m"; D = "\033[90m"; X = "\033[0m"

CFG = {
    "target": "",
    "use_sni": True,
    "use_cidr": False,
    "textline": False,
    "payload": "GET / HTTP/1.1\\r\\nHost: [host]\\r\\nConnection: close\\r\\n\\r\\n",
    "proxy": "",
    "sni": "",
    "ports": [443],
    "mode": "REDE DIRETA",
    "workers": 20,
}


def clear():
    os.system("clear" if os.name == "posix" else "cls")


def header():
    clear()
    print(C + "╔══════════════════════════════════════════════════════╗")
    print("║                 DROPNET HOST SCANNER                 ║")
    print("╚══════════════════════════════════════════════════════╝" + X)
    print(D + " Painel de testes de conectividade em redes autorizadas" + X)


def toggle(value):
    return G + "[ ON ]" + X if value else D + "[ OFF ]" + X


def show_panel():
    header()
    ports = ",".join(str(p) for p in CFG["ports"])
    print(f"\n {W}IP / CIDR :{X} {CFG['target'] or '(não definido)'}")
    print(f" {W}Usar SNI  :{X} {toggle(CFG['use_sni'])}     {W}Usar CIDR:{X} {toggle(CFG['use_cidr'])}     {W}TextLine:{X} {toggle(CFG['textline'])}")
    print(f"\n {W}MODO      :{X} {CFG['mode']}")
    print(f" {W}PROXY     :{X} {CFG['proxy'] or '(sem proxy)'}")
    print(f" {W}PAYLOAD   :{X} {'(vazia)' if not CFG['payload'].strip() else 'configurada'}")
    print(f" {W}SNI       :{X} {CFG['sni'] or '(não definida)'}")
    print(f" {W}PORTA     :{X} {ports}")
    print(f" {W}PROCESSOS :{X} {CFG['workers']}")
    print("\n" + C + " ───────────────────── CONFIGURAR ─────────────────────" + X)
    print(" 1) IP / CIDR        2) Usar SNI       3) Usar CIDR Range")
    print(" 4) Usar TextLine    5) Payload        6) Proxy")
    print(" 7) SNI              8) Porta          9) Modo de rede")
    print("10) Processos")
    print("\n" + G + " [I] INICIAR SCAN" + X + "       " + R + " [0] SAIR" + X)


def edit_line(label, current=""):
    print(f"\n{label}")
    value = input(f"> {current}\nNovo valor (ENTER mantém): ").strip()
    return value if value else current


def edit_payload():
    print("\nPAYLOAD - cole o conteúdo; finalize com uma linha contendo FIM")
    print("Dica: [host], [crlf], [lf] e [method] são substituídos pelo scanner.\n")
    lines = []
    while True:
        try:
            line = input()
        except (EOFError, KeyboardInterrupt):
            return CFG["payload"]
        if line.strip().upper() == "FIM":
            break
        lines.append(line)
    return "\n".join(lines)


def parse_ports():
    print("\n1) 80     2) 443     3) 80 e 443")
    choice = input("Porta [2]: ").strip() or "2"
    return {"1": [80], "2": [443], "3": [80, 443]}.get(choice)


def parse_proxy_list(raw):
    result = []
    for item in re.split(r"[#\n,;]+", raw):
        item = item.strip()
        if not item:
            continue
        if ":" in item:
            host, p = item.rsplit(":", 1)
            port = int(p)
        else:
            host, port = item, 8080
        if not host or not 1 <= port <= 65535:
            raise ValueError("Proxy inválida.")
        result.append((host, port))
    return list(dict.fromkeys(result))


def normalize_target(value):
    value = value.strip().replace("https://", "").replace("http://", "")
    if CFG["use_cidr"] and "/" in value:
        return value
    return value.split("/", 1)[0]


def get_targets():
    value = normalize_target(CFG["target"])
    if not value:
        raise ValueError("Informe um IP, host ou CIDR.")
    if CFG["use_cidr"]:
        net = ipaddress.ip_network(value, strict=False)
        if not net.is_private:
            raise ValueError("CIDR permitido somente em rede privada/autorizada.")
        if net.num_addresses > MAX_CIDR_HOSTS:
            raise ValueError(f"Limite de {MAX_CIDR_HOSTS} endereços por varredura.")
        return [str(ip) for ip in net.hosts()] or [str(net.network_address)]
    if "/" in value:
        raise ValueError("Ative Usar CIDR Range para informar uma faixa.")
    return [value]


async def open_connection(target, port, proxy=None, use_tls=False, sni=""):
    if proxy:
        reader, writer = await asyncio.wait_for(asyncio.open_connection(*proxy), TIMEOUT)
        req = f"CONNECT {target}:{port} HTTP/1.1\r\nHost: {target}:{port}\r\nProxy-Connection: Keep-Alive\r\n\r\n"
        writer.write(req.encode()); await writer.drain()
        response = await asyncio.wait_for(reader.readline(), TIMEOUT)
        if b" 200 " not in response:
            writer.close()
            try: await writer.wait_closed()
            except Exception: pass
            raise ConnectionError("Proxy recusou CONNECT: " + response.decode("latin-1", "replace").strip())
        while True:
            line = await asyncio.wait_for(reader.readline(), TIMEOUT)
            if line in (b"\r\n", b"\n", b""):
                break
    else:
        reader, writer = await asyncio.wait_for(asyncio.open_connection(target, port), TIMEOUT)
    if use_tls:
        context = ssl.create_default_context()
        await writer.start_tls(context, server_hostname=(sni or target), ssl_handshake_timeout=TIMEOUT)
    return reader, writer


async def probe(target, port, proxy, sem, index):
    async with sem:
        writer = None
        try:
            tls = port == 443
            sni = CFG["sni"] if CFG["use_sni"] and tls else target
            reader, writer = await open_connection(target, port, proxy, tls, sni)
            payload = CFG["payload"].replace("[host]", target).replace("[HOST]", target)
            if CFG["textline"]:
                payload = payload.replace("[crlf]", "\r\n").replace("[lf]", "\n")
            payload = payload.replace("[method]", "GET")
            payload = payload.replace("\\r", "\r").replace("\\n", "\n")
            if payload.strip():
                writer.write(payload.encode("utf-8", "replace")); await writer.drain()
            lines = []
            # Lê respostas adicionais sem bloquear indefinidamente.
            while len(lines) < 8:
                try:
                    raw = await asyncio.wait_for(reader.readline(), 1.2 if lines else TIMEOUT)
                except asyncio.TimeoutError:
                    break
                if not raw:
                    break
                line = raw.decode("latin-1", "replace").strip()
                if line:
                    lines.append(line)
                    if line.startswith("HTTP/"):
                        # Guarda o status e continua para capturar cabeçalhos/segunda resposta.
                        pass
                if len(lines) >= 8:
                    break
            status_lines = [x for x in lines if x.startswith("HTTP/")]
            detail = " | ".join(status_lines or lines or ["Conexão estabelecida; sem resposta HTTP"])
            status = status_lines[0].split()[1] if status_lines and len(status_lines[0].split()) > 1 else "TCP"
            return index, target, port, status, detail, "OK"
        except Exception as exc:
            return index, target, port, "ERRO", str(exc)[:180], "ERRO"
        finally:
            if writer:
                writer.close()
                try: await writer.wait_closed()
                except Exception: pass


async def run_scan():
    targets = get_targets()
    proxies = parse_proxy_list(CFG["proxy"]) if CFG["mode"] == "PROXY" else []
    if CFG["mode"] == "PROXY" and not proxies:
        raise ValueError("Informe ao menos uma proxy no modo PROXY.")
    if CFG["mode"] != "PROXY":
        proxies = [None]
    jobs = [(host, port) for host in targets for port in CFG["ports"]]
    sem = asyncio.Semaphore(CFG["workers"])
    print(f"\n{C}DROPNET - INICIANDO{X}")
    print(f"Alvos: {len(targets)} | Portas: {CFG['ports']} | Processos: {CFG['workers']}\n")
    log, accepted = [], []
    completed = 0
    tasks = []
    for idx, (host, port) in enumerate(jobs, 1):
        proxy = proxies[(idx - 1) % len(proxies)]
        tasks.append(probe(host, port, proxy, sem, idx))
    for task in asyncio.as_completed(tasks):
        idx, host, port, status, detail, result = await task
        completed += 1
        proxy_tag = "" if CFG["mode"] != "PROXY" else f" via {proxies[(idx-1) % len(proxies)][0]}"
        row = f"Processo {idx}: {host}:{port} - HTTP/{status} - {detail}{proxy_tag}"
        log.append(row)
        if status in ("101", "200"):
            accepted.append(row)
            print(f"{G}{row}{X}")
        elif status == "ERRO":
            print(f"{R}{row}{X}")
        else:
            print(f"{Y}{row}{X}")
        print(f"\rProcessos: {min(CFG['workers'], len(jobs)-completed)} | Enviados: {completed} | Finalizados: {completed}", end="", flush=True)
    print("\n")
    OUT.mkdir(parents=True, exist_ok=True)
    stamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    (OUT / f"host_log_{stamp}.txt").write_text("\n".join(log), encoding="utf-8")
    (OUT / f"host_status_101_200_{stamp}.txt").write_text("\n".join(accepted), encoding="utf-8")
    print(f"Resultados salvos em: {OUT}")


def configure(choice):
    if choice == "1":
        CFG["target"] = edit_line("IP ou CIDR", CFG["target"])
    elif choice == "2":
        CFG["use_sni"] = not CFG["use_sni"]
    elif choice == "3":
        CFG["use_cidr"] = not CFG["use_cidr"]
    elif choice == "4":
        CFG["textline"] = not CFG["textline"]
    elif choice == "5":
        CFG["payload"] = edit_payload()
    elif choice == "6":
        CFG["proxy"] = edit_line("Proxy(s), separadas por # ou linha. Sem porta = 8080", CFG["proxy"])
    elif choice == "7":
        CFG["sni"] = edit_line("SNI", CFG["sni"])
    elif choice == "8":
        value = parse_ports()
        if value: CFG["ports"] = value
    elif choice == "9":
        print("\n1) PROXY\n2) REDE DIRETA (usa a rota ativa do Android: Wi-Fi ou dados móveis)")
        v = input("Modo [2]: ").strip() or "2"
        if v == "1": CFG["mode"] = "PROXY"
        elif v == "2": CFG["mode"] = "REDE DIRETA"
    elif choice == "10":
        try:
            CFG["workers"] = max(1, min(64, int(edit_line("Processos (1-64)", str(CFG["workers"])))) )
        except ValueError: print("Número inválido.")


def main():
    while True:
        show_panel()
        choice = input("\n Opção: ").strip().lower()
        if choice in ("0", "q", "sair"):
            print("Até mais!"); return
        if choice in ("i", "iniciar"):
            try:
                if not CFG["target"]: CFG["target"] = input("IP / CIDR: ").strip()
                if not CFG["payload"].strip(): CFG["payload"] = edit_payload()
                asyncio.run(run_scan())
            except KeyboardInterrupt:
                print("\nScan interrompido.")
            except Exception as exc:
                print(f"\n{R}[ERRO] {exc}{X}")
            input("\nENTER para voltar ao painel")
        else:
            configure(choice)
            input("\nENTER para voltar ao painel")


if __name__ == "__main__":
    try:
        main()
    except (KeyboardInterrupt, EOFError):
        print("\nEncerrado.")
