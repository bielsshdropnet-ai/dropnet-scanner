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
TLS_PORTS = {443}
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
    "workers": 20,
    "connect": False,   # False = conecta DIRETO no IP (como o CheckHost); True = proxy HTTP (CONNECT)
}


def clear():
    os.system("clear" if os.name == "posix" else "cls")


def header():
    clear()
    print(C + "╔══════════════════════════════════════╗")
    print("║        DROPNET HOST SCANNER           ║")
    print("╚══════════════════════════════════════╝" + X)
    print(D + " Painel de testes em redes autorizadas" + X)


def toggle(value):
    return G + "[ ON ]" + X if value else D + "[ OFF ]" + X


def show_panel():
    """Painel simples, vertical e adequado à tela do Termux."""
    header()
    port = CFG["ports"][0] if CFG["ports"] else 443
    sni_active = port == 443
    proxy_label = CFG["proxy"].replace("\n", " # ") or "(não configurada)"
    if len(proxy_label) > 34:
        proxy_label = proxy_label[:31] + "..."
    print(f"\n{C}========== CONFIGURAÇÃO =========={X}")
    print(f"{W}HOST    :{X} {CFG['target'] or '(não definido)'}")
    print(f"{W}PORTA   :{X} {port}")
    print(f"{W}SNI     :{X} {CFG['sni'] or '(não definido)' if sni_active else '(desativado na porta 80)'}")
    print(f"{W}PAYLOAD :{X} {'configurada' if CFG['payload'].strip() else '(vazia)'}")
    print(f"{W}PROXY   :{X} {proxy_label}")
    print(f"{W}MODO    :{X} {'CONNECT (proxy HTTP)' if CFG['connect'] else 'DIRETO (IP + SNI + payload)'}")
    print(f"\n{C}============= MENU ==============={X}")
    print("[1] HOST")
    print("[2] PORTA (80 ou 443)")
    if sni_active:
        print("[3] SNI")
    print("[4] PAYLOAD")
    print("[5] PROXY")
    print("[7] MODO (direto / CONNECT)")
    print(G + "[6] ▶ INICIAR SCAN" + X)
    print(R + "[0] SAIR" + X)


def edit_line(label, current=""):
    print(f"\n{label}")
    value = input(f"> {current}\nNovo valor (ENTER mantém): ").strip()
    return value if value else current


def edit_payload():
    print("\nPAYLOAD - cole tudo em uma linha e aperte ENTER para salvar")
    print("Use [host], [crlf], [lf] e [method] quando necessário.")
    try:
        value = input("> ").strip()
    except (EOFError, KeyboardInterrupt):
        return CFG["payload"]
    return value if value else CFG["payload"]


def parse_ports():
    value = input("Porta (80 ou 443) [443]: ").strip() or "443"
    if value not in ("80", "443"):
        print("Escolha somente 80 ou 443.")
        return None
    # SNI fica automaticamente ativo somente na porta 443.
    CFG["use_sni"] = value == "443"
    return [int(value)]


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
            host, port = item, None
        if not host or (port is not None and not 1 <= port <= 65535):
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


def tls_context():
    """Sem verificação de certificado: o SNI de bypass quase nunca bate com o certificado do IP."""
    context = ssl.create_default_context()
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE
    return context


async def etapa(coro, mensagem):
    """Espera uma etapa e, se estourar o tempo, devolve um erro com texto (antes vinha vazio)."""
    try:
        return await asyncio.wait_for(coro, TIMEOUT)
    except asyncio.TimeoutError:
        raise TimeoutError(mensagem) from None


async def open_connection(target, port, proxy, use_tls=False, sni=""):
    phost, pport = proxy
    if not CFG["connect"]:
        # MODO DIRETO (igual ao CheckHost): conecta no IP da PROXY, faz o TLS com o SNI
        # e depois envia o payload com o Host. Sem CONNECT.
        destino_porta = pport or port
        reader, writer = await etapa(
            asyncio.open_connection(phost, destino_porta),
            f"timeout ao conectar em {phost}:{destino_porta}")
        if use_tls:
            try:
                await writer.start_tls(tls_context(), server_hostname=(sni or target),
                                       ssl_handshake_timeout=TIMEOUT)
            except asyncio.TimeoutError:
                writer.close()
                raise TimeoutError(f"timeout no handshake TLS com {phost}:{destino_porta} (SNI {sni or target})") from None
        return reader, writer

    # MODO CONNECT: a PROXY é um proxy HTTP (porta padrão 8080)
    pport = pport or 8080
    reader, writer = await etapa(asyncio.open_connection(phost, pport),
                                 f"timeout ao conectar no proxy {phost}:{pport}")
    req = f"CONNECT {target}:{port} HTTP/1.1\r\nHost: {target}:{port}\r\nProxy-Connection: Keep-Alive\r\n\r\n"
    writer.write(req.encode()); await writer.drain()
    response = await etapa(reader.readline(), f"proxy {phost}:{pport} não respondeu ao CONNECT")
    if b" 200 " not in response:
        writer.close()
        try: await writer.wait_closed()
        except Exception: pass
        raise ConnectionError("Proxy recusou CONNECT: " + response.decode("latin-1", "replace").strip())
    while True:
        line = await asyncio.wait_for(reader.readline(), TIMEOUT)
        if line in (b"\r\n", b"\n", b""):
            break
    if use_tls:
        await writer.start_tls(tls_context(), server_hostname=(sni or target), ssl_handshake_timeout=TIMEOUT)
    return reader, writer


async def probe(target, port, proxy, sem, index):
    async with sem:
        writer = None
        try:
            tls = port in TLS_PORTS
            sni = (CFG["sni"] or target) if CFG["use_sni"] and tls else target
            reader, writer = await open_connection(target, port, proxy, tls, sni)
            payload = CFG["payload"].replace("[host]", target).replace("[HOST]", target)
            if CFG["textline"]:
                payload = payload.replace("[crlf]", "\r\n").replace("[lf]", "\n")
            payload = payload.replace("[method]", "GET")
            payload = payload.replace("\\r", "\r").replace("\\n", "\n")
            if payload.strip():
                writer.write(payload.encode("utf-8", "replace")); await writer.drain()

            # Lê tudo que chegar (ex.: 403, 403, 101, 200 na mesma conexão), não só a 1ª linha.
            loop = asyncio.get_running_loop()
            recebidos = bytearray()
            limite = loop.time() + TIMEOUT
            while len(recebidos) < 262144:
                restante = limite - loop.time()
                if restante <= 0:
                    break
                try:
                    bloco = await asyncio.wait_for(reader.read(65536), restante)
                except asyncio.TimeoutError:
                    break
                if not bloco:
                    break
                if not recebidos:
                    limite = min(limite, loop.time() + 3.0)   # depois da 1ª resposta espera mais um pouco
                recebidos.extend(bloco)

            achados = re.findall(rb"(?im)^HTTP/\d(?:\.\d)?[ \t]+(\d{3})([^\r\n]*)", bytes(recebidos))
            codigos = [raw.decode() for raw, _ in achados]
            status_lines = [f"HTTP {raw.decode()}{motivo.decode('latin-1', 'replace').rstrip()}" for raw, motivo in achados]
            if status_lines:
                # Se QUALQUER resposta da sequência foi 101 ou 200, conta como aprovado.
                status = "101" if "101" in codigos else ("200" if "200" in codigos else codigos[0])
                detail = " | ".join(status_lines)
            else:
                texto = [x.strip() for x in recebidos.decode("latin-1", "replace").splitlines() if x.strip()][:3]
                status = "TCP"
                detail = " | ".join(texto) or "Conexão estabelecida; sem resposta HTTP"
            return index, target, port, status, detail, "OK"
        except Exception as exc:
            motivo = str(exc).strip() or type(exc).__name__
            return index, target, port, "ERRO", motivo[:180], "ERRO"
        finally:
            if writer:
                writer.close()
                try: await writer.wait_closed()
                except Exception: pass


async def run_scan():
    targets = get_targets()
    proxies = parse_proxy_list(CFG["proxy"])
    if not proxies:
        raise ValueError("Configure ao menos uma PROXY antes de iniciar o scan.")
    if CFG["connect"]:
        # CONNECT: cada alvo/porta usa uma proxy (rodízio), como antes
        jobs = []
        for host in targets:
            for port in CFG["ports"]:
                jobs.append((host, port, proxies[len(jobs) % len(proxies)]))
    else:
        # DIRETO: testa o Host em TODOS os IPs informados
        jobs = [(host, port, proxy) for proxy in proxies for host in targets for port in CFG["ports"]]
    sem = asyncio.Semaphore(CFG["workers"])
    print(f"\n{C}DROPNET - INICIANDO{X}")
    print(f"Modo: {'CONNECT' if CFG['connect'] else 'DIRETO'} | Hosts: {len(targets)} | IPs/Proxies: {len(proxies)} "
          f"| Portas: {CFG['ports']} | Tarefas: {len(jobs)} | Processos: {CFG['workers']}\n")
    log, accepted = [], []
    completed = 0
    tasks = [probe(host, port, proxy, sem, idx) for idx, (host, port, proxy) in enumerate(jobs, 1)]
    for task in asyncio.as_completed(tasks):
        idx, host, port, status, detail, result = await task
        completed += 1
        proxy_tag = f" via {jobs[idx - 1][2][0]}"
        row = f"Processo {idx}: {host}:{port} - HTTP/{status} - {detail}{proxy_tag}"
        log.append(row)
        cor = G if status in ("101", "200") else (R if status == "ERRO" else Y)
        if status in ("101", "200"):
            accepted.append(row)
        print(f"\r\033[K{cor}{row}{X}")
        print(f"\rProcessos: {min(CFG['workers'], len(jobs) - completed)} | Enviados: {completed} | Finalizados: {completed}", end="", flush=True)
    print("\n")
    OUT.mkdir(parents=True, exist_ok=True)
    stamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    (OUT / f"host_log_{stamp}.txt").write_text("\n".join(log), encoding="utf-8")
    (OUT / f"host_status_101_200_{stamp}.txt").write_text("\n".join(accepted), encoding="utf-8")
    print(f"Aprovados (101/200): {len(accepted)} de {len(jobs)}")
    print(f"Resultados salvos em: {OUT}")


def configure(choice):
    if choice == "1":
        CFG["target"] = edit_line("HOST", CFG["target"])
    elif choice == "2":
        value = parse_ports()
        if value:
            CFG["ports"] = value
    elif choice == "3" and CFG["ports"] == [443]:
        CFG["sni"] = edit_line("SNI", CFG["sni"])
    elif choice == "4":
        CFG["payload"] = edit_payload()
    elif choice == "5":
        CFG["proxy"] = edit_line("PROXY(s)/IP(s), separados por # ou vírgula. Sem porta = usa a PORTA escolhida", CFG["proxy"])
    elif choice == "7":
        CFG["connect"] = not CFG["connect"]
        print("Modo:", "CONNECT (proxy HTTP, porta padrão 8080)" if CFG["connect"] else "DIRETO (conecta no IP da PROXY na PORTA escolhida)")


def main():
    while True:
        show_panel()
        choice = input("\nComando: ").strip().lower()
        if choice in ("0", "q", "sair"):
            print("Até mais!"); return
        if choice in ("6", "i", "iniciar"):
            try:
                if not CFG["target"]:
                    CFG["target"] = input("HOST: ").strip()
                if not CFG["payload"].strip():
                    CFG["payload"] = edit_payload()
                if not CFG["proxy"].strip():
                    raise ValueError("Configure uma PROXY antes de iniciar o scan.")
                asyncio.run(run_scan())
            except KeyboardInterrupt:
                print("\nScan interrompido.")
            except Exception as exc:
                print(f"\n{R}[ERRO] {exc}{X}")
            input("\nENTER para voltar")
        else:
            configure(choice)
            input("\nENTER para voltar")


if __name__ == "__main__":
    try:
        main()
    except (KeyboardInterrupt, EOFError):
        print("\nEncerrado.")
