#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""DROPNET HOST SCANNER - painel simples para testes em hosts autorizados."""
import asyncio
import os
import re
import ssl
from datetime import datetime
from pathlib import Path

OUT = Path.home() / "storage" / "downloads" / "DROPNET-SCANNER"
TIMEOUT = 8
C = "\033[96m"; G = "\033[92m"; Y = "\033[93m"; R = "\033[91m"; W = "\033[97m"; D = "\033[90m"; X = "\033[0m"

CFG = {
    "host": "",
    "port": 443,
    "sni": "",
    "payload": "",
    "reg": True,  # REG = rede direta do aparelho; sem proxy.
}


def clear():
    os.system("clear" if os.name == "posix" else "cls")


def header():
    clear()
    print(C + "╔══════════════════════════════════╗")
    print("║       DROPNET HOST SCANNER       ║")
    print("╚══════════════════════════════════╝" + X)
    print(D + " Testes somente em hosts autorizados" + X)


def short(value, limit=34):
    value = str(value).replace("\n", " ")
    return value if len(value) <= limit else value[:limit - 3] + "..."


def show_panel():
    header()
    print(f"\n{C}========== CONFIGURAÇÃO =========={X}")
    print(f"{W}HOST    :{X} {short(CFG['host'] or '(não definido)')}")
    print(f"{W}PORTA   :{X} {CFG['port']}")
    if CFG["port"] == 443:
        print(f"{W}SNI     :{X} {short(CFG['sni'] or '(não definido)')}")
    else:
        print(f"{W}SNI     :{X} {D}desligado na porta 80{X}")
    print(f"{W}PAYLOAD :{X} {'configurada' if CFG['payload'].strip() else '(não definida)'}")
    print(f"{W}REG     :{X} {G}REDE DIRETA{X}")
    print(f"\n{C}============= MENU ==============={X}")
    print("[1] HOST")
    print("[2] PORTA (80 ou 443)")
    if CFG["port"] == 443:
        print("[3] SNI")
    print("[4] PAYLOAD")
    print(G + "[5] ▶ INICIAR SCAN" + X)
    print(R + "[0] SAIR" + X)


def ask_value(label, current=""):
    value = input(f"{label}: ").strip()
    return value if value else current


def edit_payload():
    print("\nCole a payload em uma linha e aperte ENTER para salvar.")
    print("Marcadores aceitos: [host], [crlf], [lf], [method].")
    try:
        value = input("PAYLOAD: ")
    except (EOFError, KeyboardInterrupt):
        return CFG["payload"]
    return value.strip() if value.strip() else CFG["payload"]


def configure(choice):
    if choice == "1":
        CFG["host"] = ask_value("HOST", CFG["host"])
        CFG["host"] = CFG["host"].replace("https://", "").replace("http://", "").split("/", 1)[0]
    elif choice == "2":
        value = input("PORTA (80 ou 443): ").strip()
        if value in ("80", "443"):
            CFG["port"] = int(value)
            if CFG["port"] == 80:
                print("SNI desligado automaticamente na porta 80.")
            else:
                print("SNI ativado automaticamente na porta 443.")
        else:
            print("Escolha somente 80 ou 443.")
    elif choice == "3" and CFG["port"] == 443:
        CFG["sni"] = ask_value("SNI", CFG["sni"])
    elif choice == "4":
        CFG["payload"] = edit_payload()


def build_payload(host):
    payload = CFG["payload"]
    payload = payload.replace("[host]", host).replace("[HOST]", host)
    payload = payload.replace("[method]", "GET")
    payload = payload.replace("[crlf]", "\r\n").replace("[lf]", "\n")
    payload = payload.replace("\\r", "\r").replace("\\n", "\n")
    return payload


async def test_host(host):
    writer = None
    try:
        tls = CFG["port"] == 443
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(host, CFG["port"]), TIMEOUT
        )
        if tls:
            context = ssl.create_default_context()
            await asyncio.wait_for(
                writer.start_tls(
                    context,
                    server_hostname=(CFG["sni"].strip() or host),
                    ssl_handshake_timeout=TIMEOUT,
                ), TIMEOUT + 1
            )
        payload = build_payload(host)
        if payload:
            writer.write(payload.encode("utf-8", "replace"))
            await writer.drain()
        lines = []
        try:
            while len(lines) < 12:
                raw = await asyncio.wait_for(reader.readline(), 2 if lines else TIMEOUT)
                if not raw:
                    break
                line = raw.decode("latin-1", "replace").strip()
                if line:
                    lines.append(line)
        except asyncio.TimeoutError:
            pass
        statuses = [line for line in lines if re.match(r"^HTTP/\S+\s+\d{3}", line)]
        if statuses:
            status = statuses[0].split()[1]
            detail = " | ".join(statuses)
        else:
            status = "TCP/TLS"
            detail = " | ".join(lines) if lines else "Conexão estabelecida; sem resposta HTTP"
        return status, detail, "OK"
    except Exception as exc:
        return "ERRO", str(exc)[:180], "ERRO"
    finally:
        if writer:
            writer.close()
            try:
                await writer.wait_closed()
            except Exception:
                pass


async def run_scan():
    host = CFG["host"].strip()
    if not host:
        raise ValueError("Informe o HOST antes de iniciar.")
    if CFG["port"] == 443 and not CFG["sni"].strip():
        # SNI automático: se o usuário não informar um SNI separado, usa o próprio HOST.
        CFG["sni"] = host
    if not CFG["payload"].strip():
        raise ValueError("Informe a PAYLOAD antes de iniciar.")

    print(f"\n{C}DROPNET - INICIANDO{X}")
    print(f"HOST: {host} | PORTA: {CFG['port']} | MODO: REG / REDE DIRETA")
    if CFG["port"] == 443:
        print(f"SNI: {CFG['sni']}")
    status, detail, result = await test_host(host)
    line = f"{host}:{CFG['port']} - {status} - {detail}"
    print((G if result == "OK" else R) + line + X)
    OUT.mkdir(parents=True, exist_ok=True)
    stamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    (OUT / f"host_log_{stamp}.txt").write_text(line + "\n", encoding="utf-8")
    print(f"\nResultado salvo em: {OUT}")


def main():
    while True:
        show_panel()
        choice = input("\nEscolha: ").strip().lower()
        if choice in ("0", "q", "sair"):
            print("Até mais!")
            return
        if choice == "5":
            try:
                asyncio.run(run_scan())
            except KeyboardInterrupt:
                print("\nScan interrompido.")
            except Exception as exc:
                print(f"\n{R}[ERRO] {exc}{X}")
            input("\nENTER para voltar ao menu")
        else:
            configure(choice)
            input("\nENTER para voltar ao menu")


if __name__ == "__main__":
    try:
        main()
    except (KeyboardInterrupt, EOFError):
        print("\nEncerrado.")
