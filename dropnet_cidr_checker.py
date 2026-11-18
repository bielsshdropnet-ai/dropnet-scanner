#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""DROPNET CIDR CHECKER — diagnóstico HTTP em redes privadas/autorizadas."""
import asyncio
import ipaddress
import os
import socket
import ssl
from datetime import datetime
from pathlib import Path

OUT = Path.home() / "storage" / "downloads" / "DROPNET-SCANNER"
TIMEOUT = 4
MAX_ADDRESSES = 256
WORKERS = 5
PORTS = (80, 443)


def clear():
    os.system("clear" if os.name == "posix" else "cls")


def parse_network(raw):
    try:
        net = ipaddress.ip_network(raw.strip(), strict=False)
    except ValueError as exc:
        raise ValueError("CIDR inválido. Exemplo: 192.168.1.0/24") from exc
    if net.version != 4:
        raise ValueError("Somente IPv4 é aceito.")
    if not net.is_private or net.is_global:
        raise ValueError("Por segurança, este módulo aceita somente redes privadas (RFC1918) sob sua administração.")
    if net.num_addresses > MAX_ADDRESSES:
        raise ValueError(f"Limite de {MAX_ADDRESSES} endereços por execução (/24 no máximo).")
    return [str(ip) for ip in net.hosts()]


async def probe(ip, port, hostname, sem):
    async with sem:
        writer = None
        started = asyncio.get_running_loop().time()
        try:
            ctx = ssl.create_default_context()
            if port == 443:
                reader, writer = await asyncio.wait_for(
                    asyncio.open_connection(ip, port, ssl=ctx, server_hostname=hostname), TIMEOUT
                )
            else:
                reader, writer = await asyncio.wait_for(asyncio.open_connection(ip, port), TIMEOUT)
            request = (f"GET / HTTP/1.1\r\nHost: {hostname}\r\n"
                       "User-Agent: DROPNET-CIDR-CHECKER/1.0\r\n"
                       "Connection: close\r\n\r\n")
            writer.write(request.encode("ascii", errors="ignore"))
            await writer.drain()
            line = await asyncio.wait_for(reader.readline(), TIMEOUT)
            status = line.decode("latin-1", errors="replace").strip()
            elapsed = int((asyncio.get_running_loop().time() - started) * 1000)
            if status.startswith("HTTP/"):
                parts = status.split(" ", 2)
                code = parts[1] if len(parts) > 1 else "?"
                reason = parts[2] if len(parts) > 2 else ""
                return (ip, port, code, reason, elapsed)
            return (ip, port, "SEM_HTTP", "resposta não reconhecida", elapsed)
        except Exception as exc:
            elapsed = int((asyncio.get_running_loop().time() - started) * 1000)
            return (ip, port, "ERRO", str(exc)[:90], elapsed)
        finally:
            if writer:
                writer.close()
                try:
                    await writer.wait_closed()
                except Exception:
                    pass


async def run_scan(network, hostname):
    sem = asyncio.Semaphore(WORKERS)
    jobs = [probe(ip, port, hostname, sem) for ip in network for port in PORTS]
    results = []
    total = len(jobs)
    for index, task in enumerate(asyncio.as_completed(jobs), 1):
        result = await task
        results.append(result)
        ip, port, code, reason, elapsed = result
        print(f"[{index}/{total}] {ip}:{port}  {code} {reason}  {elapsed}ms")
    return results


def main():
    clear()
    print("╔════════════════════════════════════════════╗")
    print("║          DROPNET CIDR CHECKER              ║")
    print("╚════════════════════════════════════════════╝")
    print("Diagnóstico HTTP simples — rede privada/autorizada")
    try:
        raw = input("CIDR da sua rede (ex.: 192.168.1.0/24): ").strip()
        network = parse_network(raw)
        hostname = input("Host/domínio do seu serviço: ").strip()
        if not hostname or any(c in hostname for c in " /\\\t\r\n"):
            raise ValueError("Informe um hostname válido, sem esquema ou caminho.")
        print(f"\nAlvos: {len(network)} IPs | Portas: 80 e 443 | Concorrência: {WORKERS}")
        print("Iniciando somente após confirmar que você administra/tem autorização para esta rede.")
        if input("Confirmar? [s/N]: ").strip().lower() != "s":
            print("Cancelado.")
            return
        results = asyncio.run(run_scan(network, hostname))
        OUT.mkdir(parents=True, exist_ok=True)
        path = OUT / f"dropnet_cidr_{datetime.now():%Y%m%d_%H%M%S}.txt"
        with path.open("w", encoding="utf-8") as f:
            f.write(f"DROPNET CIDR CHECKER\nCIDR: {raw}\nHost: {hostname}\n\n")
            for ip, port, code, reason, elapsed in sorted(results):
                f.write(f"{ip}:{port} HTTP={code} {reason} {elapsed}ms\n")
        print(f"\nConcluído. Relatório: {path}")
    except KeyboardInterrupt:
        print("\nInterrompido.")
    except ValueError as exc:
        print(f"\n[ERRO] {exc}")
    input("\nPressione Enter para voltar...")


if __name__ == "__main__":
    main()
