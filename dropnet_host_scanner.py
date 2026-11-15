#!/usr/bin/env python3
"""DROPNET HOST SCANNER — testes de conectividade em destinos autorizados."""
import asyncio
import ipaddress
import ssl
from datetime import datetime
from pathlib import Path

OUT = Path.home() / "storage" / "downloads" / "DROPNET-SCANNER"
MAX_CIDR_HOSTS = 4096
TIMEOUT = 6
C = "\033[36m"; G = "\033[32m"; Y = "\033[33m"; R = "\033[31m"; X = "\033[0m"


def ask(label, default=""):
    suffix = f" [{default}]" if default else ""
    value = input(f"{label}{suffix}: ").strip()
    return value or default


def yes_no(label, default="n"):
    return ask(label + " (s/n)", default).lower() in ("s", "sim", "y", "yes")


def add_many(label, first=1):
    values = []
    number = first
    while True:
        value = ask(f"{label} {number} (vazio para encerrar)")
        if value:
            for part in value.replace("#", "\n").replace(",", "\n").splitlines():
                item = part.strip()
                if item and item not in values:
                    values.append(item)
        if not yes_no("Deseja adicionar mais um " + label.lower() + "?", "n"):
            break
        number += 1
    return values


def read_hosts(values):
    result = []
    for value in values:
        item = value.strip()
        item = item.replace("https://", "").replace("http://", "")
        if item:
            item = item.split("/", 1)[0]
            if item not in result:
                result.append(item)
    return result


def expand_cidr(value):
    net = ipaddress.ip_network(value.strip(), strict=False)
    if net.num_addresses > MAX_CIDR_HOSTS:
        raise ValueError(f"Faixa contém {net.num_addresses} endereços; limite {MAX_CIDR_HOSTS}.")
    return [str(ip) for ip in net.hosts()] or [str(net.network_address)]


def parse_proxy(value):
    value = value.strip()
    if ":" not in value:
        raise ValueError("Use proxy no formato IP:PORTA ou HOST:PORTA.")
    host, port = value.rsplit(":", 1)
    port = int(port)
    if not host or not 1 <= port <= 65535:
        raise ValueError("Proxy inválido.")
    return host, port


async def open_target(host, port, proxy, tls, sni):
    if proxy:
        phost, pport = proxy
        reader, writer = await asyncio.wait_for(asyncio.open_connection(phost, pport), TIMEOUT)
        connect = f"CONNECT {host}:{port} HTTP/1.1\r\nHost: {host}:{port}\r\n\r\n"
        writer.write(connect.encode()); await writer.drain()
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
        reader, writer = await asyncio.wait_for(asyncio.open_connection(host, port), TIMEOUT)
    if tls:
        ctx = ssl.create_default_context()
        await writer.start_tls(ctx, server_hostname=sni or host, ssl_handshake_timeout=TIMEOUT)
    return reader, writer


async def check(host, port, mode, sni, payload, proxy, sem):
    async with sem:
        writer = None
        try:
            reader, writer = await open_target(host, port, proxy, mode == "SSL", sni)
            if mode in ("HTTP", "SSL"):
                default_payload = "GET / HTTP/1.1\r\nHost: [host]\r\nConnection: close\r\n\r\n"
                raw = payload.strip() or default_payload
                raw = raw.replace("[host]", host).replace("[HOST]", host)
                raw = raw.replace("\\r", "\r").replace("\\n", "\n")
                writer.write(raw.encode("utf-8", "replace")); await writer.drain()
                try:
                    line = (await asyncio.wait_for(reader.readline(), TIMEOUT)).decode("latin-1", "replace").strip()
                except asyncio.TimeoutError:
                    line = "Conexão estabelecida / sem resposta HTTP"
                status = line.split()[1] if line.startswith("HTTP/") and len(line.split()) > 1 else ("TLS" if mode == "SSL" else "TCP")
            else:
                status, line = "TCP", "Conexão TCP estabelecida"
            return host, port, status, line
        except Exception as exc:
            return host, port, "ERRO", str(exc)[:150]
        finally:
            if writer:
                writer.close()
                try: await writer.wait_closed()
                except Exception: pass


async def run(hosts, targets, snis, payload, proxies, workers):
    jobs = []
    for host_index, host in enumerate(hosts):
        for mode, port in targets:
            sni = snis[host_index % len(snis)] if mode == "SSL" and snis else ""
            proxy = proxies[len(jobs) % len(proxies)] if proxies else None
            jobs.append((host, port, mode, sni, proxy))
    sem = asyncio.Semaphore(workers)
    log, good, other = [], [], []
    print(f"\nProcessos: 0 | Enviados: 0 | Finalizados: 0")
    done = 0
    tasks = [check(h, port, mode, sni, payload, proxy, sem) for h, port, mode, sni, proxy in jobs]
    for task in asyncio.as_completed(tasks):
        host, port, status, detail = await task
        done += 1
        proxy_label = " | Proxy" if proxies else ""
        line = f"{host} | {status}{proxy_label} | {detail}"
        log.append(line)
        if status in ("101", "200", "204", "301", "302", "400", "403", "404", "TLS", "TCP"):
            good.append(line); print(f"{G}[{status}] {host}:{port}{X}")
        else:
            other.append(line); print(f"{R if status == 'ERRO' else Y}[{status}] {host}:{port} - {detail}{X}")
        print(f"\rProcessos: {min(workers, max(0, len(jobs)-done))} | Enviados: {done} | Finalizados: {done}", end="", flush=True)
    print()
    OUT.mkdir(parents=True, exist_ok=True)
    stamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    for suffix, rows in (("log", log), ("ok", good), ("erros", other)):
        (OUT / f"dropnet_host_{suffix}_{stamp}.txt").write_text("\n".join(rows), encoding="utf-8")
    print(f"Resultados salvos em: {OUT}")


def main():
    print(f"{C}========== DROPNET HOST SCANNER =========={X}")
    print("Use somente destinos e proxies que você tem autorização para testar.\n")
    print("TIPO DE CONEXÃO")
    print("1) HTTP NORMAL — porta 80")
    print("2) SSL/TLS — porta 443 + SNI")
    print("3) PERSONALIZADA — escolher HTTP, SSL ou os dois")
    choice = ask("Escolha", "2")
    if choice == "1": targets = [("HTTP", 80)]
    elif choice == "2": targets = [("SSL", 443)]
    elif choice == "3":
        print("\nPERSONALIZADA")
        print("1) Somente HTTP — porta 80")
        print("2) Somente SSL — porta 443")
        print("3) HTTP + SSL — portas 80 e 443")
        print("4) Informar outra porta")
        custom = ask("Escolha", "3")
        if custom == "1": targets = [("HTTP", 80)]
        elif custom == "2": targets = [("SSL", 443)]
        elif custom == "3": targets = [("HTTP", 80), ("SSL", 443)]
        elif custom == "4":
            try: custom_port = int(ask("Porta personalizada"))
            except ValueError: print("Porta inválida."); input("Enter para voltar..."); return
            if not 1 <= custom_port <= 65535: print("Porta inválida."); input("Enter para voltar..."); return
            use_tls = yes_no("Usar SSL/TLS nessa porta?", "s")
            targets = [("SSL" if use_tls else "HTTP", custom_port)]
        else:
            print("Opção inválida."); input("Enter para voltar..."); return
    else:
        print("Opção inválida."); input("Enter para voltar..."); return
    needs_ssl = any(mode == "SSL" for mode, _ in targets)

    print("\nHOSTS — adicione um por vez; responda N para avançar.")
    hosts = read_hosts(add_many("Host"))
    if yes_no("Deseja adicionar uma faixa CIDR (ex.: 10.10.10.0/24)?", "n"):
        try: hosts += [h for h in expand_cidr(ask("Rede CIDR")) if h not in hosts]
        except ValueError as exc: print(f"CIDR inválido: {exc}"); input("Enter para voltar..."); return
    if not hosts: print("Nenhum host informado."); input("Enter para voltar..."); return

    snis = []
    if needs_ssl:
        if yes_no("Deseja informar SNI?", "s"):
            snis = add_many("SNI")
    print("\nPROXIES — formato IP:PORTA ou HOST:PORTA; pode usar #, vírgula ou linhas.")
    proxies = []
    if yes_no("Deseja usar proxy?", "n"):
        raw_proxies = add_many("Proxy")
        try: proxies = [parse_proxy(p) for p in raw_proxies]
        except ValueError as exc: print(f"Proxy inválido: {exc}"); input("Enter para voltar..."); return
    payload = ask("Payload HTTP (Enter = GET padrão)", "")
    try: workers = max(1, min(100, int(ask("Processos simultâneos", "30"))))
    except ValueError: workers = 30
    print("\n========== CONFIRMAÇÃO ==========")
    print(f"Tipo: {mode} | Porta: {port} | Hosts: {len(hosts)}")
    print(f"SNI: {', '.join(snis) if snis else ('automático por host' if mode == 'SSL' else 'não aplicável')}")
    print(f"Proxies: {len(proxies)} | Processos: {workers}")
    input("Pressione Enter para iniciar...")
    try: asyncio.run(run(hosts, targets, snis, payload, proxies, workers))
    except KeyboardInterrupt: print("\nVerificação interrompida.")
    input("\nEnter para voltar ao menu...")


if __name__ == "__main__":
    main()
