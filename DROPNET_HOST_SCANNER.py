#!/usr/bin/env python3
"""DROPNET HOST SCANNER — testes de conectividade em destinos autorizados."""
import asyncio
import ipaddress
import ssl
import sys
from datetime import datetime
from pathlib import Path

OUT = Path.home() / "storage" / "downloads" / "DROPNET-SCANNER"
MAX_CIDR_HOSTS = 4096
TIMEOUT = 6
C = "\033[36m"; G = "\033[32m"; Y = "\033[33m"; R = "\033[31m"; X = "\033[0m"


def read_payload():
    print("PAYLOAD (cole sua payload; digite FIM em uma linha para terminar):")
    lines = []
    while True:
        try:
            line = input()
        except EOFError:
            break
        if line.strip().upper() == "FIM":
            break
        lines.append(line)
    return "\n".join(lines).strip()


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


def parse_proxy(value, default_port):
    value = value.strip()
    if ":" in value:
        host, port_text = value.rsplit(":", 1)
        port = int(port_text)
    else:
        host, port = value, default_port
    if not host or not 1 <= port <= 65535:
        raise ValueError("Proxy inválido.")
    return host, port


async def probe_proxy(ip, proxy_port, target, target_port):
    """Confere proxy HTTP CONNECT na rede local autorizada."""
    writer = None
    try:
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(ip, proxy_port), TIMEOUT
        )
        if proxy_port == 443:
            ctx = ssl.create_default_context()
            await writer.start_tls(ctx, server_hostname=ip, ssl_handshake_timeout=TIMEOUT)
        request = f"CONNECT {target}:{target_port} HTTP/1.1\r\nHost: {target}:{target_port}\r\n\r\n"
        writer.write(request.encode()); await writer.drain()
        response = await asyncio.wait_for(reader.readline(), TIMEOUT)
        return b" 200 " in response
    except Exception:
        return False
    finally:
        if writer:
            writer.close()
            try: await writer.wait_closed()
            except Exception: pass


async def find_proxies(cidr, target, targets):
    ips = expand_cidr(cidr)
    found = []
    sem = asyncio.Semaphore(100)
    async def one(ip, port):
        async with sem:
            if await probe_proxy(ip, port, target, targets[0][1]):
                found.append((ip, port))
                print(f"{G}[PROXY] {ip}:{port}{X}")
    jobs = [one(ip, port) for ip in ips for _, port in targets]
    await asyncio.gather(*jobs)
    return list(dict.fromkeys(found))


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
                raw = raw.replace("[crlf]", "\r\n").replace("[lf]", "\n")
                raw = raw.replace("[method]", "GET")
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
    print(f"{C}========== DROPNET HOST SCANNER =========={X}\n")
    print("1) PORTA 80\n2) PORTA 443\n3) PORTA 80 E 443")
    choice = ask("PORTA", "3")
    if choice == "1": targets = [("HTTP", 80)]
    elif choice == "2": targets = [("SSL", 443)]
    elif choice == "3": targets = [("HTTP", 80), ("SSL", 443)]
    else:
        print("Opção inválida."); return

    payload = read_payload()
    if not payload:
        print("Payload vazia. Scan cancelado."); return

    hosts = read_hosts(add_many("HOST"))
    if not hosts:
        print("Nenhum host informado."); return

    snis = []
    if any(mode == "SSL" for mode, _ in targets):
        snis = add_many("SNI")

    print("\n1) PROXY\n2) REDE DIRETA")
    route = ask("ESCOLHA", "1")
    proxies = []
    if route == "1":
        print("\n1) INFORMAR PROXY\n2) PROCURAR PROXY NA REDE")
        proxy_mode = ask("PROXY", "2")
        if proxy_mode == "1":
            print("Digite IP ou HOST. Porta padrão: " + "/".join(str(p) for _, p in targets))
            raw = add_many("PROXY")
            try:
                for item in raw:
                    if ":" in item:
                        proxies.append(parse_proxy(item, targets[0][1]))
                    else:
                        proxies.extend((item, port) for _, port in targets)
            except ValueError as exc:
                print(f"Proxy inválida: {exc}"); return
        elif proxy_mode == "2":
            cidr = ask("RANGE IP (ex.: 192.168.1.0/24)")
            try:
                # Limita a busca a redes privadas e até 4096 endereços.
                net = ipaddress.ip_network(cidr, strict=False)
                if not net.is_private:
                    raise ValueError("Use uma faixa privada da sua própria rede.")
                print("Procurando proxy...")
                proxies = asyncio.run(find_proxies(cidr, hosts[0], targets))
            except ValueError as exc:
                print(f"RANGE inválido: {exc}"); return
            if not proxies:
                print("Nenhuma proxy CONNECT encontrada nessa faixa."); return
        else:
            print("Opção inválida."); return
    elif route != "2":
        print("Opção inválida."); return

    try: workers = max(1, min(100, int(ask("PROCESSOS", "30"))))
    except ValueError: workers = 30
    print("\n========== SCAN ==========")
    print(f"Portas: {', '.join(str(p) for _, p in targets)}")
    print(f"Hosts: {len(hosts)} | SNI: {len(snis)} | Proxies: {len(proxies)}")
    input("ENTER PARA INICIAR")
    try: asyncio.run(run(hosts, targets, snis, payload, proxies, workers))
    except KeyboardInterrupt: print("\nScan interrompido.")
    input("\nENTER PARA VOLTAR")

if __name__ == "__main__":
    main()
