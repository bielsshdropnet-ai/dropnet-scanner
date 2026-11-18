#!/usr/bin/env python3
# DROPNET SCANNER 3 — diagnóstico HTTP/TLS por CIDR (versão organizada)

import ipaddress
import socket
import ssl
from concurrent.futures import ThreadPoolExecutor, as_completed

MAX_IPS = 65536  # limite prático (/16); aumente se quiser
TIMEOUT = 3
WORKERS = 20


# ---------- entrada ----------
def ask_cidr():
    while True:
        raw = input("IP ou CIDR: ").strip()
        try:
            net = ipaddress.ip_network(raw, strict=False)
        except ValueError:
            print("[ERRO] CIDR inválido. Ex: 192.168.1.0/24")
            continue
        if net.version != 4:
            print("[ERRO] Somente IPv4.")
        elif net.num_addresses > MAX_IPS:
            print(f"[ERRO] {net.num_addresses} IPs. Limite: {MAX_IPS}.")
        else:
            return net


def ask_ids(total):
    """Devolve (inicio, fim) dos IDs a testar. Enter = todos."""
    while True:
        raw = input(f"IDs a testar (1-{total}, ex: 10-50 ou 7; Enter = todos): ").strip()
        if not raw:
            return 1, total
        try:
            a, _, b = raw.partition("-")
            start, end = int(a), int(b or a)
            if 1 <= start <= end <= total:
                return start, end
        except ValueError:
            pass
        print("[ERRO] Intervalo inválido.")


def ask_options():
    port = 443 if input("Porta (1 = 80 | 2 = 443): ").strip() == "2" else 80
    host = input("SNI/Host (Enter = usar o IP): ").strip()
    print("Payload (use [host] e \\r\\n):")
    payload = ""
    while not payload:
        payload = input("> ").strip()
    return port, host, payload


# ---------- teste ----------
def probe(ip, port, host, payload):
    """Conecta, envia o payload e devolve (tipo, código, detalhe)."""
    sock = None
    try:
        sock = socket.create_connection((str(ip), port), timeout=TIMEOUT)
        sock.settimeout(TIMEOUT)
        name = host or str(ip)
        if port == 443:
            sock = ssl.create_default_context().wrap_socket(sock, server_hostname=name)

        data = payload.replace("[host]", name).replace("\\r\\n", "\r\n")
        sock.sendall(data.encode("ascii", errors="ignore"))

        resp = b""
        while b"\r\n" not in resp and len(resp) < 4096:
            chunk = sock.recv(512)
            if not chunk:
                break
            resp += chunk

        line = resp.split(b"\r\n", 1)[0].decode("latin-1", errors="replace")
        parts = line.split()
        if len(parts) >= 2 and parts[0].startswith("HTTP/"):
            return "HTTP", parts[1], line
        return "TCP", "SEM_STATUS_HTTP", line or "Conexão aberta, sem resposta HTTP"
    except ssl.SSLCertVerificationError as e:
        return "ERRO", "CERT_INVALIDO", str(e)
    except ssl.SSLError as e:
        return "ERRO", "ERRO_TLS", str(e)
    except (socket.timeout, TimeoutError):
        return "ERRO", "TIMEOUT", "Tempo limite excedido"
    except ConnectionRefusedError:
        return "ERRO", "RECUSADO", "Conexão recusada"
    except OSError as e:
        return "ERRO", "SEM_CONEXAO", str(e)
    finally:
        if sock:
            try:
                sock.close()
            except OSError:
                pass


# ---------- principal ----------
def main():
    print("=" * 60)
    print("DROPNET SCANNER 3 — HTTP/TLS POR CIDR")
    print("=" * 60)

    net = ask_cidr()
    ips = list(net)
    start, end = ask_ids(len(ips))
    port, host, payload = ask_options()

    targets = [(i, ips[i - 1]) for i in range(start, end + 1)]
    print(f"\nCIDR {net} | IDs {start}-{end} ({len(targets)} alvos) | porta {port}")
    input("Enter para iniciar...")

    counts, hits, done = {}, [], 0
    with ThreadPoolExecutor(max_workers=WORKERS) as pool:
        jobs = {pool.submit(probe, ip, port, host, payload): (i, ip) for i, ip in targets}
        for fut in as_completed(jobs):
            i, ip = jobs[fut]
            try:
                kind, code, detail = fut.result()
            except Exception as e:
                kind, code, detail = "ERRO", "FALHA_INTERNA", str(e)

            done += 1
            counts[code] = counts.get(code, 0) + 1
            if kind == "HTTP":
                hits.append((i, ip, code, detail))
            print(f"[{i:>3}] {ip}:{port} {code}", flush=True)
            if done % 10 == 0 or done == len(targets):
                print(f"--- {done}/{len(targets)} ---", flush=True)

    # resultados que responderam ficam no final, ordenados por ID
    print("\n" + "=" * 60)
    print(f"RESPONDERAM ({len(hits)})")
    for i, ip, code, detail in sorted(hits):
        print(f"[ID {i}] {ip}:{port} -> {detail}")
    if not hits:
        print("Nenhum respondeu com HTTP.")

    print("\nRESUMO")
    for code, total in sorted(counts.items()):
        print(f"  {code}: {total}")
    input("\nEnter para sair...")


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n[INFO] Interrompido.")
