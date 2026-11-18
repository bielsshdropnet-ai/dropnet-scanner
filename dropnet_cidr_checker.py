#!/usr/bin/env python3
# DROPNET SCANNER 3 — diagnóstico de conectividade HTTP/TLS
# Varre uma faixa autorizada e registra respostas HTTP por IP.
# Não envia payloads de túnel nem tenta estabelecer/descobrir proxies.

import ipaddress
import socket
import ssl
from concurrent.futures import ThreadPoolExecutor, as_completed

MAX_IPS = 256
TIMEOUT = 3
WORKERS = 20

def read_cidr():
    while True:
        raw = input("CIDR da rede que você administra/tem autorização para testar: ").strip()
        try:
            net = ipaddress.ip_network(raw, strict=False)
            if net.version != 4:
                print("[ERRO] Informe IPv4.")
                continue
            if net.num_addresses > MAX_IPS:
                print(f"[ERRO] A faixa tem {net.num_addresses} IPs. Limite desta versão: {MAX_IPS}.")
                continue
            return net
        except ValueError:
            print("[ERRO] CIDR inválido. Exemplo: 192.168.1.0/24")

def probe(ip, port, sni):
    """Envia somente HEAD / e devolve status HTTP ou erro de conexão."""
    sock = None
    try:
        sock = socket.create_connection((str(ip), port), timeout=TIMEOUT)
        sock.settimeout(TIMEOUT)

        if port == 443:
            context = ssl.create_default_context()
            # O SNI é usado no handshake TLS; a validação do certificado permanece ativa.
            server_name = sni.strip() if sni.strip() else str(ip)
            sock = context.wrap_socket(sock, server_hostname=server_name)

        host_header = sni.strip() if (port == 443 and sni.strip()) else str(ip)
        request = (
            f"HEAD / HTTP/1.1\r\n"
            f"Host: {host_header}\r\n"
            f"User-Agent: DROPNET-Authorized-Diagnostic/1.0\r\n"
            f"Connection: close\r\n\r\n"
        )
        sock.sendall(request.encode("ascii", errors="ignore"))

        data = b""
        while b"\r\n" not in data and len(data) < 4096:
            chunk = sock.recv(512)
            if not chunk:
                break
            data += chunk

        first_line = data.split(b"\r\n", 1)[0].decode("latin-1", errors="replace")
        parts = first_line.split()
        if len(parts) >= 2 and parts[0].startswith("HTTP/"):
            return ("HTTP", parts[1], first_line)
        return ("TCP", "CONECTOU_SEM_STATUS_HTTP", first_line or "Conexão aberta; sem resposta HTTP")
    except ssl.SSLCertVerificationError as exc:
        return ("TLS", "CERTIFICADO_INVALIDO", str(exc))
    except ssl.SSLError as exc:
        return ("TLS", "ERRO_TLS", str(exc))
    except (socket.timeout, TimeoutError):
        return ("ERRO", "TIMEOUT", "Tempo limite excedido")
    except ConnectionRefusedError:
        return ("ERRO", "RECUSADO", "Conexão recusada")
    except OSError as exc:
        return ("ERRO", "SEM_CONEXAO", str(exc))
    finally:
        if sock:
            try:
                sock.close()
            except OSError:
                pass

def main():
    print("=" * 62)
    print("DROPNET SCANNER 3 — DIAGNÓSTICO HTTP/TLS POR CIDR")
    print("Testa conectividade; não verifica payloads nem proxies.")
    print(f"Limite: {MAX_IPS} endereços | concorrência: {WORKERS}")
    print("=" * 62)

    network = read_cidr()

    print("\nModo:")
    print("1) HTTP / porta 80")
    print("2) HTTPS-TLS / porta 443")
    while True:
        choice = input("Escolha 1 ou 2: ").strip()
        if choice in ("1", "2"):
            break
        print("[ERRO] Escolha 1 ou 2.")
    port = 80 if choice == "1" else 443
    sni = input("SNI (somente para 443; Enter para usar o IP): ").strip() if port == 443 else ""

    print(f"\nCIDR: {network}")
    print(f"Total: {network.num_addresses} endereços")
    print(f"Teste: {'HTTP' if port == 80 else 'HTTPS/TLS'} na porta {port}")
    print("Será enviada uma requisição HTTP HEAD / por endereço.")
    print("Use somente redes e serviços sob sua administração ou autorização.")
    if input("Digite INICIAR para executar: ").strip().upper() != "INICIAR":
        print("Cancelado.")
        return

    ips = list(network)
    print("\n[LOG] Iniciando testes...\n", flush=True)

    counts = {}
    completed = 0
    with ThreadPoolExecutor(max_workers=WORKERS) as pool:
        jobs = {pool.submit(probe, ip, port, sni): ip for ip in ips}
        for future in as_completed(jobs):
            ip = jobs[future]
            try:
                kind, code, detail = future.result()
            except Exception as exc:
                kind, code, detail = "ERRO", "FALHA_INTERNA", str(exc)

            completed += 1
            counts[code] = counts.get(code, 0) + 1

            if kind == "HTTP":
                print(f"[HTTP {code}] {ip}:{port} — {detail}", flush=True)
            elif kind == "TCP":
                print(f"[TCP ABERTO] {ip}:{port} — {detail}", flush=True)
            else:
                print(f"[{code}] {ip}:{port} — {detail}", flush=True)

            if completed % 10 == 0 or completed == len(ips):
                print(f"--- Progresso: {completed}/{len(ips)} ---", flush=True)

    print("\n" + "=" * 62)
    print("RESUMO")
    for code, total in sorted(counts.items()):
        print(f"{code}: {total}")
    print(f"Total testado: {completed}")
    print("Fim do diagnóstico. HTTP 403 é acesso negado; 101 é upgrade; 200 é OK.")
    print("Nenhum desses códigos, isoladamente, confirma que um proxy/túnel funciona.")
    input("\nPressione Enter para sair...")

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n[INFO] Varredura interrompida.")
