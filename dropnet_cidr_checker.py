#!/usr/bin/env python3
# DROPNET - módulo 3: diagnóstico HTTP/TLS de CIDR autorizado.
# Não estabelece túneis, não encaminha payloads e não valida proxies de terceiros.

import ipaddress
import socket
import ssl
import urllib.error
import urllib.request

MAX_IPS = 256
TIMEOUT = 3

def ask_cidr():
    while True:
        value = input("CIDR IPv4 autorizado: ").strip()
        try:
            network = ipaddress.ip_network(value, strict=False)
            if network.version != 4:
                print("[ERRO] Informe um CIDR IPv4.")
                continue
            if network.num_addresses > MAX_IPS:
                print(f"[ERRO] Limite de {MAX_IPS} endereços por execução.")
                continue
            return network
        except ValueError:
            print("[ERRO] CIDR inválido. Exemplo: 192.168.1.0/24")

def http_check(ip, port, sni):
    scheme = "https" if port == 443 else "http"
    host = sni.strip() if sni.strip() else str(ip)
    url = f"{scheme}://{ip}:{port}/"
    request = urllib.request.Request(
        url, method="HEAD",
        headers={"Host": host, "User-Agent": "DROPNET-Authorized-Diagnostic/1.0"}
    )
    context = ssl.create_default_context()
    if scheme == "https":
        # SNI/certificado são verificados usando o nome informado.
        opener = urllib.request.build_opener(
            urllib.request.HTTPSHandler(context=context)
        )
    else:
        opener = urllib.request.build_opener()
    try:
        with opener.open(request, timeout=TIMEOUT) as response:
            return response.status
    except urllib.error.HTTPError as exc:
        return exc.code
    except (urllib.error.URLError, TimeoutError, socket.timeout,
            ssl.SSLError, OSError, ValueError):
        return None

def main():
    print("=" * 56)
    print("DROPNET - OPÇÃO 3: CIDR HTTP/TLS DIAGNOSTIC")
    print("Somente redes/equipamentos sob sua administração ou autorização.")
    print("=" * 56)

    user_id = input("Seu ID: ").strip()
    if not user_id:
        print("[ERRO] ID não pode ficar vazio.")
        return

    network = ask_cidr()
    print("\nTipo de teste:")
    print("1) HTTP - porta 80")
    print("2) HTTPS/TLS - porta 443")
    choice = input("Escolha: ").strip()
    if choice not in ("1", "2"):
        print("[ERRO] Escolha inválida.")
        return
    port = 80 if choice == "1" else 443

    sni = ""
    if port == 443:
        sni = input("SNI (nome DNS do seu serviço; vazio para usar o IP): ").strip()

    print(f"\nID: {user_id}")
    print(f"Faixa: {network} ({network.num_addresses} endereços)")
    print(f"Teste: {'HTTP' if port == 80 else 'HTTPS/TLS'} / porta {port}")
    print("Será enviada somente uma requisição HEAD para /.")
    print("Este teste não envia payload de túnel nem confirma proxy funcional.")
    if input("Digite SIM para iniciar: ").strip().upper() != "SIM":
        print("Cancelado.")
        return

    print("\nIniciando...\n")
    answered = 0
    for ip in network:
        status = http_check(ip, port, sni)
        if status is None:
            print(f"[SEM RESPOSTA] {ip}:{port}")
        else:
            answered += 1
            if status == 403:
                meaning = "HTTP respondeu; acesso negado"
            elif status == 101:
                meaning = "HTTP respondeu; Switching Protocols"
            elif status == 200:
                meaning = "HTTP respondeu; OK"
            else:
                meaning = "resposta HTTP recebida"
            print(f"[RESPOSTA] {ip}:{port} — HTTP {status} — {meaning}")

    print(f"\nConcluído. Endereços com resposta HTTP: {answered}/{network.num_addresses}")

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\nInterrompido.")
