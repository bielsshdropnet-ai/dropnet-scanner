#!/usr/bin/env python3
# Diagnóstico HTTP simples para redes IPv4 autorizadas.
# Aceita CIDRs públicos ou privados, mas limita a execução a 256 endereços.

import ipaddress
import socket
import ssl
import urllib.error
import urllib.request

MAX_HOSTS = 256
TIMEOUT = 3

def read_network():
    while True:
        raw = input("CIDR IPv4 autorizado (ex.: 108.158.186.0/24): ").strip()
        try:
            net = ipaddress.ip_network(raw, strict=False)
            if net.version != 4:
                print("[ERRO] Informe uma rede IPv4.")
                continue
            if net.num_addresses > MAX_HOSTS:
                print(f"[ERRO] Essa rede contém {net.num_addresses} endereços.")
                print(f"Por segurança, este teste está limitado a {MAX_HOSTS} endereços.")
                print("Informe uma faixa menor, por exemplo /24 ou mais específica.")
                continue
            return net
        except ValueError:
            print("[ERRO] CIDR inválido. Exemplo: 192.168.1.0/24")

def check_http(ip, scheme):
    url = f"{scheme}://{ip}/"
    request = urllib.request.Request(
        url,
        method="HEAD",
        headers={"User-Agent": "Dropnet-Authorized-Diagnostic/1.0"}
    )
    context = ssl.create_default_context()
    opener = urllib.request.build_opener(
        urllib.request.HTTPSHandler(context=context)
    )
    try:
        with opener.open(request, timeout=TIMEOUT) as response:
            return response.status
    except urllib.error.HTTPError as exc:
        # Um HTTP 403/404/500 também confirma que houve resposta HTTP.
        return exc.code
    except (urllib.error.URLError, TimeoutError, socket.timeout, ssl.SSLError, OSError):
        return None

def main():
    print("=" * 55)
    print("DIAGNÓSTICO HTTP — REDES IPv4 AUTORIZADAS")
    print("Aceita endereços públicos e privados; limite: 256 IPs.")
    print("=" * 55)

    net = read_network()
    print(f"\nRede interpretada: {net}")
    print(f"Quantidade de endereços: {net.num_addresses}")
    print("\nATENÇÃO: só prossiga se você administra essa rede ou")
    print("tem autorização explícita para testar todos esses IPs.")
    confirm = input("Digite AUTORIZO para iniciar: ").strip()
    if confirm != "AUTORIZO":
        print("Teste cancelado.")
        return

    print("\nIniciando diagnóstico HTTP (porta 80 e 443)...")
    print("O teste envia apenas requisições HEAD à raiz (/).\n")

    found = 0
    for number, ip in enumerate(net, start=1):
        address = str(ip)
        results = []
        for scheme in ("http", "https"):
            status = check_http(address, scheme)
            if status is not None:
                results.append(f"{scheme.upper()} {status}")
                found += 1
        if results:
            print(f"[RESPOSTA] {address} — " + " | ".join(results))
        else:
            print(f"[SEM RESPOSTA] {address}")
    print(f"\nFinalizado. Respostas HTTP recebidas: {found}")

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\nTeste interrompido pelo usuário.")
