#!/usr/bin/env python3
# DROPNET SCANNER 3 — interface inicial
# Protótipo de interface: coleta configurações, mas ainda não executa varredura
# nem envia payloads para endereços de rede.

import ipaddress
import os
import textwrap

RESET = "\033[0m"
CYAN = "\033[96m"
GREEN = "\033[92m"
YELLOW = "\033[93m"
RED = "\033[91m"
BOLD = "\033[1m"

def clear():
    os.system("clear" if os.name == "posix" else "cls")

def line():
    print(CYAN + "═" * 58 + RESET)

def ask(prompt, secret=False):
    value = input(f"{YELLOW}{prompt}{RESET} ").strip()
    return value

def main():
    clear()
    line()
    print(f"{BOLD}{CYAN}             DROPNET • SCANNER 3{RESET}")
    print(f"{GREEN}          CIDR / PAYLOAD / SNI{RESET}")
    line()
    print("Protótipo de interface para diagnóstico autorizado.")
    print("Esta versão coleta os parâmetros; ainda não faz varredura.")
    line()

    user_id = ask("ID da operadora/identificador:")
    while not user_id:
        print(RED + "Informe um identificador." + RESET)
        user_id = ask("ID da operadora/identificador:")

    while True:
        cidr_text = ask("CIDR da rede (ex.: 192.168.1.0/24):")
        try:
            network = ipaddress.ip_network(cidr_text, strict=False)
            if network.version != 4:
                raise ValueError
            break
        except ValueError:
            print(RED + "CIDR IPv4 inválido. Tente novamente." + RESET)

    print("\nModo de conexão:")
    print("  [1] SSH / TCP — porta 80")
    print("  [2] SSL / TLS — porta 443")
    while True:
        mode = ask("Escolha 1 ou 2:")
        if mode in ("1", "2"):
            break
        print(RED + "Escolha inválida." + RESET)

    port = 80 if mode == "1" else 443
    mode_name = "SSH/TCP" if port == 80 else "SSL/TLS"

    payload = ask("Payload (texto para configuração; não será enviada):")
    sni = ""
    if port == 443:
        sni = ask("SNI (nome DNS do serviço):")

    clear()
    line()
    print(f"{BOLD}{CYAN}             RESUMO DA CONFIGURAÇÃO{RESET}")
    line()
    print(f"ID/Identificador : {user_id}")
    print(f"CIDR             : {network}")
    print(f"Endereços        : {network.num_addresses}")
    print(f"Modo             : {mode_name}")
    print(f"Porta            : {port}")
    print(f"Payload          : {'informada' if payload else 'não informada'}")
    print(f"SNI              : {sni if sni else 'não aplicável/não informado'}")
    line()
    print(YELLOW + "LOG" + RESET)
    print("[INFO] Parâmetros recebidos.")
    print("[INFO] Interface pronta para integração com testes autorizados.")
    print("[INFO] Nenhum IP foi varrido; nenhuma payload foi transmitida.")
    print()
    print(GREEN + "Configuração registrada nesta execução." + RESET)
    print("Pressione Enter para sair.")
    input()

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\nEncerrado.")
