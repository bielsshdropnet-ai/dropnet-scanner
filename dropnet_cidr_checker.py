#!/usr/bin/env python3
# DROPNET SCANNER 3 — diagnóstico de um endpoint autorizado.
# Testa TCP e, na porta 443, handshake TLS. Não varre CIDRs nem envia payload de túnel.

import os, re, socket, ssl, ipaddress
from datetime import datetime

C="\033[96m"; G="\033[92m"; Y="\033[93m"; R="\033[91m"; X="\033[0m"

def ask(label, required=False):
    while True:
        v=input(f"{Y}{label}{X} ").strip()
        if v or not required: return v
        print(R+"Campo obrigatório."+X)

def clean_host(v):
    v=v.strip()
    v=re.sub(r"^https?://","",v,flags=re.I)
    return v.split("/")[0].split(":")[0]

def valid_host(h):
    try: ipaddress.ip_address(h); return True
    except ValueError:
        return bool(re.fullmatch(r"(?=.{1,253}$)[A-Za-z0-9](?:[A-Za-z0-9.-]*[A-Za-z0-9])?",h))

def diagnose(host,port,sni):
    sock=None
    print(f"\n{C}[TESTE] {host}:{port}{X}")
    try:
        sock=socket.create_connection((host,port),timeout=5)
        print(G+"[OK] Conexão TCP estabelecida."+X)
        if port==443:
            ctx=ssl.create_default_context()
            tls=ctx.wrap_socket(sock,server_hostname=sni or host)
            sock=None
            print(G+f"[OK] Handshake TLS: {tls.version()}"+X)
            print(f"[INFO] SNI: {sni or host}")
            tls.close()
        else:
            print("[INFO] Porta 80: teste TCP concluído; SNI não se aplica.")
    except ssl.SSLCertVerificationError as e:
        print(R+f"[TLS] Certificado não validado: {e}"+X)
    except ssl.SSLError as e:
        print(R+f"[TLS] Falha no handshake: {e}"+X)
    except socket.timeout:
        print(R+"[ERRO] Tempo limite excedido."+X)
    except OSError as e:
        print(R+f"[ERRO] Conexão falhou: {e}"+X)
    finally:
        if sock:
            try: sock.close()
            except OSError: pass

def main():
    while True:
        os.system("clear")
        print(C+"╔══════════════════════════════════════════════════╗")
        print("║          DROPNET • SCANNER 3                     ║")
        print("║       DIAGNÓSTICO DE CONEXÃO AUTORIZADO          ║")
        print("╚══════════════════════════════════════════════════╝"+X)
        print("Informe os dados na ordem solicitada.\n")
        operator_id=ask("ID da operadora/identificador:",True)
        payload=ask("Payload (guardada como referência):",True)
        if "[host]" in payload.lower():
            print(G+"[INFO] Marcador [host] encontrado."+X)
        else:
            print(Y+"[INFO] Payload sem [host]; informe o Host separadamente."+X)
        host=clean_host(ask("Host do serviço que você administra:",True))
        if not valid_host(host):
            print(R+"Host inválido."+X); input("Enter para continuar..."); continue
        while True:
            p=ask("Porta (80 ou 443):",True)
            if p in ("80","443"): break
            print(R+"Informe 80 ou 443."+X)
        port=int(p)
        sni=""
        if port==443:
            sni=clean_host(ask("SNI (Enter para usar o Host):"))
            if sni and not valid_host(sni):
                print(R+"SNI inválido."+X); input("Enter..."); continue
        print("\n"+C+"──────── RESUMO ────────"+X)
        print("ID:",operator_id)
        print("Host:",host)
        print("Porta:",port)
        print("Modo:","HTTP/TCP" if port==80 else "HTTPS/TLS")
        print("SNI:",sni or ("não utilizado" if port==80 else host))
        print("Payload:","[host] encontrado" if "[host]" in payload.lower() else "informada")
        print(Y+"A payload não será transmitida. Este teste verifica apenas o host informado."+X)
        if ask("Digite TESTAR para iniciar:").upper()=="TESTAR":
            diagnose(host,port,sni)
        else:
            print("Teste cancelado.")
        print(f"\n[{datetime.now().strftime('%H:%M:%S')}] Diagnóstico finalizado.")
        if ask("1) Nova configuração  0) Sair:")!="1": break
    print("DROPNET encerrado.")

if __name__=="__main__":
    try: main()
    except KeyboardInterrupt: print("\nInterrompido.")
