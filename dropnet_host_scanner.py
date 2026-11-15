#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""DROPNET HOST SCANNER - painel TUI para testes em destinos autorizados (modo CONNECT)."""
import asyncio
import ipaddress
import os
import re
import socket
import ssl
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path

# ───────────────────────── Constantes ─────────────────────────
VERSION = "2.0"
OUT = Path.home() / "storage" / "downloads" / "DROPNET-SCANNER"
MAX_CIDR_HOSTS = 256
TIMEOUT = 5
EXTRA_WAIT = 3.0            # tempo extra de espera depois da 1ª resposta
MAX_READ = 262144           # limite de bytes lidos por conexão
TLS_PORTS = {443}
ACCEPTED = ("101", "200")   # status considerados aprovados

C, G, Y, R, W, D, X = ("\033[96m", "\033[92m", "\033[93m", "\033[91m",
                       "\033[97m", "\033[90m", "\033[0m")

CFG = {
    "target": "",
    "use_sni": True,
    "use_cidr": False,
    "textline": False,
    "payload": "GET / HTTP/1.1\\r\\nHost: [host]\\r\\nConnection: close\\r\\n\\r\\n",
    "proxy": "",
    "sni": "",
    "ports": [80, 443],   # automático: testa as duas
    "workers": 20,
}


@dataclass
class Result:
    index: int
    host: str
    port: int
    proxy: str          # "ip:porta" (porta = a do menu)
    status: str         # "101", "200", "403"..., "TCP" ou "ERRO"
    detail: str         # mensagem (usada em TCP/ERRO)
    responses: tuple = ()   # todas as respostas HTTP, na ordem: (("403", "Forbidden"), ("101", "..."))

    @property
    def connected(self):
        return self.status != "ERRO"

    @property
    def approved(self):
        return self.status in ACCEPTED

    @property
    def color(self):
        return G if self.approved else (R if self.status == "ERRO" else Y)

    def render(self, colored=False, show_host=False, show_port=False):
        """Uma linha só: símbolo, proxy:porta, resultado e status."""
        if self.status == "ERRO":
            symbol, result, info = "✘", "NÃO CONECTOU", self.detail
        else:
            codes = " → ".join(code for code, _ in self.responses) or self.status
            symbol = "✔" if self.approved else "•"
            result = "CONECTOU"
            info = codes
            if len(self.responses) == 1:          # um status só: mostra também a mensagem
                info = f"{codes} {self.responses[0][1]}".strip()
            elif not self.responses:              # sem HTTP (só TCP)
                info = self.detail
        line = f"{symbol} {self.proxy:<21} {result:<13} {info}"
        extras = []                               # só quando o scan tem mais de um host/porta
        if show_host:
            extras.append(self.host)
        if show_port:
            extras.append(f"porta {self.port}")
        if extras:
            line += f"  ({', '.join(extras)})"
        return f"{self.color}{line}{X}" if colored else line


# ───────────────────────── Interface ─────────────────────────
def clear():
    os.system("clear" if os.name == "posix" else "cls")


def header():
    clear()
    print(C + "╔══════════════════════════════════════╗")
    print("║        DROPNET HOST SCANNER          ║")
    print("╚══════════════════════════════════════╝" + X)
    print(D + f" Painel de testes em redes autorizadas  v{VERSION}" + X)


def show_panel():
    """Painel vertical, adequado à tela do Termux."""
    header()
    ports = CFG["ports"]
    sni_active = any(p in TLS_PORTS for p in ports)
    port_label = " e ".join(str(p) for p in ports) + (" (automático)" if len(ports) > 1 else "")
    try:
        total = len(parse_proxy_list(CFG["proxy"]))
    except ValueError:
        total = 0
    proxy_label = f"{total} proxy(s)" if total else "(não configurada)"
    sni_label = (CFG["sni"] or "(não definido)") if sni_active else "(desativado na porta 80)"
    print(f"\n{C}========== CONFIGURAÇÃO =========={X}")
    print(f"{W}HOST    :{X} {CFG['target'] or '(não definido)'}")
    print(f"{W}PORTA   :{X} {port_label}")
    print(f"{W}SNI     :{X} {sni_label}")
    print(f"{W}PAYLOAD :{X} {'configurada' if CFG['payload'].strip() else '(vazia)'}")
    print(f"{W}PROXY   :{X} {proxy_label}")
    print(f"\n{C}============= MENU ==============={X}")
    print("[1] HOST")
    print("[2] PORTA (80, 443 ou automático)")
    if sni_active:
        print("[3] SNI")
    print("[4] PAYLOAD")
    print("[5] PROXY")
    print(G + "[6] ▶ INICIAR SCAN" + X)
    print(R + "[0] SAIR" + X)


def edit_line(label, current=""):
    print(f"\n{label}")
    value = input(f"> {current}\nNovo valor (ENTER mantém): ").strip()
    return value if value else current


def edit_payload():
    print("\nPAYLOAD - cole tudo em uma linha e aperte ENTER para salvar")
    print("Use [host], [crlf], [lf] e [method] quando necessário.")
    try:
        value = input("> ").strip()
    except (EOFError, KeyboardInterrupt):
        return CFG["payload"]
    return value if value else CFG["payload"]


def edit_proxies():
    """Aceita proxies coladas uma embaixo da outra ou separadas por #."""
    print("\nPROXIES - só o IP (a porta é a que você escolheu no menu)")
    print("Cole uma embaixo da outra ou separadas por #")
    print("Termine com uma linha vazia (ENTER). ENTER direto mantém as atuais.")
    lines = []
    try:
        while True:
            line = input("> ").strip()
            if not line:
                break
            lines.append(line)
    except (EOFError, KeyboardInterrupt):
        return CFG["proxy"]
    if not lines:
        return CFG["proxy"]
    raw = "\n".join(lines)
    try:
        count = len(parse_proxy_list(raw))
    except ValueError as exc:
        print(f"{R}{exc}. Nada foi alterado.{X}")
        return CFG["proxy"]
    print(f"{G}{count} proxy(s) salva(s).{X}")
    return raw


def ask_port():
    value = input("Porta: 80, 443 ou A = automático (as duas) [A]: ").strip().lower() or "a"
    if value in ("a", "auto", "automatico", "automático"):
        CFG["use_sni"] = True              # o SNI só é usado na 443
        return [80, 443]
    if value not in ("80", "443"):
        print("Escolha 80, 443 ou A.")
        return None
    CFG["use_sni"] = int(value) in TLS_PORTS
    return [int(value)]


# ───────────────────────── Entrada / validação ─────────────────────────
def parse_proxy_list(raw):
    """Lista de proxies (só o IP/host). A porta vem sempre da PORTA escolhida no menu."""
    result = []
    for item in re.split(r"[#\s,;]+", raw):
        item = item.strip().split(":", 1)[0]   # se vier ip:porta, a porta é ignorada
        if item:
            result.append(item)
    return list(dict.fromkeys(result))


def normalize_target(value):
    value = value.strip().replace("https://", "").replace("http://", "")
    if CFG["use_cidr"] and "/" in value:
        return value
    return value.split("/", 1)[0]


def get_targets():
    value = normalize_target(CFG["target"])
    if not value:
        raise ValueError("Informe um IP, host ou CIDR.")
    if CFG["use_cidr"]:
        net = ipaddress.ip_network(value, strict=False)
        if not net.is_private:
            raise ValueError("CIDR permitido somente em rede privada/autorizada.")
        if net.num_addresses > MAX_CIDR_HOSTS:
            raise ValueError(f"Limite de {MAX_CIDR_HOSTS} endereços por varredura.")
        return [str(ip) for ip in net.hosts()] or [str(net.network_address)]
    if "/" in value:
        raise ValueError("Ative Usar CIDR Range para informar uma faixa.")
    return [value]


def build_payload(target):
    payload = CFG["payload"].replace("[host]", target).replace("[HOST]", target)
    if CFG["textline"]:
        payload = payload.replace("[crlf]", "\r\n").replace("[lf]", "\n")
    payload = payload.replace("[method]", "GET")
    return payload.replace("\\r", "\r").replace("\\n", "\n")


# ───────────────────────── Rede ─────────────────────────
def tls_context():
    """Sem verificação de certificado: o SNI usado quase nunca bate com o certificado do IP."""
    context = ssl.create_default_context()
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE
    return context


async def step(coro, message):
    """Aguarda uma etapa; se estourar o tempo, levanta erro com texto legível."""
    try:
        return await asyncio.wait_for(coro, TIMEOUT)
    except asyncio.TimeoutError:
        raise TimeoutError(message) from None


async def close_writer(writer):
    if writer:
        writer.close()
        try:
            await writer.wait_closed()
        except Exception:
            pass


async def open_direct(bypass_host, port, use_tls, sni):
    """Conecta direto no IP/host de bypass e, se for porta com TLS, faz o handshake com o SNI de fachada."""
    reader, writer = await step(asyncio.open_connection(bypass_host, port),
                                f"timeout ao conectar em {bypass_host}:{port}")
    if use_tls:
        try:
            await writer.start_tls(tls_context(), server_hostname=sni,
                                   ssl_handshake_timeout=TIMEOUT)
        except asyncio.TimeoutError:
            await close_writer(writer)
            raise TimeoutError(f"timeout no handshake TLS (SNI {sni})") from None
        except Exception:
            await close_writer(writer)
            raise
    return reader, writer


async def read_response(reader):
    """Lê tudo que chegar (ex.: 403, 403, 101, 200 na mesma conexão), não só a 1ª linha."""
    loop = asyncio.get_running_loop()
    data = bytearray()
    deadline = loop.time() + TIMEOUT
    while len(data) < MAX_READ:
        remaining = deadline - loop.time()
        if remaining <= 0:
            break
        try:
            chunk = await asyncio.wait_for(reader.read(65536), remaining)
        except asyncio.TimeoutError:
            break
        if not chunk:
            break
        if not data:
            deadline = min(deadline, loop.time() + EXTRA_WAIT)
        data.extend(chunk)
    return bytes(data)


def summarize(data):
    """Transforma a resposta bruta em (status, respostas, detalhe)."""
    found = re.findall(rb"(?im)^HTTP/\d(?:\.\d)?[ \t]+(\d{3})([^\r\n]*)", data)
    if found:
        responses = tuple((code.decode(), reason.decode("latin-1", "replace").strip())
                          for code, reason in found)
        codes = [code for code, _ in responses]
        # Se QUALQUER resposta da sequência foi 101 ou 200, conta como aprovado.
        status = next((c for c in ACCEPTED if c in codes), codes[0])
        return status, responses, ""
    text = [x.strip() for x in data.decode("latin-1", "replace").splitlines() if x.strip()][:3]
    return "TCP", (), " | ".join(text) or "Conexão estabelecida; sem resposta HTTP"


def friendly_error(exc):
    """Traduz o erro para uma frase curta e fácil de entender."""
    if isinstance(exc, ConnectionRefusedError):
        return "conexão recusada (porta fechada ou proxy desligada)"
    if isinstance(exc, ConnectionResetError):
        return "conexão derrubada pelo servidor"
    if isinstance(exc, socket.gaierror):
        return "endereço não encontrado"
    if isinstance(exc, ssl.SSLError):
        return "falha no TLS (confira o SNI e a porta)"
    return (str(exc).strip() or type(exc).__name__)[:180]


async def probe(target, port, bypass_host, sem, index):
    proxy = bypass_host  # mantém o nome usado no restante da função
    proxy_name = f"{proxy}:{port}"
    async with sem:
        writer = None
        try:
            tls = port in TLS_PORTS
            sni = CFG["sni"] or target if CFG["use_sni"] and tls else target
            reader, writer = await open_direct(proxy, port, tls, sni)
            payload = build_payload(target)
            if payload.strip():
                writer.write(payload.encode("utf-8", "replace"))
                await writer.drain()
            status, responses, detail = summarize(await read_response(reader))
            return Result(index, target, port, proxy_name, status, detail, responses)
        except Exception as exc:
            return Result(index, target, port, proxy_name, "ERRO", friendly_error(exc))
        finally:
            await close_writer(writer)


# ───────────────────────── Scan ─────────────────────────
def build_jobs(targets, proxies):
    """Testa TODAS as proxies em cada host/porta."""
    return [(host, port, bypass)          # cada IP de bypass é testado na PORTA escolhida no menu
            for bypass in proxies for host in targets for port in CFG["ports"]]


def save_results(results, show_host=False, show_port=False):
    OUT.mkdir(parents=True, exist_ok=True)
    stamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    ordered = sorted(results, key=lambda r: r.index)
    (OUT / f"host_log_{stamp}.txt").write_text("\n".join(r.render(show_host=show_host, show_port=show_port) for r in ordered), encoding="utf-8")
    (OUT / f"host_status_101_200_{stamp}.txt").write_text(
        "\n".join(r.render(show_host=show_host, show_port=show_port) for r in ordered if r.approved), encoding="utf-8")


async def run_scan():
    targets = get_targets()
    proxies = parse_proxy_list(CFG["proxy"])
    if not proxies:
        raise ValueError("Configure ao menos uma PROXY antes de iniciar o scan.")
    jobs = build_jobs(targets, proxies)
    sem = asyncio.Semaphore(CFG["workers"])
    print(f"\n{C}DROPNET - INICIANDO{X}")
    print(f"Hosts: {len(targets)} | Proxies: {len(proxies)} | Portas: {CFG['ports']} "
          f"| Tarefas: {len(jobs)} | Simultâneas: {CFG['workers']}\n")

    results = []
    show_host = len(targets) > 1
    show_port = len(CFG["ports"]) > 1
    tasks = [probe(host, port, proxy, sem, idx) for idx, (host, port, proxy) in enumerate(jobs, 1)]
    for task in asyncio.as_completed(tasks):
        res = await task
        results.append(res)
        print(f"\r\033[K{res.render(colored=True, show_host=show_host, show_port=show_port)}")
        print(f"\rProgresso: {len(results)}/{len(jobs)}", end="", flush=True)
    print("\n")

    save_results(results, show_host, show_port)
    connected = sum(r.connected for r in results)
    approved = sum(r.approved for r in results)
    print(f"{G}Conectaram: {connected} de {len(jobs)}{X} | "
          f"{R}Não conectaram: {len(jobs) - connected}{X} | Com 101/200: {approved}")
    print(f"Resultados salvos em: {OUT}")


# ───────────────────────── Menu ─────────────────────────
def configure(choice):
    if choice == "1":
        CFG["target"] = edit_line("HOST", CFG["target"])
    elif choice == "2":
        value = ask_port()
        if value:
            CFG["ports"] = value
    elif choice == "3" and any(p in TLS_PORTS for p in CFG["ports"]):
        CFG["sni"] = edit_line("SNI", CFG["sni"])
    elif choice == "4":
        CFG["payload"] = edit_payload()
    elif choice == "5":
        CFG["proxy"] = edit_proxies()


def start_scan():
    try:
        if not CFG["target"]:
            CFG["target"] = input("HOST: ").strip()
        if not CFG["payload"].strip():
            CFG["payload"] = edit_payload()
        if not CFG["proxy"].strip():
            raise ValueError("Configure uma PROXY antes de iniciar o scan.")
        asyncio.run(run_scan())
    except KeyboardInterrupt:
        print("\nScan interrompido.")
    except Exception as exc:
        print(f"\n{R}[ERRO] {exc}{X}")


def main():
    while True:
        show_panel()
        choice = input("\nComando: ").strip().lower()
        if choice in ("0", "q", "sair"):
            print("Até mais!")
            return
        if choice in ("6", "i", "iniciar"):
            start_scan()
        else:
            configure(choice)
        input("\nENTER para voltar")


if __name__ == "__main__":
    try:
        main()
    except (KeyboardInterrupt, EOFError):
        print("\nEncerrado.")
