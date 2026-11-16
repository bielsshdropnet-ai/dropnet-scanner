#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""DROPNET HOST SCANNER - painel TUI para testes em destinos autorizados (modo CONNECT)."""
import asyncio
import ipaddress
import os
import random
import re
import socket
import ssl
import time
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
    proxy: str           # IP/host testado (bypass)
    sni: str             # SNI usado no handshake ("" na porta 80)
    elapsed_ms: int
    status: str          # "101", "200", "403"..., "TCP" ou "ERRO"
    detail: str          # mensagem (usada em TCP/ERRO)
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

    def render(self, colored=False):
        """Uma linha só: IP, protocolo:porta, host/SNI, status HTTP e tempo de resposta."""
        proto = "ssl" if self.port in TLS_PORTS else "tcp"
        symbol = "✔" if self.approved else ("✘" if self.status == "ERRO" else "•")
        host_part = f"{self.host} / SNI {self.sni}" if self.sni else self.host

        if self.status == "ERRO":
            info = self.detail
        elif self.responses:
            codes = " → ".join(code for code, _ in self.responses)
            info = f"HTTP/1.1 {codes}"
            if len(self.responses) == 1:          # um status só: mostra também a mensagem
                info += f" {self.responses[0][1]}".rstrip()
            if self.approved:
                info += "  DROPNET"
        else:
            info = self.detail or "sem resposta HTTP"

        line = f"{symbol} {self.proxy:<15} {proto}:{self.port:<4} {host_part}  {info}  {self.elapsed_ms}ms"
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
    sni_list = parse_sni_list(CFG["sni"])
    if not sni_active:
        sni_label = "(desativado na porta 80)"
    elif not sni_list:
        sni_label = "(não definido)"
    elif len(sni_list) == 1:
        sni_label = sni_list[0]
    else:
        sni_label = f"{len(sni_list)} SNIs em rotação (aleatório)"
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
    value = input(f"> {current}SEU HOST AQUI (ENTER): ").strip()
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


def edit_sni():
    """Aceita um ou vários SNIs: digite um, ENTER, digite outro... Termine com linha vazia."""
    print("\nSUA SNI AQUI- digite um e aperte (ENTER)")
    lines = []
    try:
        while True:
            line = input("> ").strip()
            if not line:
                break
            lines.append(line)
    except (EOFError, KeyboardInterrupt):
        return CFG["sni"]
    if not lines:
        return CFG["sni"]
    raw = "\n".join(lines)
    count = len(parse_sni_list(raw))
    print(f"{G}{count} SNI(s) salvo(s).{X}" + (" Vai alternar entre eles (aleatório) a cada teste." if count > 1 else ""))
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


def parse_sni_list(raw):
    """Lista de SNIs (um por linha, ou separados por # , ;). Pode ter vários."""
    result = []
    for item in re.split(r"[#\n,;]+", raw):
        item = item.strip()
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
    """Troca os marcadores do payload. [crlf]/[lf] (como no CheckHost) e \\r\\n sempre viram quebra de linha real."""
    payload = CFG["payload"].replace("[host]", target).replace("[HOST]", target)
    payload = payload.replace("[crlf]", "\r\n").replace("[CRLF]", "\r\n")
    payload = payload.replace("[lf]", "\n").replace("[LF]", "\n")
    payload = payload.replace("[method]", "GET").replace("[METHOD]", "GET")
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
    tls = port in TLS_PORTS
    sni_list = parse_sni_list(CFG["sni"])
    sni = (random.choice(sni_list) if sni_list else target) if CFG["use_sni"] and tls else ""
    async with sem:
        writer = None
        start = time.monotonic()
        try:
            reader, writer = await open_direct(bypass_host, port, tls, sni or target)
            payload = build_payload(target)
            if payload.strip():
                writer.write(payload.encode("utf-8", "replace"))
                await writer.drain()
            status, responses, detail = summarize(await read_response(reader))
            elapsed_ms = round((time.monotonic() - start) * 1000)
            return Result(index, target, port, bypass_host, sni, elapsed_ms, status, detail, responses)
        except Exception as exc:
            elapsed_ms = round((time.monotonic() - start) * 1000)
            return Result(index, target, port, bypass_host, sni, elapsed_ms, "ERRO", friendly_error(exc))
        finally:
            await close_writer(writer)


# ───────────────────────── Scan ─────────────────────────
def build_jobs(targets, proxies):
    """Testa TODAS as proxies em cada host/porta."""
    return [(host, port, bypass)          # cada IP de bypass é testado na PORTA escolhida no menu
            for bypass in proxies for host in targets for port in CFG["ports"]]


def save_results(results):
    OUT.mkdir(parents=True, exist_ok=True)
    stamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    ordered = sorted(results, key=lambda r: r.index)
    (OUT / f"host_log_{stamp}.txt").write_text("\n".join(r.render() for r in ordered), encoding="utf-8")
    (OUT / f"host_status_101_200_{stamp}.txt").write_text(
        "\n".join(r.render() for r in ordered if r.approved), encoding="utf-8")


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
    tasks = [probe(host, port, proxy, sem, idx) for idx, (host, port, proxy) in enumerate(jobs, 1)]
    for task in asyncio.as_completed(tasks):
        res = await task
        results.append(res)
        if res.approved:                       # só mostra na tela quem realmente aprovou (101/200)
            print(f"\r\033[K{res.render(colored=True)}")
        print(f"\rProgresso: {len(results)}/{len(jobs)}", end="", flush=True)
    print("\n")

    save_results(results)
    connected = sum(r.connected for r in results)
    approved = sum(r.approved for r in results)
    print(f"{G}Aprovados (101/200): {approved}{X} | Conectaram: {connected} de {len(jobs)} "
          f"| {R}Não conectaram: {len(jobs) - connected}{X}")
    print(f"Resultados completos (todos) salvos em: {OUT}")


# ───────────────────────── Menu ─────────────────────────
def configure(choice):
    if choice == "1":
        CFG["target"] = edit_line("HOST", CFG["target"])
    elif choice == "2":
        value = ask_port()
        if value:
            CFG["ports"] = value
    elif choice == "3" and any(p in TLS_PORTS for p in CFG["ports"]):
        CFG["sni"] = edit_sni()
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
