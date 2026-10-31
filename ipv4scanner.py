#!/usr/bin/env python3
"""
DROPNET SCANNER v2.1
Varre faixas de CDNs/provedores e separa os IPs por porta (80 / 443).

Uso:
  python dropnet_scanner.py                 -> menu (CDN, tipo de busca, porta e payload)
  python dropnet_scanner.py --avancado      -> menu com mais opções
  python dropnet_scanner.py --cidr 1.2.3.0/24 --tcp --ports 80,443
  python dropnet_scanner.py --provider azion --tcp --ports 80,443
  python dropnet_scanner.py --hosts hosts.txt --port 443 --tls --status "101;200"

Só biblioteca padrão (roda no Termux). Use apenas em faixas que você
tem permissão de testar.
"""
import argparse
import asyncio
import bisect
import copy
from collections import Counter
import ipaddress
import json
import os
import random
import re
import shutil
import ssl
import sys
import textwrap
import time

VERSION = "2.1"
RETRY_TOTAL_LIMIT = 20000   # até esse tamanho, guarda quem NUNCA respondeu p/ tentar de novo

FAIL = Counter()   # por que as conexões falharam (timeout / recusado / outro)
SEEN = Counter()   # o que os IPs com porta aberta responderam ao teste real

APP_UA = "ScannerV4/1.0"

DEFAULT_PAYLOAD = (
    "GET / HTTP/1.1[crlf]Host: [host][crlf]"
    "Upgrade: websocket[crlf]Connection: Keep-Alive[crlf][crlf]"
)

TLS_VERSIONS = {
    "1.0": ssl.TLSVersion.TLSv1,
    "1.1": ssl.TLSVersion.TLSv1_1,
    "1.2": ssl.TLSVersion.TLSv1_2,
    "1.3": ssl.TLSVersion.TLSv1_3,
}


# ============================ visual ============================
class UI:
    color = sys.stdout.isatty() and os.environ.get("NO_COLOR") is None


def c(code, txt):
    return f"\033[{code}m{txt}\033[0m" if UI.color else str(txt)


def term_width():
    return shutil.get_terminal_size((40, 20)).columns


def fmt(n):
    return f"{n:,}".replace(",", ".")


def banner():
    w = 36
    print()
    print(c("1;36", "╔" + "═" * w + "╗"))
    print(c("1;36", "║") + c("1;97", "D R O P N E T".center(w)) + c("1;36", "║"))
    print(c("1;36", "║") + c("36", f"S C A N N E R   v{VERSION}".center(w)) + c("1;36", "║"))
    print(c("1;36", "╚" + "═" * w + "╝"))


def line(ch="─", color="2"):
    print(c(color, ch * min(term_width() - 1, 38)))


def badge(ports, all_ports):
    txt = "+".join(str(p) for p in ports)
    if len(all_ports) > 1 and set(ports) == set(all_ports):
        return c("1;32", txt)          # abriu em todas as portas
    if ports and ports[0] == all_ports[0]:
        return c("33", txt)
    return c("35", txt)


def port_cell(port_num, open_ports, width=5):
    """Uma célula de tabela para uma porta: ✔ aberta, · fechada."""
    if port_num in (open_ports or []):
        return c("1;32", "✔".center(width))
    return c("2", "·".center(width))


def header_row(ports):
    cols = "".join(f"{p:^5}" for p in ports)
    return c("1;97", f" {'IP':<16}") + c("1;36", cols)


def etapa(titulo):
    """Cabeçalho de cada etapa do assistente."""
    print()
    print(c("1;36", " ▌") + c("1;97", f" {titulo}"))
    line()


def opcao(chave, titulo, detalhe=""):
    extra = f"  {c('2', detalhe)}" if detalhe else ""
    print(f" {c('1;36', chave + ')')} {c('1', titulo)}{extra}")


def escolher(rotulo, validas, padrao=None):
    """Pergunta de múltipla escolha. Repete até vir uma opção válida."""
    sufixo = f" [{padrao}]" if padrao else ""
    while True:
        try:
            r = input(c("1;36", " ❯ ") + f"{rotulo}{sufixo}: ").strip().lower()
        except EOFError:
            sys.exit("\n Entrada encerrada.")
        if not r and padrao:
            return padrao
        if r in validas:
            return r
        print(c("31", f" Opção inválida. Digite {' / '.join(validas)}."))


def info_row(rotulo, valor):
    print(f" {c('1;36', '▸')} {c('2', rotulo.ljust(8))} {valor}")


def raise_nofile():
    """Aumenta o limite de conexões abertas (essencial p/ ir mais rápido)."""
    try:
        import resource
        soft, hard = resource.getrlimit(resource.RLIMIT_NOFILE)
        alvo = 65536 if hard == resource.RLIM_INFINITY else min(hard, 65536)
        if soft < alvo:
            resource.setrlimit(resource.RLIMIT_NOFILE, (alvo, hard))
        return resource.getrlimit(resource.RLIMIT_NOFILE)[0]
    except Exception:
        return 1024


# ============================ entrada ============================
def find_providers_file(path):
    if os.path.exists(path):
        return path
    alt = os.path.join(os.path.dirname(os.path.abspath(__file__)), os.path.basename(path))
    if os.path.exists(alt):
        return alt
    sys.exit("providers.json não encontrado. Coloque na mesma pasta do script.")


def load_providers(path):
    with open(find_providers_file(path), encoding="utf-8") as f:
        return json.load(f)["providers"]


def provider_cidrs(path, names):
    by_name = {p["name"].lower(): p["cidrs"] for p in load_providers(path)}
    out = []
    for n in names:
        if n.lower() not in by_name:
            sys.exit(f"Provedor '{n}' não existe. Disponíveis: {', '.join(sorted(by_name))}")
        out += by_name[n.lower()]
    return out


def parse_nets(cidrs):
    nets = []
    for cdr in cidrs:
        try:
            n = ipaddress.ip_network(cdr.strip(), strict=False)
        except ValueError:
            print(f"[!] CIDR inválido ignorado: {cdr}", file=sys.stderr)
            continue
        if n.version == 4:
            nets.append(n)
    return nets


def total_ips(cidrs):
    return sum(n.num_addresses for n in parse_nets(cidrs))


def iter_targets(cidrs, max_ips, shuffle):
    """Gera IPs sem carregar tudo na memória. Com limite, sorteia IPs
    espalhados por TODAS as faixas."""
    nets = parse_nets(cidrs)
    sizes = [n.num_addresses for n in nets]
    total = sum(sizes)
    if max_ips and max_ips < total:
        starts, acc = [], 0
        for sz in sizes:
            starts.append(acc)
            acc += sz
        for off in sorted(random.sample(range(total), max_ips)):
            k = bisect.bisect_right(starts, off) - 1
            yield str(nets[k][off - starts[k]])
        return
    if shuffle:
        random.shuffle(nets)
    for net in nets:
        for ip in net:
            yield str(ip)


def iter_hosts(path):
    with open(path, encoding="utf-8") as f:
        for ln in f:
            ln = ln.strip()
            if ln and not ln.startswith("#"):
                yield ln


# ============================ testes ============================
def parse_status_spec(spec):
    out = []
    for part in spec.split(";"):
        part = part.strip()
        if not part:
            continue
        if "-" in part:
            a, b = part.split("-", 1)
            out.append((int(a), int(b)))
        else:
            out.append((int(part), int(part)))
    return out


def status_ok(code, ranges):
    return any(a <= code <= b for a, b in ranges)


async def open_conn(target, args, ssl_ctx, port=None, use_tls=None):
    port = port or args.port
    use_tls = args.tls if use_tls is None else use_tls
    sni = args.sni if (use_tls and args.sni) else None
    if args.proxy:
        phost, _, pport = args.proxy.partition(":")
        r, w = await asyncio.open_connection(phost, int(pport or 8080))
        w.write(f"CONNECT {target}:{port} HTTP/1.1\r\nHost: {target}:{port}\r\n\r\n".encode())
        await w.drain()
        head = await r.readuntil(b"\r\n\r\n")
        if b" 200" not in head.split(b"\r\n", 1)[0]:
            w.close()
            raise ConnectionError("proxy recusou CONNECT")
        if use_tls:
            await w.start_tls(ssl_ctx, server_hostname=sni or target)
        return r, w
    return await asyncio.open_connection(
        target,
        port,
        ssl=ssl_ctx if use_tls else None,
        server_hostname=(sni or target) if use_tls else None,
        ssl_handshake_timeout=args.timeout if use_tls else None,
    )


async def probe_tcp(target, args, ports):
    """Só confere quais portas abrem (igual à aba Scanner do app)."""
    t0 = time.monotonic()

    async def uma(porta):
        w = None
        try:
            _, w = await asyncio.wait_for(
                open_conn(target, args, None, porta, use_tls=False), args.timeout)
            return porta
        except Exception as e:
            if isinstance(e, ConnectionRefusedError):
                FAIL["recusado"] += 1
            elif isinstance(e, (asyncio.TimeoutError, TimeoutError)):
                FAIL["timeout"] += 1
            else:
                FAIL["outro"] += 1
            if args.debug:
                print(f"[--] {target}:{porta} falhou ({type(e).__name__})", flush=True)
            return None
        finally:
            if w is not None:
                try:
                    w.close()
                except Exception:
                    pass

    res = await asyncio.gather(*(uma(p) for p in ports))
    abertas = [p for p in res if p]
    if not abertas:
        return None
    return target, abertas, "", int((time.monotonic() - t0) * 1000)


async def probe_http(target, args, ssl_ctx, ranges, port=None, use_tls=None, tries=1):
    port = port or args.port
    use_tls = args.tls if use_tls is None else use_tls
    host_header = getattr(args, "host", None) or args.sni or target
    # Tokens compatíveis com os tokens visíveis no APK.
    # [crlf] usa CRLF; [lf] usa LF; [host], [ip], [ua] e [method] são substituídos.
    template = args.payload.replace("[crlf]", "\r\n").replace("[lf]", "\n")
    template = template.replace("[host]", host_header).replace("[ip]", target)
    template = template.replace("[ua]", APP_UA).replace("[method]", "GET")
    # [rotate=a;b] seleciona uma alternativa por requisição.
    def rotate_token(match):
        choices = [x for x in match.group(1).split(";") if x]
        return random.choice(choices) if choices else ""
    template = re.sub(r"\[rotate=([^\]]*)\]", rotate_token, template)
    payload = template.encode()
    t0 = time.monotonic()
    for tentativa in range(tries):
        w = None
        conectou = False
        try:
            r, w = await asyncio.wait_for(
                open_conn(target, args, ssl_ctx, port, use_tls), args.timeout)
            conectou = True
            w.write(payload)
            await w.drain()
            raw = await asyncio.wait_for(r.readline(), args.timeout)
            status_line = raw.decode("latin-1", "replace").strip()
            m = re.match(r"HTTP/\d(?:\.\d)?\s+(\d{3})", status_line)
            if not m:
                SEEN["resposta não-HTTP"] += 1
                if args.debug:
                    print(f"[--] {target}:{port}: sem status HTTP: {status_line[:60]!r}", flush=True)
                continue
            if not status_ok(int(m.group(1)), ranges):
                SEEN[m.group(1)] += 1
                if args.debug:
                    print(f"[--] {target}:{port}: respondeu {status_line[:60]!r} (fora do esperado)", flush=True)
                continue
            return target, [port], status_line, int((time.monotonic() - t0) * 1000)
        except Exception as e:
            SEEN["conectou e não respondeu" if conectou else "não conectou"] += 1
            if args.debug:
                print(f"[--] {target}:{port}: falhou ({type(e).__name__}: {e})", flush=True)
            continue
        finally:
            if w is not None:
                try:
                    w.close()
                except Exception:
                    pass
    return None


# ============================ scan ============================
def resolve_ports(args):
    if args.tcp:
        if args.ports:
            return [int(x) for x in str(args.ports).split(",") if x.strip()]
        return [args.port]
    return [args.port]


def build_targets(args):
    if args.hosts:
        return iter_hosts(args.hosts), None
    cidrs = list(args.cidr or [])
    if args.cidr_file:
        cidrs += list(iter_hosts(args.cidr_file))
    if args.provider:
        cidrs += provider_cidrs(args.providers, args.provider)
    if not cidrs:
        sys.exit("Informe --cidr, --cidr-file, --provider ou --hosts.")
    tot = total_ips(cidrs)
    if args.max_ips and args.max_ips < tot:
        tot = args.max_ips
    return iter_targets(cidrs, args.max_ips, args.shuffle), tot


def progress_line(done, total, oks, start, extra=""):
    el = max(time.monotonic() - start, 0.001)
    rate = done / el
    if total:
        pct = int(done * 100 / total)
        bw = max(6, min(22, term_width() - 42))
        fill = int(bw * done / total)
        bar = "█" * fill + "░" * (bw - fill)
        return (f" {c('1;36', f'{pct:>3}%')} {c('36', '▕' + bar + '▏')} "
                f"{fmt(done)}/{fmt(total)} {c('32', f'✔{oks}')}{extra}")
    return f" {fmt(done)} testados  {c('32', f'✔{oks}')}  {rate:.0f} ip/s"


async def run(args):
    ports = resolve_ports(args)
    ranges = parse_status_spec(args.status)
    FAIL.clear()
    SEEN.clear()

    nofile = raise_nofile()
    por_ip = len(ports) if args.tcp else 1
    threads = max(1, min(args.threads, (nofile - 64) // por_ip))

    ssl_ctx = None
    # Também prepara TLS quando a confirmação TCP/HTTP inclui a porta 443.
    # A varredura TCP simples continua sem TLS; somente a etapa de confirmação usa.
    precisa_tls = args.tls and not args.tcp
    if args.tcp and args.confirmar and 443 in ports:
        precisa_tls = True
    if precisa_tls:
        ssl_ctx = ssl.create_default_context()
        ssl_ctx.check_hostname = False
        ssl_ctx.verify_mode = ssl.CERT_NONE
        if args.tls_version:
            v = TLS_VERSIONS[args.tls_version]
            ssl_ctx.minimum_version = v
            ssl_ctx.maximum_version = v
            if v in (ssl.TLSVersion.TLSv1, ssl.TLSVersion.TLSv1_1):
                try:
                    ssl_ctx.set_ciphers("DEFAULT@SECLEVEL=0")
                except ssl.SSLError:
                    pass

    targets, total = build_targets(args)
    sem = asyncio.Semaphore(threads)
    results = []          # (ip, ports, info, ms)
    rastrear_tudo = args.tcp and total and total <= RETRY_TOTAL_LIMIT
    nunca_respondeu = set() if rastrear_tudo else None
    done = 0
    start = time.monotonic()
    last_draw = 0.0
    interrupted = False
    n_abertos = 0

    def redraw(force=False):
        nonlocal last_draw
        now = time.monotonic()
        if not UI.color:
            return
        if force or now - last_draw > 0.15:
            extra = c("2", f" ab:{n_abertos}") if (args.tcp and args.confirmar) else ""
            sys.stdout.write("\r\033[K" + progress_line(done, total, len(results), start, extra))
            sys.stdout.flush()
            last_draw = now

    def show_hit(res):
        ip, pts, info, ms = res
        if args.tcp:
            cells = "".join(port_cell(p, pts) for p in ports)
            extra = ""
            if args.confirmar:
                codes = re.findall(r"HTTP/\d(?:\.\d)?\s+(\d{3})", info)
                extra = c("2", " " + "/".join(codes))
            txt = f" {c('1', ip.ljust(16))}{cells}{extra}  {c('2', f'{ms}ms')}"
        else:
            txt = f" {c('1;32', '✔')} {c('1', ip.ljust(15))} {c('32', info[:20])}  {c('2', f'{ms}ms')}"
        if UI.color:
            sys.stdout.write("\r\033[K" + txt + "\n")
        else:
            print(txt, flush=True)

    async def worker(t):
        nonlocal done, n_abertos
        if rastrear_tudo:
            nunca_respondeu.add(t)
        try:
            if args.tcp and not args.confirmar:
                res = await probe_tcp(t, args, ports)
                if res and rastrear_tudo:
                    nunca_respondeu.discard(t)
            elif args.tcp and args.confirmar:
                abertas = await probe_tcp(t, args, ports)
                res = None
                if abertas:
                    n_abertos += 1
                    if rastrear_tudo:
                        nunca_respondeu.discard(t)
                    for p in abertas[1]:
                        # Porta 443 precisa de handshake TLS; porta 80 permanece HTTP.
                        tls_port = (p == 443)
                        ok = await probe_http(t, args, ssl_ctx if tls_port else None,
                                               ranges, port=p, use_tls=tls_port,
                                               tries=args.tentativas)
                        if ok:
                            res = (t, [p], ok[2], ok[3]) if res is None else (
                                t, res[1] + [p], res[2] + " | " + ok[2], max(res[3], ok[3]))
            else:
                res = await probe_http(t, args, ssl_ctx, ranges, tries=args.tentativas)
                if res and rastrear_tudo:
                    nunca_respondeu.discard(t)
        finally:
            sem.release()
        done += 1
        if res:
            results.append(res)
            show_hit(res)
            redraw(True)
        else:
            redraw()
            if UI.color and not results and done in (30, 100, 300) and args.tcp:
                sys.stdout.write("\r\033[K" + c("2", " Nenhum host respondeu ainda...") + "\n")
            if not UI.color and done % 1000 == 0:
                print(f"... {done} testados, {len(results)} ok", flush=True)

    if args.tcp and UI.color:
        print(header_row(ports))
        line("─", "2")

    tasks = set()
    try:
        for t in targets:
            await sem.acquire()
            tk = asyncio.create_task(worker(t))
            tasks.add(tk)
            tk.add_done_callback(tasks.discard)
        while tasks:
            await asyncio.wait(set(tasks))
    except (KeyboardInterrupt, asyncio.CancelledError):
        interrupted = True
        for tk in list(tasks):
            tk.cancel()
        await asyncio.gather(*list(tasks), return_exceptions=True)

    if UI.color:
        sys.stdout.write("\r\033[K")

    # 2ª chance: refaz do zero quem NUNCA respondeu em nenhuma porta
    # (timeout de rede derruba conexão real; sem isso esses IPs se perdem)
    if rastrear_tudo and nunca_respondeu and not interrupted:
        alvo = list(nunca_respondeu)
        print(c("2", f" Revisando {len(alvo)} IPs sem resposta..."), flush=True)
        sem3 = asyncio.Semaphore(max(10, threads // 3))

        async def segunda_chance(ip):
            async with sem3:
                if args.confirmar:
                    abertas = await probe_tcp(ip, args, ports)
                    if not abertas:
                        return
                    n_abertos_local = abertas
                    res2 = None
                    for p in n_abertos_local[1]:
                        ok = await probe_http(ip, args, None, ranges, port=p,
                                               use_tls=False, tries=max(args.tentativas, 2))
                        if ok:
                            res2 = (ip, [p], ok[2], ok[3]) if res2 is None else (
                                ip, res2[1] + [p], res2[2] + " | " + ok[2], max(res2[3], ok[3]))
                    if res2:
                        results.append(res2)
                        show_hit(res2)
                elif args.tcp:
                    res2 = await probe_tcp(ip, args, ports)
                    if res2:
                        results.append(res2)
                        show_hit(res2)
                else:
                    res2 = await probe_http(ip, args, ssl_ctx, ranges, tries=2)
                    if res2:
                        results.append(res2)
                        show_hit(res2)

        try:
            await asyncio.gather(*(segunda_chance(ip) for ip in alvo))
        except (KeyboardInterrupt, asyncio.CancelledError):
            interrupted = True

    # 2ª checagem: nos IPs achados, tenta de novo a porta que não abriu
    # (em rede móvel alguns pacotes se perdem e dão falso "fechado")
    # Pulada quando já confirma com HTTP: seria reconfirmar milhares de IPs
    # com uma requisição completa só pra preencher o "badge" da outra porta.
    if args.tcp and not args.confirmar and len(ports) > 1 and not interrupted:
        faltam = [(r, [p for p in ports if p not in r[1]]) for r in results if len(r[1]) < len(ports)]
        if faltam and len(faltam) <= 3000:
            print(c("2", f" Confirmando portas de {len(faltam)} IPs encontrados..."), flush=True)
            sem2 = asyncio.Semaphore(20)

            async def recheck(r, miss):
                async with sem2:
                    for p in miss:
                        if args.confirmar:
                            ok = await probe_http(r[0], args, None, ranges, port=p,
                                                   use_tls=False, tries=2)
                            if ok:
                                r[1].append(p)
                            continue
                        for _ in range(2):
                            w = None
                            try:
                                _, w = await asyncio.wait_for(
                                    open_conn(r[0], args, None, p, use_tls=False), args.timeout + 1.5)
                                r[1].append(p)
                                break
                            except Exception:
                                pass
                            finally:
                                if w is not None:
                                    try:
                                        w.close()
                                    except Exception:
                                        pass

            try:
                await asyncio.gather(*(recheck(r, m) for r, m in faltam))
            except (KeyboardInterrupt, asyncio.CancelledError):
                interrupted = True
            for r in results:
                r[1].sort()

    summary(args, ports, results, done, time.monotonic() - start, interrupted, n_abertos)


def save_lists(args, ports, results):
    """Salva um arquivo por porta + um de 'ambas'. Retorna [(arquivo, qtd)]."""
    base = args.output or "dropnet_scan"
    saved = []
    if args.tcp:
        grupos = {}
        for p in ports:
            grupos[f"{base}_{p}.txt"] = [r[0] for r in results if p in r[1]]
        if len(ports) > 1:
            grupos[f"{base}_ambas.txt"] = [r[0] for r in results if set(ports) <= set(r[1])]
    else:
        grupos = {f"{base}.txt": [r[0] for r in results]}
    for nome, ips in grupos.items():
        if ips:
            with open(nome, "w", encoding="utf-8") as f:
                f.write("\n".join(ips) + "\n")
            saved.append((nome, len(ips)))
    return saved


def summary(args, ports, results, done, dur, interrupted, n_abertos=0):
    print()
    line("═", "1;36")
    titulo = "RESULTADO (interrompido)" if interrupted else "RESULTADO"
    print(c("1;97", f" {titulo}"))
    line("═", "1;36")
    rate = done / dur if dur > 0 else 0
    print(f" {c('2', 'Testados')}  {fmt(done)}    {c('2', 'Tempo')}  {dur:.0f}s    {c('2', 'Vel.')}  {rate:.0f} ip/s")
    print()

    if args.tcp:
        # contagem por porta, lado a lado
        counts = [(p, len([r for r in results if p in r[1]])) for p in ports]
        cols = "  ".join(f"{c('1;36', f'[{p}]')} {c('1;32', str(n)).rjust(2 + len(str(n)))}" for p, n in counts)
        print(f" {c('1', 'Portas')}   {cols}")
        if len(ports) > 1:
            both = len([r for r in results if set(ports) <= set(r[1])])
            print(f" {c('1', 'Ambas ')}   {c('1;36', '[' + '+'.join(map(str, ports)) + ']')} {c('1;32', str(both))}")
        print()

        # tabela: IP | col por porta
        line("─", "2")
        print(header_row(ports))
        line("─", "2")
        for r in sorted(results, key=lambda r: len(r[1]), reverse=True)[:20]:
            ip, pts = r[0], r[1]
            cells = "".join(port_cell(p, pts) for p in ports)
            print(f" {c('1', ip.ljust(16))}{cells}")
        if len(results) > 20:
            print(c("2", f"   ... +{len(results) - 20} no arquivo"))
    else:
        print(f" {c('1;32', '●')} {c('1', 'IPs OK')}  {c('32', str(len(results)))}")
        for ip, _, info, ms in results[:25]:
            print(f"   {ip.ljust(15)} {info[:24]}  {c('2', f'{ms}ms')}")
        if len(results) > 25:
            print(c("2", f"   ... +{len(results) - 25} no arquivo"))

    if args.tcp and args.confirmar:
        print()
        line("─", "2")
        print(f" {c('2', 'Abriram a porta')}  {n_abertos}    {c('2', 'Deram ' + args.status)}  {c('1;32', str(len(results)))}")
        if SEEN:
            top = ", ".join(f"{k}×{v}" for k, v in SEEN.most_common(5))
            print(c("2", f" Respostas dos demais: {top}"))
    if not results and done >= 100:
        tot = sum(FAIL.values())
        if tot:
            print()
            print(c("2", f" Falhas de conexão: timeout {FAIL['timeout']} · recusado {FAIL['recusado']} · outro {FAIL['outro']}"))
        if tot and not n_abertos and FAIL["timeout"] >= 0.9 * tot:
            print(c("33", " Nenhuma porta abriu: a rede não respondeu."))
            print(c("33", " Veja se há outro scan pausado (jobs), reative os dados"))
            print(c("33", " móveis e teste de novo com --threads 50."))

    saved = save_lists(args, ports, results)
    print()
    if saved:
        line("─", "2")
        print(c("1", " Arquivos salvos:"))
        for nome, qtd in saved:
            print(f"   {c('36', nome)} {c('2', f'({qtd})')}")
    else:
        print(c("33", " Nenhum IP encontrado."))
    print()


# ============== modo combo: payload + modo de conexão + porta ==============
# Em vez de só ver se a porta abre, testa de verdade a configuração
# (modo + porta + payload) em cada IP e devolve só quem funcionou.
MODOS = {
    "ssl": "SSL proxy (443)",
    "ssh": "SSH proxy (80)",
}
SNI_PADRAO = "www.tim.com.br"
HOST_PADRAO = "gm.azion.app"
PAYLOAD_SSL = "GET / HTTP/1.1[crlf]Host: gm.azion.app[crlf]Upgrade: websocket[crlf][crlf]"
# Na 80 não existe TLS/SNI: a SNI vai como Host da 1ª requisição ([split]),
# e a 2ª requisição leva o host real.
PAYLOAD_SSH = ("GET / HTTP/1.1[crlf]Host: " + SNI_PADRAO + "[crlf][crlf][split]"
               "GET / HTTP/1.1[crlf]Host: gm.azion.app[crlf]Upgrade: websocket[crlf][crlf]")
COMBO_SEEN = Counter()   # o que os IPs responderam (p/ diagnóstico quando nada funciona)


def parse_ports(args):
    raw = str(args.ports) if args.ports else str(args.port)
    out = []
    for x in raw.split(","):
        x = x.strip()
        if x.isdigit() and 0 < int(x) < 65536 and int(x) not in out:
            out.append(int(x))
    return out or [args.port]


def build_payload(args, target, texto=None):
    host_header = getattr(args, "host", None) or args.sni or target
    template = (texto or args.payload).replace("[crlf]", "\r\n").replace("[lf]", "\n")
    template = template.replace("[host]", host_header).replace("[ip]", target)
    template = template.replace("[ua]", APP_UA).replace("[method]", "GET")

    def rotate_token(match):
        choices = [x for x in match.group(1).split(";") if x]
        return random.choice(choices) if choices else ""
    template = re.sub(r"\[rotate=([^\]]*)\]", rotate_token, template)
    return template.encode()


def build_combos(args):
    ssl_c = ("ssl", getattr(args, "port_ssl", 443))
    ssh_c = ("ssh", getattr(args, "port_ssh", 80))
    return {"ssl": [ssl_c], "ssh": [ssh_c], "ambos": [ssh_c, ssl_c]}[args.modo]


PAYLOADS_PADRAO = {
    "1": "GET / HTTP/1.1[crlf]Host: [host][crlf]Upgrade: websocket[crlf][crlf]",
    "2": "GET / HTTP/1.1[lf]Host: [host][lf]Connection: Upgrade[lf]Upgrade: Websocket[lf][lf]",
}


PAYLOAD_NOMES = {
    "1": ("Padrão CRLF", "Upgrade: websocket"),
    "2": ("Padrão LF", "Connection: Upgrade"),
}
TOKENS_AJUDA = "[host] [crlf] [lf] [split] [rotate=a;b]"

USOU_PRESET = [False]   # True quando o usuario escolheu o payload 1 ou 2


def _limpar_payload(pl):
    return pl.replace("\\r\\n", "[crlf]").replace("\\n", "[lf]")


def pedir_payload(rotulo):
    """1 e 2 = payloads padrão (só pede o host). 3 = payload manual (colar)."""
    porta = rotulo.replace("Payload ", "")
    larg = max(24, term_width() - 9)
    print()
    print(c("1", f" Modelo para a porta {porta}"))
    for k, v in PAYLOADS_PADRAO.items():
        nome, destaque = PAYLOAD_NOMES[k]
        print(f" {c('1;36', k + ')')} {c('1', nome.ljust(11))} {c('2', '· ' + destaque)}")
        for ln in textwrap.wrap(v, larg):
            print(c("2", "      " + ln))
    print(f" {c('1;36', '3)')} {c('1', 'Manual'.ljust(11))} {c('2', '· colar o seu payload')}")
    line()
    while True:
        try:
            esc = input(c("1;36", " ❯ ") + f"{rotulo} [1/2/3]: ").strip()
        except EOFError:
            sys.exit("Payload nao informado.")
        if esc in PAYLOADS_PADRAO:
            USOU_PRESET[0] = True
            return PAYLOADS_PADRAO[esc]
        if esc == "3":
            print(c("2", f" Tokens: {TOKENS_AJUDA}"))
            while True:
                try:
                    pl = input(c("1;36", " ❯ ") + f"Cole o payload {porta}: ").strip()
                except EOFError:
                    sys.exit("Payload nao informado.")
                if pl:
                    return _limpar_payload(pl)
                print(c("31", " Payload vazio. Cole o payload."))
        if esc and not (esc.isdigit() and len(esc) <= 2):   # colou o payload direto
            return _limpar_payload(esc)
        print(c("31", " Digite 1, 2 ou 3."))


def pedir_texto(rotulo):
    """Pergunta sem exemplo/padrao: voce digita e da Enter (vazio nao vale)."""
    while True:
        try:
            v = input(c("1;36", " ❯ ") + f"{rotulo}: ").strip()
        except EOFError:
            sys.exit(f"{rotulo} nao informado.")
        if v:
            return v
        print(c("31", f" {rotulo} vazio. Digite o valor."))


def aplicar_padroes_combo(args):
    """Só preenche a SNI padrão. O payload é sempre colado manualmente."""
    if args.modo in ("ssl", "ambos") and args.payload == DEFAULT_PAYLOAD:
        args.payload = pedir_payload("Payload 443")
    if args.modo in ("ssh", "ambos") and not getattr(args, "payload_ssh", None):
        args.payload_ssh = pedir_payload("Payload 80")
    if USOU_PRESET[0] and not getattr(args, "host", None):
        args.host = pedir_texto("Host (vai no payload)")
    if args.modo in ("ssl", "ambos") and not args.sni:
        args.sni = pedir_texto("SNI (handshake TLS)")


def make_ssl_ctx(args):
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    if args.tls_version:
        v = TLS_VERSIONS[args.tls_version]
        ctx.minimum_version = v
        ctx.maximum_version = v
        if v in (ssl.TLSVersion.TLSv1, ssl.TLSVersion.TLSv1_1):
            try:
                ctx.set_ciphers("DEFAULT@SECLEVEL=0")
            except ssl.SSLError:
                pass
    return ctx


async def probe_combo(target, args, ssl_ctx, ranges, modo, porta):
    """Testa UMA combinação (modo + porta + payload) num IP.
    Retorna (info, ms) se funcionou, senão None."""
    use_tls = modo == "ssl"
    payload = build_payload(args, target, args.payload_ssh if modo == "ssh" else args.payload)
    chave = f"{modo}:{porta}"
    for _ in range(max(1, args.tentativas)):
        w = None
        t0 = time.monotonic()
        try:
            r, w = await asyncio.wait_for(
                open_conn(target, args, ssl_ctx if use_tls else None, porta, use_tls),
                args.timeout * 2 if use_tls else args.timeout)
        except Exception:
            COMBO_SEEN[f"{chave} não conectou"] += 1
            continue
        try:
            # [split] divide o payload em requisições enviadas em sequência na
            # mesma conexão (ex.: 1ª com Host da SNI, 2ª com o Host real).
            # A resposta das partes anteriores é descartada; vale a da última.
            partes = [p for p in payload.split(b"[split]") if p]
            for i, parte in enumerate(partes):
                w.write(parte)
                await w.drain()
                if i < len(partes) - 1:
                    try:
                        await asyncio.wait_for(r.read(65536), min(args.timeout, 1.0))
                    except asyncio.TimeoutError:
                        pass
            raw = await asyncio.wait_for(r.readline(), args.timeout)
            linha = raw.decode("latin-1", "replace").strip()
            ms = int((time.monotonic() - t0) * 1000)
            if modo == "ssh" and linha.startswith("SSH-"):
                return linha[:40], ms
            m = re.match(r"HTTP/\d(?:\.\d)?\s+(\d{3})", linha)
            if m and status_ok(int(m.group(1)), ranges):
                return linha, ms
            COMBO_SEEN[f"{chave} respondeu {m.group(1) if m else 'não-HTTP'}"] += 1
        except Exception:
            COMBO_SEEN[f"{chave} conectou e não respondeu"] += 1
        finally:
            try:
                w.close()
            except Exception:
                pass
    return None


async def run_combo(args):
    ranges = parse_status_spec(args.status)
    combos = build_combos(args)
    COMBO_SEEN.clear()
    ssl_ctx = make_ssl_ctx(args) if any(m == "ssl" for m, _ in combos) else None
    nofile = raise_nofile()
    threads = max(1, min(args.threads, (nofile - 64) // len(combos)))
    targets, total = build_targets(args)
    sem = asyncio.Semaphore(threads)
    hits = []          # (ip, modo, porta, info, ms)
    done = 0
    start = time.monotonic()
    last_draw = 0.0
    interrupted = False

    def redraw(force=False):
        nonlocal last_draw
        now = time.monotonic()
        if not UI.color:
            return
        if force or now - last_draw > 0.15:
            sys.stdout.write("\r\033[K" + progress_line(done, total, len(hits), start))
            sys.stdout.flush()
            last_draw = now

    def show_hit(ip, modo, porta, info, ms):
        txt = (f" {c('1;32', '✔')} {c('1', ip.ljust(15))} "
               f"{c('1;36', f'{modo}:{porta}'.ljust(9))} {c('32', info[:24])}  {c('2', f'{ms}ms')}")
        if UI.color:
            sys.stdout.write("\r\033[K" + txt + "\n")
        else:
            print(txt, flush=True)

    async def worker(ip):
        nonlocal done
        try:
            res = await asyncio.gather(
                *(probe_combo(ip, args, ssl_ctx, ranges, m, p) for m, p in combos))
        finally:
            sem.release()
        done += 1
        achou = False
        for (m, p), ok in zip(combos, res):
            if ok:
                achou = True
                hits.append((ip, m, p, ok[0], ok[1]))
                show_hit(ip, m, p, ok[0], ok[1])
        redraw(achou)
        if not UI.color and done % 1000 == 0:
            print(f"... {done} testados, {len(hits)} ok", flush=True)

    tasks = set()
    try:
        for t in targets:
            await sem.acquire()
            tk = asyncio.create_task(worker(t))
            tasks.add(tk)
            tk.add_done_callback(tasks.discard)
        while tasks:
            await asyncio.wait(set(tasks))
    except (KeyboardInterrupt, asyncio.CancelledError):
        interrupted = True
        for tk in list(tasks):
            tk.cancel()
        await asyncio.gather(*list(tasks), return_exceptions=True)

    if UI.color:
        sys.stdout.write("\r\033[K")
    summary_combo(args, combos, hits, done, time.monotonic() - start, interrupted)


def summary_combo(args, combos, hits, done, dur, interrupted):
    print()
    line("═", "1;36")
    print(c("1;97", " RESULTADO (interrompido)" if interrupted else " RESULTADO"))
    line("═", "1;36")
    rate = done / dur if dur > 0 else 0
    print(f" {c('2', 'Testados')}  {fmt(done)}    {c('2', 'Tempo')}  {dur:.0f}s    {c('2', 'Vel.')}  {rate:.0f} ip/s")
    for m, p in combos:
        pl = args.payload_ssh if m == "ssh" else args.payload
        print(f" {c('2', f'Payload {p}')}  {pl.replace(chr(10), ' ')[:60]}")
    print()
    print(c("1", " Quem funcionou, por configuração:"))
    for m, p in combos:
        n = len([h for h in hits if h[1] == m and h[2] == p])
        cor = "1;32" if n else "2"
        print(f"   {c('1;36', f'{m}:{p}'.ljust(10))} {c(cor, str(n))}")
    ips_ok = sorted({h[0] for h in hits})
    print(f"\n {c('1', 'IPs que funcionaram')}  {c('1;32', str(len(ips_ok)))}")
    for h in hits[:20]:
        print(f"   {h[0].ljust(15)} {f'{h[1]}:{h[2]}'.ljust(9)} {h[3][:24]}")
    if len(hits) > 20:
        print(c("2", f"   ... +{len(hits) - 20} no arquivo"))

    if not hits and COMBO_SEEN:
        print()
        print(c("2", " O que os IPs responderam:"))
        for k, v in COMBO_SEEN.most_common(6):
            print(c("2", f"   {k} ×{v}"))

    base = args.output or "dropnet_scan"
    saved = []
    if hits:
        nome = f"{base}_funcionando.txt"
        with open(nome, "w", encoding="utf-8") as f:
            for ip, m, p, info, ms in hits:
                f.write(f"{ip}:{p};{m};{info};{ms}ms\n")
        saved.append((nome, len(hits)))
        for m, p in combos:
            ips = [h[0] for h in hits if h[1] == m and h[2] == p]
            if ips and len(combos) > 1:
                nome = f"{base}_{m}_{p}.txt"
                with open(nome, "w", encoding="utf-8") as f:
                    f.write("\n".join(ips) + "\n")
                saved.append((nome, len(ips)))
    print()
    if saved:
        line("─", "2")
        print(c("1", " Arquivos salvos:"))
        for nome, qtd in saved:
            print(f"   {c('36', nome)} {c('2', f'({qtd})')}")
    else:
        print(c("33", " Nenhum IP funcionou com essa configuração."))
    print()


def ask_busca(args):
    """Assistente da busca: tipo (proxy + payload / só proxy), porta,
    payload, host e SNI. Deixa o args pronto para run() ou run_combo()."""
    etapa("ETAPA 1 · Tipo de busca")
    opcao("1", "Proxy + Payload".ljust(16), "testa de verdade")
    opcao("2", "Só Proxy".ljust(16), "só vê se a porta abre")
    line()
    so_proxy = escolher("Tipo", ("1", "2"), "1") == "2"

    etapa("ETAPA 2 · Porta")
    if so_proxy:
        opcao("1", "443".ljust(8), "porta TLS (HTTPS)")
        opcao("2", "80".ljust(8), "porta HTTP")
        opcao("3", "80 + 443".ljust(8), "as duas")
    else:
        opcao("1", "443".ljust(8), "SSL · TLS + SNI + payload")
        opcao("2", "80".ljust(8), "SSH · payload com [split]")
        opcao("3", "80 + 443".ljust(8), "os dois")
    line()
    esc = escolher("Porta", ("1", "2", "3"), "3")

    if so_proxy:
        # Só Proxy = só confere se a porta abre (sem payload, sem status).
        args.modo = None
        args.ports = {"1": "443", "2": "80", "3": "80,443"}[esc]
        args.port = int(args.ports.split(",")[0])
        args.tcp = True
        args.confirmar = False
        args.tls = False
        args.tentativas = 1
        args.output = args.output + "_proxy"
        return

    args.modo = {"1": "ssl", "2": "ssh", "3": "ambos"}[esc]
    args.port_ssl, args.port_ssh = 443, 80
    USOU_PRESET[0] = False
    tem_tls = args.modo in ("ssl", "ambos")
    tem_80 = args.modo in ("ssh", "ambos")

    etapa("ETAPA 3 · Payload")
    args.payload = pedir_payload("Payload 443") if tem_tls else DEFAULT_PAYLOAD
    args.payload_ssh = pedir_payload("Payload 80") if tem_80 else ""

    etapa("ETAPA 4 · Host, SNI e status")
    usados = ([args.payload] if tem_tls else []) + ([args.payload_ssh] if tem_80 else [])
    precisa_host = any("[host]" in p for p in usados)
    if precisa_host:
        print(c("2", " Host = valor do [host] no payload"))
    if tem_tls:
        print(c("2", " SNI  = nome do handshake TLS (só na 443)"))
    if precisa_host or tem_tls:
        print()
    args.host = pedir_texto("Host") if precisa_host else None
    if tem_tls:
        args.sni = pedir_texto("SNI")
    args.status = ask("Status de sucesso", "101")
    args.tcp = False
    args.confirmar = False
    args.tls = False
    args.tentativas = 1
    args.output = args.output + "_" + args.modo


# ============================ menu ============================
def ask(texto, padrao):
    r = input(c("1;36", " ❯ ") + f"{texto.strip()} [{padrao}]: ").strip()
    return r if r else str(padrao)


def show_menu(provs):
    banner()
    print()
    print(c("1", " Escolha a CDN / provedor"))
    line()
    n = len(provs)
    metade = (n + 1) // 2
    two_cols = term_width() >= 38
    if two_cols:
        for k in range(metade):
            esq = f"{k + 1:>2}) {provs[k]['name']:<13}"
            j = k + metade
            dir_ = f"{j + 1:>2}) {provs[j]['name']}" if j < n else ""
            print(" " + c("36", esq[:4]) + esq[4:] + "  " + (c("36", dir_[:4]) + dir_[4:] if dir_ else ""))
    else:
        for i, p in enumerate(provs, 1):
            print(f" {c('36', f'{i:>2})')} {p['name']}")
    line()
    print(f" {c('36', ' 0)')} TODOS        {c('36', ' q)')} sair")
    print()


def interactive(base):
    provs = load_providers(base.providers)
    while True:
        show_menu(provs)
        try:
            esc = input(c("1;36", " ❯ ") + "Número da CDN (ex.: 5 ou 1,4,7): ").strip().lower()
        except EOFError:
            return None
        if esc in ("q", "sair", "exit"):
            return None
        if esc == "0":
            nomes = [p["name"] for p in provs]
        else:
            nomes = []
            for x in esc.replace(" ", "").split(","):
                if x.isdigit() and 1 <= int(x) <= len(provs):
                    nomes.append(provs[int(x) - 1]["name"])
        if nomes:
            break
        print(c("31", "\n Opção inválida.\n"))

    args = copy.copy(base)
    args.provider = nomes
    args.tcp = True
    # A aba Scanner do APK identifica portas TCP abertas; não exige HTTP 101.
    # A confirmação HTTP fica disponível separadamente com --confirmar / modo avançado.
    args.confirmar = False
    args.tentativas = 1
    args.ports = "80,443"
    args.port = 80
    args.tls = False
    args.status = "101;200;301-302;400;403;404;426"
    args.threads = 150
    args.timeout = 2.0
    args.shuffle = True
    args.output = "dropnet_" + (nomes[0] if len(nomes) == 1 else "multi")

    cidrs = provider_cidrs(args.providers, nomes)

    if len(nomes) == 1 and len(cidrs) > 1:
        print()
        print(c("2", f" {len(cidrs)} faixas em {nomes[0]}. Enter = todas, ou busque (ex.: 179.191, 10.0.0.0/24):"))
        busca = input(c("1;36", " ❯ ") + "Buscar faixa: ").strip()
        if busca:
            achadas = [cd for cd in cidrs if busca in cd]
            if achadas:
                print(c("2", f" {len(achadas)} faixa(s) encontrada(s):"))
                for cd in achadas[:15]:
                    print(f"   {cd}")
                if len(achadas) > 15:
                    print(c("2", f"   ... +{len(achadas) - 15}"))
                esc2 = input(c("1;36", " ❯ ") + "Usar essas faixas? (s/n) [s]: ").strip().lower()
                if esc2 != "n":
                    cidrs = achadas
                    args.output = "dropnet_" + nomes[0] + "_busca"
            else:
                print(c("33", " Nenhuma faixa corresponde. Usando todas."))

    total = total_ips(cidrs)
    args.max_ips = 1000000   # sem amostra: testa TODOS os IPs, mesmo em CDNs grandes

    args.modo = None
    ask_busca(args)

    if args.avancado:
        if not args.modo:   # Só Proxy: opção de confirmar com status real
            args.confirmar = ask("Confirmar com status real (101/200)? (s/n)", "n").lower().startswith("s")
            if args.confirmar:
                print(c("33", " A confirmação só bate se o Host/SNI forem os certos"))
                print(c("33", " dessa CDN/operadora (o mesmo valor que funciona na sua VPN)."))
                args.payload = pedir_payload(f"Payload {args.port}")
                args.host = pedir_texto("Host (vai no payload)")
                args.status = ask("Status de sucesso", args.status)
                args.tentativas = int(ask("Tentativas por IP", args.tentativas))
        args.max_ips = int(ask("Quantos IPs testar (0 = todos)", args.max_ips))
        args.threads = int(ask("Threads", args.threads))
        args.timeout = float(ask("Timeout (s)", args.timeout))
        args.shuffle = args.max_ips > 0

    sel = min(total, args.max_ips) if args.max_ips else total
    print()
    line("═", "1;36")
    info_row("CDN", c("1", ", ".join(nomes)))
    info_row("Faixas", f"{len(cidrs)}  ·  {fmt(sel)} IPs" + (c("2", "  (amostra)") if args.max_ips else ""))
    if args.modo:
        info_row("Busca", c("1", "Proxy + Payload"))
        info_row("Portas", " + ".join(f"{p} ({m})" for m, p in build_combos(args)))
        if args.host:
            info_row("Host", args.host)
        if args.modo in ("ssl", "ambos") and args.sni:
            info_row("SNI", args.sni)
        info_row("Status", args.status)
    else:
        info_row("Busca", c("1", "Só Proxy") + c("2", "  (sem payload)"))
        info_row("Portas", " + ".join(map(str, resolve_ports(args))))
        if args.confirmar:
            info_row("Status", args.status)
    info_row("Threads", f"{args.threads}  ·  timeout {args.timeout:g}s")
    line("═", "1;36")
    print(c("2", " Ctrl+C para parar"))
    print()
    return args



# ============================ diagnóstico ============================
APP_UA = "ScannerV4/1.0"


def diag_variants(host):
    return [
        ("GET simples",
         f"GET / HTTP/1.1\r\nHost: {host}\r\nUser-Agent: {APP_UA}\r\nAccept: */*\r\nConnection: close\r\n\r\n"),
        ("Upgrade (payload padrão)",
         DEFAULT_PAYLOAD.replace("[crlf]", "\r\n").replace("[host]", host)),
        ("Upgrade + UA do app",
         f"GET / HTTP/1.1\r\nHost: {host}\r\nUser-Agent: {APP_UA}\r\nAccept: */*\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\r\n"),
        ("WebSocket completo",
         f"GET / HTTP/1.1\r\nHost: {host}\r\nUser-Agent: {APP_UA}\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n"
         f"Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nSec-WebSocket-Version: 13\r\n\r\n"),
    ]


async def diag_one(ip, port, tls, nome, req, args):
    ctx = None
    if tls:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
    w = None
    try:
        r, w = await asyncio.wait_for(asyncio.open_connection(
            ip, port, ssl=ctx, server_hostname=(args.sni or ip) if tls else None), 4)
        w.write(req.encode())
        await w.drain()
        data = await asyncio.wait_for(r.read(1024), 4)
        txt = data.decode("latin-1", "replace")
        first = txt.split("\r\n", 1)[0].strip() or "(vazio)"
        srv = re.search(r"(?im)^server:\s*(.+)$", txt)
        return first[:34] + (f"  [{srv.group(1).strip()[:14]}]" if srv else "")
    except asyncio.TimeoutError:
        return "timeout"
    except Exception as e:
        return f"falhou ({type(e).__name__})"
    finally:
        if w is not None:
            try:
                w.close()
            except Exception:
                pass


async def diag(args):
    portas = [int(x) for x in (args.ports or "80,443").split(",")]
    banner()
    print(c("1", "\n Diagnóstico de requisição"))
    for ip in args.diag:
        print()
        line("═", "1;36")
        print(c("1;97", f" {ip}"))
        line("═", "1;36")
        for porta in portas:
            tls = porta == 443
            print(c("1;33", f" Porta {porta}") + c("2", "  (TLS)" if tls else ""))
            for nome, req in diag_variants(args.sni or ip):
                res = await diag_one(ip, porta, tls, nome, req, args)
                cor = "1;32" if " 101" in res else ("33" if " 200" in res else "2")
                print(f"  {nome:<25}{c(cor, res)}")
    print()


def build_parser():
    p = argparse.ArgumentParser(description="DROPNET SCANNER - scanner IPv4 por CDN/provedor")
    g = p.add_argument_group("alvos")
    g.add_argument("--cidr", action="append", help="faixa CIDR (pode repetir)")
    g.add_argument("--cidr-file", help="arquivo com um CIDR por linha")
    g.add_argument("--providers", default="providers.json", help="arquivo providers.json")
    g.add_argument("--provider", action="append", help="nome do provedor (azion, cloudflare...)")
    g.add_argument("--hosts", help="arquivo com hosts/IPs (um por linha)")
    g.add_argument("--max-ips", type=int, default=0, help="limite de IPs (0 = todos)")
    g.add_argument("--shuffle", action="store_true", help="embaralha as faixas")

    c_ = p.add_argument_group("conexão")
    c_.add_argument("--port", type=int, default=80)
    c_.add_argument("--ports", help="várias portas (modo --tcp), ex.: 80,443")
    c_.add_argument("--modo", choices=["ssl", "ssh", "ambos"],
                    help="proxy: ssl=443, ssh=80, ambos=80+443 (testa de verdade e lista só quem funcionou)")
    c_.add_argument("--payload-ssh", help="payload da porta 80 (aceita [split])")
    c_.add_argument("--tcp", action="store_true", help="só testa se a porta abre (sem payload)")
    c_.add_argument("--tls", action="store_true", help="usar TLS/SNI (modo payload)")
    c_.add_argument("--sni", help="SNI / valor do [host] no payload")
    c_.add_argument("--host", help="valor do [host] no payload (modo combo; separado da SNI)")
    c_.add_argument("--tls-version", choices=TLS_VERSIONS)
    c_.add_argument("--proxy", help="proxy HTTP CONNECT host:porta")
    c_.add_argument("--payload", default=DEFAULT_PAYLOAD, help="use [crlf], [lf], [host], [ip], [ua], [method], [rotate=a;b]")
    c_.add_argument("--status", default="101;200", help='ex.: "101;200;301-302"')

    r = p.add_argument_group("desempenho / saída")
    r.add_argument("--threads", type=int, default=100, help="IPs testados ao mesmo tempo")
    r.add_argument("--timeout", type=float, default=2.0, help="timeout em segundos")
    r.add_argument("-o", "--output", default="", help="prefixo dos arquivos de saída")
    r.add_argument("--debug", action="store_true", help="mostra o motivo de cada falha")
    r.add_argument("--avancado", action="store_true", help="no menu, pergunta mais opções")
    r.add_argument("--confirmar", action="store_true", help="depois do TCP, confirma de verdade (status) em quem abriu porta")
    r.add_argument("--tentativas", type=int, default=1, help="tentativas por IP na confirmação (rede instável)")
    r.add_argument("--diag", nargs="+", metavar="IP", help="testa várias formas de requisição nesses IPs")
    r.add_argument("--no-color", action="store_true", help="sem cores")
    return p


def main():
    args = build_parser().parse_args()
    if args.no_color:
        UI.color = False

    if args.diag:
        try:
            asyncio.run(diag(args))
        except KeyboardInterrupt:
            pass
        return

    if not (args.cidr or args.cidr_file or args.provider or args.hosts):
        try:
            while True:
                a = interactive(args)
                if a is None:
                    break
                try:
                    asyncio.run(run_combo(a) if a.modo else run(a))
                except KeyboardInterrupt:
                    pass
                try:
                    r = input(c("2", " Enter = voltar ao menu  ·  q = sair: ")).strip().lower()
                except EOFError:
                    break
                if r in ("q", "sair", "0"):
                    break
        except KeyboardInterrupt:
            pass
        print(c("2", "\n Até mais.\n"))
        return

    try:
        if args.modo:
            aplicar_padroes_combo(args)
            args.port_ssl, args.port_ssh = 443, 80
            args.tentativas = max(1, args.tentativas)
            asyncio.run(run_combo(args))
        else:
            asyncio.run(run(args))
    except KeyboardInterrupt:
        pass


if __name__ == "__main__":
    main()
