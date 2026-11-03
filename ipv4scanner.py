#!/usr/bin/env python3
"""
DROPNET SCANNER v3.0
Varre faixas de CDNs/provedores e separa os IPs por porta (80 / 443).

Novidades da v3.0:
  - Vários Host/SNI em rodízio: ao perguntar Host ou SNI no menu, agora dá
    pra adicionar mais de um ("Adicionar outro?"). Com 2+ valores, um
    diferente é sorteado a cada requisição (Host e SNI de forma
    independente), em vez de bater sempre no mesmo domínio
  - Novo --hosts-lista / --sni-lista: carrega vários Hosts/SNIs de um
    arquivo (um por linha) pra usar fora do menu interativo

Novidades da v2.7:
  - Novo estilo de cabeçalho: "Upgrade" sozinho, sem ": valor" (não é HTTP
    válido, mas algumas CDNs — como a Azion neste caso — só checam se a
    palavra aparece e já trocam para 101)
  - O payload exato confirmado em uso real (HEAD /ws, sem User-Agent,
    "Upgrade" sozinho) agora está garantido entre as variações testadas
  - Gerador: de 432 para 522 variações

Novidades da v2.6.1:
  - Corrigido bug grave: a opção 4 (Gerar) do assistente, quando aberta de
    dentro do menu da CDN, herdava o status largo do "Só Proxy"
    (101;200;301-302;400;403;404;426) e aceitava 404/403 como "funcionou".
    Agora sempre pergunta o status esperado e mostra qual está usando.

Novidades da v2.6:
  - Gerador de payload: de 120 para 432 variações
  - Novos tipos de split: [instant_split] (sem espera) e [delay_split]
    (espera --split-delay segundos, padrão 2.0) além do [split] de sempre
  - Novo estilo de cabeçalho: Content-Length falso (9999999999999)
  - Novo método testado: ACL (além de GET e HEAD)

Novidades da v2.5:
  - Gerador de payload ampliado: de 24 para 120 variações (5 estilos de
    cabeçalho × 3 caminhos × 2 métodos × 2 quebras de linha, cada uma com
    e sem [split] — 1ª requisição no SNI, 2ª no Host real)
  - Novo token [sni] no payload, separado do [host]

Novidades da v2.4.1:
  - Corrigido: o gerador de payload (opção 4) agora pergunta Host e SNI
    separados, em vez de usar o mesmo valor para os dois

Novidades da v2.4:
  - Gerador de payload: testa várias variações num IP e mostra as que funcionaram (--gerar-payload IP)
  - Testador de Host/SNI: testa uma lista de hosts com o payload atual (--testar-hosts arquivo.txt --ip IP)
  - Perfis por rede: salva e carrega modo/host/sni/payload com um nome (--salvar-perfil / --usar-perfil / --listar-perfis)
  - No assistente de payload (opções 1/2/3), nova opção 4) Gerar

Novidades da v2.3:
  - Ranking de latência: mede os IPs achados 3x e ordena (média, mín, jitter)
  - Retomar scan: Ctrl+C ou Termux fechado não perde o progresso
  - Modo rápido (opcional, --rapido): amostra cada /24 e só varre blocos que responderam

Novidades da v2.2:
  - TLS correto na 443 na revisão dos IPs sem resposta
  - faixas sobrepostas são unidas (sem IP repetido)
  - hits salvos na hora em <prefixo>_parcial.txt (não perde se o Termux fechar)
  - sockets fechados corretamente (wait_closed)
  - semáforo não vaza ao cancelar (Ctrl+C)
  - entradas numéricas validadas no modo avançado
  - "todos os IPs" agora é realmente todos (0 = sem limite)
  - embaralha por blocos /24 (menos chance de rate limit)

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
import hashlib
import ipaddress
import itertools
import json
import os
import random
import re
import shutil
import ssl
import sys
import textwrap
import time

VERSION = "3.0"
# Pasta fixa para salvar automaticamente os resultados no Android/Termux.
# O caminho ~/storage/downloads é o atalho criado pelo termux-setup-storage.
OUTPUT_DIR = os.path.join(os.path.expanduser("~"), "storage", "downloads", "DROPNET-SCANNER")


def output_path(filename):
    """Cria a pasta automaticamente e devolve o caminho do arquivo de saída."""
    global OUTPUT_DIR
    candidatos = [
        OUTPUT_DIR,
        "/storage/emulated/0/Download/DROPNET-SCANNER",
    ]
    ultimo_erro = None
    for pasta in candidatos:
        try:
            os.makedirs(pasta, exist_ok=True)
            OUTPUT_DIR = pasta
            return os.path.join(OUTPUT_DIR, os.path.basename(filename))
        except OSError as erro:
            ultimo_erro = erro
    raise OSError(
        "Não foi possível acessar a pasta de Downloads. "
        "No Termux, execute termux-setup-storage uma única vez e permita o acesso."
    ) from ultimo_erro


RETRY_TOTAL_LIMIT = 20000   # até esse tamanho, guarda quem NUNCA respondeu p/ tentar de novo

FAIL = Counter()   # por que as conexões falharam (timeout / recusado / outro)
SEEN = Counter()   # o que os IPs com porta aberta responderam ao teste real
PARCIAL = {}       # arquivo de hits salvos na hora (nome -> caminho)

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


# ============================ utilidades ============================
async def fechar(w):
    """Fecha o socket de verdade (close + wait_closed), sem travar."""
    if w is None:
        return
    try:
        w.close()
        await asyncio.wait_for(w.wait_closed(), 2)
    except Exception:
        pass


def salvar_parcial(args, linha):
    """Grava cada hit na hora, para não perder nada se o app for fechado."""
    nome = (args.output or "dropnet_scan") + "_parcial.txt"
    try:
        if nome not in PARCIAL:
            PARCIAL[nome] = output_path(nome)
            open(PARCIAL[nome], "a" if PARCIAL_MANTER[0] else "w", encoding="utf-8").close()
        with open(PARCIAL[nome], "a", encoding="utf-8") as f:
            f.write(linha + "\n")
    except OSError:
        pass


PARCIAL_MANTER = [False]   # True ao retomar: não apaga o parcial anterior
RANK_MAX = 300             # máximo de IPs medidos no ranking
RAPIDO = Counter()         # estatísticas do modo rápido
CHECKPOINT_FORMATO = 1


# ----------------------------- modo rápido -----------------------------
def rapido_ativo(args):
    """Modo rápido só vale para faixas completas (não com --hosts nem limite de IPs)."""
    return bool(getattr(args, "rapido", False)) and not args.hosts and not args.max_ips


def aviso_rapido(args):
    if not getattr(args, "rapido", False):
        return
    if not rapido_ativo(args):
        print(c("33", " Modo rápido ignorado (não vale com --hosts ou limite de IPs)."))
        return
    print(c("33", " Modo rápido: blocos /24 sem resposta nas amostras são pulados."))
    print(c("33", " Pode perder IPs isolados. Retomar scan fica desativado."))


def mostrar_rapido():
    if not RAPIDO:
        return
    line("─", "2")
    print(c("1", " Modo rápido"))
    print(f"   {RAPIDO['blocos_varridos']} blocos varridos · {RAPIDO['blocos_pulados']} pulados")
    print(c("2", f"   {fmt(RAPIDO['ips_pulados'])} IPs não testados"))
    print()


async def aiter_sync(it):
    """Adapta um iterador comum para 'async for'."""
    for x in it:
        yield x


async def alvos_rapido(args, blocos, portas, pular):
    """Fase 1: testa algumas amostras de cada bloco /24.
    Fase 2: só entrega os IPs dos blocos em que alguma amostra respondeu."""
    amostras = max(1, getattr(args, "rapido_amostras", 3))
    simultaneos = max(5, args.threads // max(1, amostras * len(portas)))
    fila = asyncio.Queue(maxsize=1000)
    FIM = object()
    it = iter(blocos)

    async def sondar():
        for bloco in it:
            ips = [str(ip) for ip in bloco]
            amostra = random.sample(ips, min(amostras, len(ips)))
            vivos = await asyncio.gather(*(probe_tcp(ip, args, portas) for ip in amostra))
            if any(vivos):
                RAPIDO["blocos_varridos"] += 1
                for ip in ips:
                    await fila.put(ip)
            else:
                RAPIDO["blocos_pulados"] += 1
                RAPIDO["ips_pulados"] += len(ips)
                pular(len(ips))

    async def encerrar(tarefas):
        await asyncio.gather(*tarefas, return_exceptions=True)
        await fila.put(FIM)

    tarefas = [asyncio.create_task(sondar()) for _ in range(simultaneos)]
    fim = asyncio.create_task(encerrar(tarefas))
    try:
        while True:
            ip = await fila.get()
            if ip is FIM:
                break
            yield ip
    finally:
        fim.cancel()
        for t in tarefas:
            t.cancel()


def build_alvos(args, portas, pular, skip, rng):
    """Devolve (iterador assíncrono de IPs, total). Aplica retomada e modo rápido."""
    targets, total = build_targets(args, rng)
    if rapido_ativo(args):
        blocos = blocos_24(coletar_cidrs(args), args.shuffle, rng)
        return alvos_rapido(args, blocos, portas, pular), total
    if skip:
        targets = itertools.islice(targets, skip, None)
    return aiter_sync(targets), total


# ----------------------------- retomar scan -----------------------------
def chave_scan(args, tag):
    """Identifica a configuração do scan: só retoma se for exatamente a mesma."""
    partes = [
        CHECKPOINT_FORMATO, tag,
        args.hosts if args.hosts else sorted(coletar_cidrs(args)),
        args.max_ips, bool(args.shuffle), str(args.ports), args.port, bool(args.tcp),
        bool(getattr(args, "confirmar", False)), getattr(args, "modo", None),
        getattr(args, "payload", ""), getattr(args, "payload_ssh", ""),
        getattr(args, "host", None), getattr(args, "sni", None),
        args.status, bool(args.tls),
    ]
    return hashlib.sha1(repr(partes).encode()).hexdigest()


class Checkpoint:
    """Guarda o progresso do scan para retomar depois (Ctrl+C / Termux fechado)."""

    def __init__(self, args, tag):
        self.ativo = not rapido_ativo(args)   # o modo rápido não tem ordem fixa
        self.retomou = False
        self.idx = 0
        self.hits = []
        self.seed = random.randrange(1 << 30)
        self.ultimo = time.monotonic()
        if not self.ativo:
            return
        self.path = output_path((args.output or "dropnet_scan") + "_retomar.json")
        self.key = chave_scan(args, tag)
        self._carregar(args)

    def _carregar(self, args):
        if getattr(args, "novo", False):
            return
        try:
            with open(self.path, encoding="utf-8") as f:
                d = json.load(f)
        except (OSError, ValueError):
            return
        if d.get("key") != self.key or d.get("idx", 0) <= 0:
            return
        if not getattr(args, "retomar", False):
            if not sys.stdin.isatty():
                return
            print()
            print(c("33", f" Scan anterior parou no IP nº {fmt(d['idx'])} "
                          f"({len(d.get('hits', []))} achados guardados)."))
            try:
                r = input(c("1;36", " ❯ ") + "Retomar de onde parou? (s/n) [s]: ").strip().lower()
            except EOFError:
                return
            if r == "n":
                return
        self.seed, self.idx = d["seed"], d["idx"]
        self.hits, self.retomou = d.get("hits", []), True
        print(c("2", f" Retomando do IP nº {fmt(self.idx)} · {len(self.hits)} achados guardados"))

    def devido(self):
        return self.ativo and time.monotonic() - self.ultimo >= 5

    def salvar(self, idx, hits, force=False):
        if not self.ativo:
            return
        self.ultimo = time.monotonic()
        d = {"key": self.key, "seed": self.seed, "idx": idx, "hits": [list(h) for h in hits]}
        tmp = self.path + ".tmp"
        try:
            with open(tmp, "w", encoding="utf-8") as f:
                json.dump(d, f)
            os.replace(tmp, self.path)
        except OSError:
            pass

    def concluir(self):
        if self.ativo:
            try:
                os.remove(self.path)
            except OSError:
                pass


# ----------------------------- ranking de latência -----------------------------
async def tcp_ms(ip, args, porta):
    t0 = time.monotonic()
    w = None
    try:
        _, w = await asyncio.wait_for(
            open_conn(ip, args, None, porta, use_tls=False), args.timeout)
        return int((time.monotonic() - t0) * 1000)
    except Exception:
        return None
    finally:
        await fechar(w)


async def http_ms(ip, args, ssl_ctx, ranges, porta):
    r = await probe_http(ip, args, ssl_ctx, ranges, port=porta)
    return r[3] if r else None


async def combo_ms(ip, args, ssl_ctx, ranges, modo, porta):
    r = await probe_combo(ip, args, ssl_ctx, ranges, modo, porta)
    return r[1] if r else None


async def ranquear(itens, rodadas=3):
    """itens: [(ip, rotulo, fabrica)] onde fabrica() devolve uma corrotina -> ms ou None.
    Mede cada IP algumas vezes e ordena do melhor para o pior."""
    itens = itens[:RANK_MAX]
    if not itens:
        return []
    print(c("2", f" Medindo latência de {len(itens)} IPs..."), flush=True)
    sem = asyncio.Semaphore(30)

    async def um(ip, rotulo, fab):
        amostras = []
        async with sem:
            for _ in range(rodadas):
                ms = await fab()
                if ms is not None:
                    amostras.append(ms)
                await asyncio.sleep(0.05)
        if not amostras:
            return None
        return {"ip": ip, "rotulo": rotulo, "media": int(sum(amostras) / len(amostras)),
                "minimo": min(amostras), "jitter": max(amostras) - min(amostras),
                "ok": len(amostras), "de": rodadas}

    res = await asyncio.gather(*(um(*i) for i in itens), return_exceptions=True)
    res = [r for r in res if isinstance(r, dict)]
    res.sort(key=lambda r: (-r["ok"], r["media"], r["jitter"]))
    return res


def mostrar_ranking(args, ranking):
    if not ranking:
        print(c("33", " Ranking: nenhum IP respondeu na medição."))
        print()
        return
    print()
    line("═", "1;36")
    print(c("1;97", " RANKING DE LATÊNCIA"))
    line("═", "1;36")
    print(c("2", f" {'IP':<15} {'cfg':<7} {'média':>6} ok"))
    for r in ranking[:10]:
        cor = "1;32" if r["ok"] == r["de"] else "33"
        print(f" {c('1', r['ip'].ljust(15))} {r['rotulo']:<7} {r['media']:>4}ms "
              f"{c(cor, str(r['ok']) + '/' + str(r['de']))}")
    if len(ranking) > 10:
        print(c("2", f"   ... +{len(ranking) - 10} no arquivo"))
    caminho = output_path((args.output or "dropnet_scan") + "_ranking.txt")
    with open(caminho, "w", encoding="utf-8") as f:
        for r in ranking:
            f.write(f"{r['ip']};{r['rotulo']};{r['media']}ms;min {r['minimo']}ms;"
                    f"jitter {r['jitter']}ms;{r['ok']}/{r['de']}\n")
    print()
    print(c("1", " Ranking salvo:"))
    print(f"   {c('36', caminho)} {c('2', f'({len(ranking)})')}")
    print()


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
    # Une faixas sobrepostas/adjacentes: nenhum IP é testado duas vezes.
    return list(ipaddress.collapse_addresses(nets))


def total_ips(cidrs):
    return sum(n.num_addresses for n in parse_nets(cidrs))


def dividir_24(nets, rng=None, embaralhar=True):
    """Quebra as faixas em blocos /24 (e embaralha a ordem dos blocos)."""
    blocos = []
    for net in nets:
        if net.prefixlen < 24:
            blocos.extend(net.subnets(new_prefix=24))
        else:
            blocos.append(net)
    if embaralhar:
        (rng or random).shuffle(blocos)
    return blocos


def blocos_24(cidrs, shuffle, rng=None):
    return dividir_24(parse_nets(cidrs), rng, shuffle)


def iter_targets(cidrs, max_ips, shuffle, rng=None):
    """Gera IPs sem carregar tudo na memória. Com limite, sorteia IPs
    espalhados por TODAS as faixas. Com rng fixo, a ordem é repetível
    (necessário para retomar um scan)."""
    rng = rng or random
    nets = parse_nets(cidrs)
    sizes = [n.num_addresses for n in nets]
    total = sum(sizes)
    if max_ips and max_ips < total:
        starts, acc = [], 0
        for sz in sizes:
            starts.append(acc)
            acc += sz
        for off in sorted(rng.sample(range(total), max_ips)):
            k = bisect.bisect_right(starts, off) - 1
            yield str(nets[k][off - starts[k]])
        return
    if shuffle:
        # Embaralha por blocos /24: espalha a carga e evita rate limit
        # por varrer uma faixa inteira em sequência.
        nets = dividir_24(nets, rng, True)
    for net in nets:
        for ip in net:
            yield str(ip)


def iter_hosts(path):
    with open(path, encoding="utf-8") as f:
        for ln in f:
            ln = ln.strip()
            if ln and not ln.startswith("#"):
                yield ln


# ---------------------- vários Hosts/SNIs (rodízio) ----------------------
def carregar_pools(args):
    """Carrega --hosts-lista / --sni-lista (um valor por linha) em
    args._hosts_pool / args._sni_pool. Com um pool carregado, cada
    requisição sorteia um valor diferente em vez de usar sempre o mesmo
    Host/SNI fixo — útil pra não depender de um único domínio na varredura."""
    if getattr(args, "hosts_lista", None):
        pool = [h for h in iter_hosts(args.hosts_lista)]
        if not pool:
            sys.exit(f"{args.hosts_lista} está vazio.")
        args._hosts_pool = pool
    if getattr(args, "sni_lista", None):
        pool = [h for h in iter_hosts(args.sni_lista)]
        if not pool:
            sys.exit(f"{args.sni_lista} está vazio.")
        args._sni_pool = pool


def escolher_host_sni(args, target):
    """Devolve (host, sni) pra uma requisição: sorteia do pool, se houver;
    senão usa o valor fixo de sempre (args.host/args.sni), com o mesmo
    fallback de antes (host -> sni -> target)."""
    pool_h = getattr(args, "_hosts_pool", None)
    pool_s = getattr(args, "_sni_pool", None)
    host = random.choice(pool_h) if pool_h else (
        getattr(args, "host", None) or getattr(args, "sni", None) or target)
    sni = random.choice(pool_s) if pool_s else (getattr(args, "sni", None) or host)
    return host, sni


def pedir_host_sni(args, rotulo, campo):
    """Como pedir_texto, mas deixa adicionar mais de um valor: pergunta
    'adicionar outro?' depois de cada um. Com só 1 valor, funciona igual
    a antes (fixo). Com 2+, um diferente é sorteado a cada requisição."""
    pool_attr = "_hosts_pool" if campo == "host" else "_sni_pool"
    itens = [pedir_texto(rotulo)]
    while True:
        try:
            r = input(c("1;36", " ❯ ") + f"Adicionar outro {rotulo}? (s/n) [n]: ").strip().lower()
        except EOFError:
            break
        if not r.startswith("s"):
            break
        itens.append(pedir_texto(rotulo))
    if len(itens) > 1:
        setattr(args, pool_attr, itens)
        print(c("32", f" {len(itens)} valores de {rotulo} em rodízio — um diferente é sorteado a cada requisição."))
    else:
        setattr(args, pool_attr, None)
    return itens[0]


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


async def open_conn(target, args, ssl_ctx, port=None, use_tls=None, host_sni=None):
    port = port or args.port
    use_tls = args.tls if use_tls is None else use_tls
    sni = None
    if use_tls:
        # Usa exatamente o SNI da combinação atual; mantém o comportamento
        # antigo para chamadas que não informam uma combinação explícita.
        _, sni = host_sni if host_sni is not None else escolher_host_sni(args, target)
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
            await fechar(w)

    res = await asyncio.gather(*(uma(p) for p in ports))
    abertas = [p for p in res if p]
    if not abertas:
        return None
    return target, abertas, "", int((time.monotonic() - t0) * 1000)


async def probe_http(target, args, ssl_ctx, ranges, port=None, use_tls=None, tries=1):
    port = port or args.port
    use_tls = args.tls if use_tls is None else use_tls
    payload = build_payload(args, target)
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
            await fechar(w)
    return None


# ============================ scan ============================
def resolve_ports(args):
    if args.tcp:
        if args.ports:
            return [int(x) for x in str(args.ports).split(",") if x.strip()]
        return [args.port]
    return [args.port]


def coletar_cidrs(args):
    cidrs = list(args.cidr or [])
    if args.cidr_file:
        cidrs += list(iter_hosts(args.cidr_file))
    if args.provider:
        cidrs += provider_cidrs(args.providers, args.provider)
    if not cidrs:
        sys.exit("Informe --cidr, --cidr-file, --provider ou --hosts.")
    return cidrs


def build_targets(args, rng=None):
    if args.hosts:
        return iter_hosts(args.hosts), None
    cidrs = coletar_cidrs(args)
    tot = total_ips(cidrs)
    if args.max_ips and args.max_ips < tot:
        tot = args.max_ips
    return iter_targets(cidrs, args.max_ips, args.shuffle, rng), tot


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
    PARCIAL.clear()
    RAPIDO.clear()

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
        ssl_ctx = make_ssl_ctx(args)

    aviso_rapido(args)
    cp = Checkpoint(args, "run")
    PARCIAL_MANTER[0] = cp.retomou
    skip = cp.idx
    results = [(h[0], list(h[1]), h[2], h[3]) for h in cp.hits]   # (ip, ports, info, ms)
    vistos = {r[0] for r in results}
    done = skip
    n_abertos = 0
    interrupted = False
    last_draw = 0.0
    start = time.monotonic()

    def pular(n):
        nonlocal done
        done += n

    portas_amostra = ports if args.tcp else [args.port]
    targets, total = build_alvos(args, portas_amostra, pular, skip, random.Random(cp.seed))
    sem = asyncio.Semaphore(threads)
    rastrear_tudo = args.tcp and total and total <= RETRY_TOTAL_LIMIT
    nunca_respondeu = set() if rastrear_tudo else None

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
        salvar_parcial(args, f"{ip};{','.join(map(str, pts))};{info};{ms}ms")
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
        res = None
        if args.tcp and not args.confirmar:
            res = await probe_tcp(t, args, ports)
            if res and rastrear_tudo:
                nunca_respondeu.discard(t)
        elif args.tcp and args.confirmar:
            abertas = await probe_tcp(t, args, ports)
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
        done += 1
        if res:
            if res[0] not in vistos:
                vistos.add(res[0])
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
    pend = set()          # posições (na ordem do scan) ainda em andamento
    enviados = skip       # quantos alvos já foram despachados (contando os pulados na retomada)
    try:
        async for t in targets:
            await sem.acquire()
            pos = enviados
            enviados += 1
            pend.add(pos)
            tk = asyncio.create_task(worker(t))
            tasks.add(tk)
            tk.add_done_callback(tasks.discard)
            tk.add_done_callback(lambda _f, p=pos: pend.discard(p))
            # libera a vaga SEMPRE que a task termina (mesmo se for cancelada)
            tk.add_done_callback(lambda _f: sem.release())
            if cp.devido():
                cp.salvar(min(pend) if pend else enviados, results)
        while tasks:
            await asyncio.wait(set(tasks))
    except (KeyboardInterrupt, asyncio.CancelledError):
        interrupted = True
        cp.salvar(min(pend) if pend else enviados, results, force=True)
        for tk in list(tasks):
            tk.cancel()
        await asyncio.gather(*list(tasks), return_exceptions=True)

    if UI.color:
        sys.stdout.write("\r\033[K")
    if not interrupted:
        cp.concluir()

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
                    res2 = None
                    for p in abertas[1]:
                        # 443 com TLS (corrigido na v2.2); 80 em HTTP puro.
                        tls_port = (p == 443)
                        ok = await probe_http(ip, args, ssl_ctx if tls_port else None,
                                              ranges, port=p, use_tls=tls_port,
                                              tries=max(args.tentativas, 2))
                        if ok:
                            res2 = (ip, [p], ok[2], ok[3]) if res2 is None else (
                                ip, res2[1] + [p], res2[2] + " | " + ok[2], max(res2[3], ok[3]))
                elif args.tcp:
                    res2 = await probe_tcp(ip, args, ports)
                else:
                    res2 = await probe_http(ip, args, ssl_ctx, ranges, tries=2)
                if res2 and res2[0] not in vistos:
                    vistos.add(res2[0])
                    results.append(res2)
                    show_hit(res2)

        try:
            await asyncio.gather(*(segunda_chance(ip) for ip in alvo))
        except (KeyboardInterrupt, asyncio.CancelledError):
            interrupted = True

    # 2ª checagem: nos IPs achados, tenta de novo a porta que não abriu
    # (em rede móvel alguns pacotes se perdem e dão falso "fechado").
    # Só roda no modo TCP simples; com --confirmar seria reconfirmar milhares
    # de IPs com uma requisição completa só pra preencher a outra porta.
    if args.tcp and not args.confirmar and len(ports) > 1 and not interrupted:
        faltam = [(r, [p for p in ports if p not in r[1]]) for r in results if len(r[1]) < len(ports)]
        if faltam and len(faltam) <= 3000:
            print(c("2", f" Confirmando portas de {len(faltam)} IPs encontrados..."), flush=True)
            sem2 = asyncio.Semaphore(20)

            async def recheck(r, miss):
                async with sem2:
                    for p in miss:
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
                                await fechar(w)

            try:
                await asyncio.gather(*(recheck(r, m) for r, m in faltam))
            except (KeyboardInterrupt, asyncio.CancelledError):
                interrupted = True
            for r in results:
                r[1].sort()

    summary(args, ports, results, done, time.monotonic() - start, interrupted, n_abertos,
            base_done=skip)
    mostrar_rapido()
    if interrupted and cp.ativo:
        print(c("33", " Progresso salvo. Rode de novo com as mesmas opções para retomar."))
        print()

    if getattr(args, "ranking", False) and results and not interrupted:
        itens = []
        for r in results:
            if args.tcp:
                for p in r[1]:
                    itens.append((r[0], str(p), lambda ip=r[0], p=p: tcp_ms(ip, args, p)))
            else:
                p0 = r[1][0]
                itens.append((r[0], str(p0), lambda ip=r[0], p=p0: http_ms(ip, args, ssl_ctx, ranges, p)))
        try:
            mostrar_ranking(args, await ranquear(itens))
        except (KeyboardInterrupt, asyncio.CancelledError):
            pass


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
            caminho = output_path(nome)
            with open(caminho, "w", encoding="utf-8") as f:
                f.write("\n".join(ips) + "\n")
            saved.append((caminho, len(ips)))
    return saved


def summary(args, ports, results, done, dur, interrupted, n_abertos=0, base_done=0):
    print()
    line("═", "1;36")
    titulo = "RESULTADO (interrompido)" if interrupted else "RESULTADO"
    print(c("1;97", f" {titulo}"))
    line("═", "1;36")
    rate = (done - base_done) / dur if dur > 0 else 0
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


def build_payload(args, target, texto=None, host_sni=None):
    """Monta o payload final (única implementação, usada por todos os modos).
    Tokens: [crlf] [lf] [host] [sni] [ip] [ua] [method] [split] [rotate=a;b]"""
    host_header, sni_val = host_sni if host_sni is not None else escolher_host_sni(args, target)
    template = (texto or args.payload).replace("[crlf]", "\r\n").replace("[lf]", "\n")
    template = template.replace("[host]", host_header).replace("[sni]", sni_val).replace("[ip]", target)
    template = template.replace("[ua]", APP_UA).replace("[method]", "GET")

    def rotate_token(match):
        choices = [x for x in match.group(1).split(";") if x]
        return random.choice(choices) if choices else ""
    template = re.sub(r"\[rotate=([^\]]*)\]", rotate_token, template)
    return template.encode()


_MARCADOR_SPLIT = re.compile(rb"\[instant_split\]|\[delay_split\]|\[split\]")


def dividir_payload(payload):
    """Quebra o payload nos marcadores de split, guardando o tipo de cada um:
    [split] (padrão, espera um pouco a resposta), [instant_split] (manda a
    2ª parte sem esperar nada) e [delay_split] (espera alguns segundos antes
    da 2ª parte). Retorna [(parte, modo_antes_dela)], modo=None na 1ª parte."""
    partes, pos, modo = [], 0, None
    for m in _MARCADOR_SPLIT.finditer(payload):
        partes.append((payload[pos:m.start()], modo))
        modo = {b"[split]": "normal", b"[instant_split]": "instant",
                b"[delay_split]": "delay"}[m.group()]
        pos = m.end()
    partes.append((payload[pos:], modo))
    return [p for p in partes if p[0]]


async def enviar_payload_partes(r, w, payload, args):
    """Envia o payload parte a parte, respeitando o tipo de split de cada uma."""
    for i, (parte, modo) in enumerate(dividir_payload(payload)):
        if i > 0:
            if modo == "delay":
                await asyncio.sleep(getattr(args, "split_delay", 2.0))
            elif modo == "normal":
                try:
                    await asyncio.wait_for(r.read(65536), min(args.timeout, 1.0))
                except asyncio.TimeoutError:
                    pass
            # modo == "instant": manda na hora, sem esperar nada
        w.write(parte)
        await w.drain()


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


def pedir_payload(rotulo, args=None):
    """1 e 2 = payloads padrão (só pede o host). 3 = manual (colar). 4 = gerar testando num IP."""
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
    print(f" {c('1;36', '4)')} {c('1', 'Gerar'.ljust(11))} {c('2', '· testa variações num IP e escolhe a melhor')}")
    line()
    while True:
        try:
            esc = input(c("1;36", " ❯ ") + f"{rotulo} [1/2/3/4]: ").strip()
        except EOFError:
            sys.exit("Payload nao informado.")
        if esc in PAYLOADS_PADRAO:
            USOU_PRESET[0] = True
            return PAYLOADS_PADRAO[esc]
        if esc == "4":
            ip = pedir_texto("IP já conhecido para testar")
            porta_txt = porta if porta.isdigit() else ("443" if "443" in rotulo else "80")
            a2 = copy.copy(args) if args else argparse.Namespace()
            a2.ip, a2.porta_gerar = ip, int(porta_txt)
            # Host (vai no cabeçalho) e SNI (vai no handshake TLS) costumam
            # ser diferentes num bypass de CDN: pergunta os dois separados.
            a2.host = getattr(a2, "host", None) or pedir_texto("Host (cabeçalho do payload)")
            sni_atual = getattr(a2, "sni", None)
            if int(porta_txt) == 443:
                sni_txt = input(c("1;36", " ❯ ") + f"SNI (TLS) [Enter = {a2.host}]: ").strip()
                a2.sni = sni_txt or sni_atual or a2.host
            else:
                a2.sni = sni_atual or a2.host
            # Pergunta sempre: não reaproveita o status herdado do menu (no
            # menu da CDN ele costuma vir largo demais, aceitando 404/403
            # como "deu certo", o que não garante o túnel real abrir).
            status_txt = input(c("1;36", " ❯ ") + "Status que conta como sucesso [101;200]: ").strip()
            a2.status = status_txt or "101;200"
            a2.proxy = getattr(a2, "proxy", None)
            a2.timeout = getattr(a2, "timeout", 2.0) or 2.0
            a2.tls_version = getattr(a2, "tls_version", None)
            a2.split_delay = getattr(a2, "split_delay", 2.0) or 2.0
            melhor = asyncio.run(gerar_payload(a2))
            if melhor:
                esc2 = input(c("1;36", " ❯ ") + "Usar esse payload? (s/n) [s]: ").strip().lower()
                if esc2 != "n":
                    return melhor
            continue
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
        args.payload = pedir_payload("Payload 443", args)
    if args.modo in ("ssh", "ambos") and not getattr(args, "payload_ssh", None):
        args.payload_ssh = pedir_payload("Payload 80", args)
    if USOU_PRESET[0] and not getattr(args, "host", None):
        args.host = pedir_host_sni(args, "Host (vai no payload)", "host")
    if args.modo in ("ssl", "ambos") and not args.sni:
        args.sni = pedir_host_sni(args, "SNI (handshake TLS)", "sni")


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


# ============== gerador de payload / testador de host-sni / perfis ==============
# Em vez de montar o payload na mão, o script testa várias variações numa
# rede/IP de verdade e mostra quais funcionaram (status esperado + latência).
PAYLOAD_METODOS = ["GET", "HEAD", "ACL"]
PAYLOAD_CAMINHOS = ["/", "/ws", "/chat"]
PAYLOAD_QUEBRAS = ["[crlf]", "[lf]"]
PAYLOAD_CABECALHOS = [
    ("sem upgrade", ""),
    ("upgrade+keep-alive", "Upgrade: websocket[Q]Connection: Keep-Alive[Q]"),
    ("connection+upgrade", "Connection: Upgrade[Q]Upgrade: Websocket[Q]"),
    ("só keep-alive", "Connection: Keep-Alive[Q]"),
    ("handshake completo", "Upgrade: websocket[Q]Connection: Upgrade[Q]"
                            "Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==[Q]Sec-WebSocket-Version: 13[Q]"),
    ("content-length falso", "Content-Length: 9999999999999[Q]"),
    # "Upgrade" sozinho, sem ": valor" — tecnicamente não é um cabeçalho
    # HTTP válido, mas algumas CDNs só checam se a palavra aparece em
    # algum lugar do pedido e já trocam para 101 sem validar o resto.
    ("upgrade sozinho (sem valor)", "Upgrade[Q]"),
]
# Tipos de split testados além do payload sem split: padrão (espera um
# pouco a resposta antes da 2ª parte), instantâneo (sem espera nenhuma) e
# com atraso (espera alguns segundos — útil contra DPI que olha só o 1º pacote).
PAYLOAD_SPLITS = [(" +split", "[split]"), (" +instant", "[instant_split]"),
                  (" +delay", "[delay_split]")]


def gerar_variantes_payload(ua=True, incluir_split=True):
    """Monta todos os modelos de payload a testar (combina método, caminho,
    quebra de linha, cabeçalho e, opcionalmente, as 3 formas de split:
    1ª requisição no Host do SNI, 2ª no Host real — como no modo SSH/porta 80)."""
    variantes = []
    for metodo in PAYLOAD_METODOS:
        for caminho in PAYLOAD_CAMINHOS:
            for quebra in PAYLOAD_QUEBRAS:
                for nome_cab, cab in PAYLOAD_CABECALHOS:
                    def montar(host_token):
                        corpo = f"{metodo} {caminho} HTTP/1.1[Q]Host: {host_token}[Q]" + cab
                        if ua:
                            corpo += "User-Agent: [ua][Q]"
                        corpo += "[Q]"
                        return corpo.replace("[Q]", quebra)

                    rotulo_base = f"{metodo} {caminho} {quebra.strip('[]')} · {nome_cab}"
                    variantes.append((rotulo_base, montar("[host]")))
                    if incluir_split:
                        for sufixo, marcador in PAYLOAD_SPLITS:
                            corpo_split = montar("[sni]") + marcador + montar("[host]")
                            variantes.append((rotulo_base + sufixo, corpo_split))

    # Variante enxuta confirmada em uso real: sem User-Agent, "Upgrade"
    # sozinho — algumas CDNs já trocam pra 101 só de ver essa palavra.
    for metodo in PAYLOAD_METODOS:
        for caminho in PAYLOAD_CAMINHOS:
            for quebra in PAYLOAD_QUEBRAS:
                corpo = (f"{metodo} {caminho} HTTP/1.1[Q]Host: [host][Q]Upgrade[Q][Q]"
                         .replace("[Q]", quebra))
                variantes.append((f"{metodo} {caminho} {quebra.strip('[]')} · "
                                   "upgrade sozinho, sem UA", corpo))
    return variantes


async def testar_um_payload(ip, porta, template, args, ssl_ctx, ranges, use_tls, tries=2):
    """Testa UM template de payload no IP. Retorna (info, ms) do melhor try, ou None."""
    for _ in range(max(1, tries)):
        w = None
        t0 = time.monotonic()
        try:
            r, w = await asyncio.wait_for(
                open_conn(ip, args, ssl_ctx if use_tls else None, porta, use_tls),
                args.timeout * 2 if use_tls else args.timeout)
            payload = build_payload(args, ip, template)
            await enviar_payload_partes(r, w, payload, args)
            raw = await asyncio.wait_for(r.readline(), args.timeout)
            linha = raw.decode("latin-1", "replace").strip()
            ms = int((time.monotonic() - t0) * 1000)
            m = re.match(r"HTTP/\d(?:\.\d)?\s+(\d{3})", linha)
            if linha.startswith("SSH-"):
                return linha[:40], ms
            if m and status_ok(int(m.group(1)), ranges):
                return linha, ms
        except Exception:
            pass
        finally:
            await fechar(w)
    return None


async def gerar_payload(args):
    """Testa várias variações de payload num IP e mostra as que funcionaram."""
    ip = args.ip
    porta = args.porta_gerar
    use_tls = porta == 443
    ssl_ctx = make_ssl_ctx(args) if use_tls else None
    ranges = parse_status_spec(args.status)
    variantes = gerar_variantes_payload()
    host_mostrar = args.host or args.sni or ip
    sni_mostrar = args.sni or args.host or ip
    print()
    print(c("1", f" Gerando payload para {ip}:{porta}"))
    if use_tls and host_mostrar != sni_mostrar:
        print(c("2", f" Host: {host_mostrar}   SNI: {sni_mostrar}"))
    else:
        print(c("2", f" Host/SNI: {host_mostrar}"))
    print(c("2", f" Status aceito como sucesso: {args.status}"))
    print(c("2", f" Testando {len(variantes)} variações (as '+delay' esperam "
                 f"{getattr(args, 'split_delay', 2.0):g}s a mais cada uma)..."))
    print()
    sem = asyncio.Semaphore(16)

    async def um(rotulo, template):
        async with sem:
            # tries=1 aqui: com centenas de variações, 2 tentativas por uma
            # dobraria o tempo total. O "+delay" já espera sozinho, então
            # não precisa de retry para mostrar o efeito.
            res = await testar_um_payload(ip, porta, template, args, ssl_ctx, ranges, use_tls, tries=1)
        if res:
            print(f" {c('1;32', '✔')} {c('1', rotulo.ljust(32))} {c('32', res[0][:30])}  {c('2', f'{res[1]}ms')}")
        return (rotulo, template, res)

    resultados = await asyncio.gather(*(um(r, t) for r, t in variantes))
    ok = [(r, t, res) for r, t, res in resultados if res]
    ok.sort(key=lambda x: x[2][1])

    print()
    line("═", "1;36")
    print(c("1;97", " RESULTADO"))
    line("═", "1;36")
    if not ok:
        print(c("33", " Nenhuma variação funcionou. Confira Host/SNI e a porta."))
        print()
        return None
    print(f" {c('1;32', str(len(ok)))} de {len(variantes)} variações funcionaram")
    print()
    for rotulo, _, res in ok[:8]:
        print(f" {c('1', rotulo.ljust(32))} {c('2', f'{res[1]}ms')}  {res[0][:40]}")
    melhor_rotulo, melhor_template, melhor_res = ok[0]
    print()
    print(c("1", " Melhor payload:") + f"  {c('36', melhor_rotulo)}  ({melhor_res[1]}ms)")
    for ln in textwrap.wrap(melhor_template, max(24, term_width() - 3)):
        print(c("2", "   " + ln))
    print()
    return melhor_template


async def testar_hosts(args):
    """Testa uma lista de Host/SNI (um por linha) com o payload atual num IP:porta."""
    ip, porta = args.ip, args.porta_gerar
    use_tls = porta == 443
    ssl_ctx = make_ssl_ctx(args) if use_tls else None
    ranges = parse_status_spec(args.status)
    hosts = [h for h in iter_hosts(args.testar_hosts)]
    print()
    print(c("1", f" Testando {len(hosts)} hosts em {ip}:{porta}"))
    print()
    sem = asyncio.Semaphore(15)
    ok = []

    async def um(host):
        a2 = copy.copy(args)
        a2.host, a2.sni = host, host
        async with sem:
            res = await testar_um_payload(ip, porta, args.payload, a2, ssl_ctx, ranges, use_tls)
        if res:
            ok.append((host, res))
            print(f" {c('1;32', '✔')} {c('1', host.ljust(28))} {c('32', res[0][:30])}  {c('2', f'{res[1]}ms')}")

    await asyncio.gather(*(um(h) for h in hosts))
    ok.sort(key=lambda x: x[1][1])
    print()
    line("═", "1;36")
    print(c("1;97", " RESULTADO"))
    line("═", "1;36")
    if not ok:
        print(c("33", " Nenhum host funcionou com esse payload nesse IP."))
        print()
        return
    print(f" {c('1;32', str(len(ok)))} de {len(hosts)} hosts funcionaram")
    caminho = output_path((args.output or "dropnet_scan") + "_hosts_ok.txt")
    with open(caminho, "w", encoding="utf-8") as f:
        for host, res in ok:
            f.write(f"{host};{res[1]}ms;{res[0]}\n")
    print()
    print(c("1", " Arquivo salvo:"))
    print(f"   {c('36', caminho)} {c('2', f'({len(ok)})')}")
    print()


# ----------------------------- perfis por rede -----------------------------
def perfis_path():
    return output_path("perfis.json")


def perfis_carregar_todos():
    try:
        with open(perfis_path(), encoding="utf-8") as f:
            return json.load(f)
    except (OSError, ValueError):
        return {}


def perfil_salvar(args, nome):
    perfis = perfis_carregar_todos()
    perfis[nome] = {
        "modo": args.modo, "host": args.host, "sni": args.sni,
        "payload": args.payload, "payload_ssh": getattr(args, "payload_ssh", ""),
        "status": args.status,
    }
    with open(perfis_path(), "w", encoding="utf-8") as f:
        json.dump(perfis, f, ensure_ascii=False, indent=2)
    print(c("1;32", f" Perfil '{nome}' salvo em {perfis_path()}"))


def perfil_carregar(args, nome):
    perfis = perfis_carregar_todos()
    if nome not in perfis:
        sys.exit(f"Perfil '{nome}' não existe. Disponíveis: {', '.join(sorted(perfis)) or '(nenhum)'}")
    p = perfis[nome]
    args.modo = p["modo"]
    args.host, args.sni = p["host"], p["sni"]
    args.payload = p["payload"]
    args.payload_ssh = p.get("payload_ssh", "")
    args.status = p["status"]
    print(c("2", f" Perfil '{nome}' carregado (modo {args.modo})"))


def listar_perfis():
    perfis = perfis_carregar_todos()
    if not perfis:
        print(c("33", " Nenhum perfil salvo ainda."))
        return
    print(c("1", f" Perfis salvos ({len(perfis)}):"))
    for nome, p in perfis.items():
        print(f"   {c('36', nome.ljust(16))} modo {p['modo']}  host/sni: {p.get('host') or p.get('sni') or '-'}")


async def probe_combo(target, args, ssl_ctx, ranges, modo, porta, host_sni=None):
    """Testa uma combinação de modo/porta usando o par HOST/SNI informado."""
    use_tls = modo == "ssl"
    payload = build_payload(args, target, args.payload_ssh if modo == "ssh" else args.payload,
                            host_sni=host_sni)
    chave = f"{modo}:{porta}"
    for _ in range(max(1, args.tentativas)):
        w = None
        t0 = time.monotonic()
        try:
            r, w = await asyncio.wait_for(
                open_conn(target, args, ssl_ctx if use_tls else None, porta, use_tls,
                          host_sni=host_sni),
                args.timeout * 2 if use_tls else args.timeout)
        except Exception:
            COMBO_SEEN[f"{chave} não conectou"] += 1
            continue
        try:
            # [split]/[instant_split]/[delay_split] dividem o payload em
            # requisições enviadas em sequência na mesma conexão (ex.: 1ª com
            # Host do SNI, 2ª com o Host real). A resposta das partes
            # anteriores é descartada; vale a da última.
            await enviar_payload_partes(r, w, payload, args)
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
            await fechar(w)
    return None


async def run_combo(args):
    ranges = parse_status_spec(args.status)
    combos = build_combos(args)
    COMBO_SEEN.clear()
    PARCIAL.clear()
    RAPIDO.clear()
    ssl_ctx = make_ssl_ctx(args) if any(m == "ssl" for m, _ in combos) else None
    nofile = raise_nofile()
    # Matriz completa: cada HOST é combinado com cada SNI.
    hosts_pool = getattr(args, "_hosts_pool", None)
    snis_pool = getattr(args, "_sni_pool", None)
    host_values = hosts_pool or [getattr(args, "host", None) or getattr(args, "sni", None)]
    sni_values = snis_pool or [getattr(args, "sni", None)]
    host_values = [v for v in host_values if v] or [None]
    sni_values = [v for v in sni_values if v] or [None]
    host_sni_pairs = [(h or s or None, s or h or None)
                      for h in host_values for s in sni_values]
    # Evita pares repetidos sem alterar a ordem informada pelo usuário.
    host_sni_pairs = list(dict.fromkeys(host_sni_pairs))
    # Cada IP dispara len(combos) * len(host_sni_pairs) conexões ao mesmo
    # tempo (ex.: 2 portas x 9 pares Host/SNI = 18 por IP), então o número
    # de IPs simultâneos precisa considerar isso para não estourar o limite
    # de conexões abertas (nofile).
    conexoes_por_ip = max(1, len(combos) * len(host_sni_pairs))
    threads = max(1, min(args.threads, (nofile - 64) // conexoes_por_ip))

    aviso_rapido(args)
    cp = Checkpoint(args, "combo")
    PARCIAL_MANTER[0] = cp.retomou
    skip = cp.idx
    hits = [tuple(h) for h in cp.hits]          # (ip, modo, porta, host, sni, info, ms)
    vistos = {(h[0], h[1], h[2], h[3], h[4]) for h in hits}
    done = skip
    interrupted = False
    last_draw = 0.0
    start = time.monotonic()

    def pular(n):
        nonlocal done
        done += n

    targets, total = build_alvos(args, [p for _, p in combos], pular, skip,
                                 random.Random(cp.seed))
    sem = asyncio.Semaphore(threads)

    def redraw(force=False):
        nonlocal last_draw
        now = time.monotonic()
        if not UI.color:
            return
        if force or now - last_draw > 0.15:
            sys.stdout.write("\r\033[K" + progress_line(done, total, len(hits), start))
            sys.stdout.flush()
            last_draw = now

    def show_hit(ip, modo, porta, host, sni, info, ms):
        salvar_parcial(args, f"{ip}:{porta};{modo};{host};{sni};{info};{ms}ms")
        hs = host if host == sni else f"{host} / SNI {sni}"
        txt = (f" {c('1;32', '✔')} {c('1', ip.ljust(15))} "
               f"{c('1;36', f'{modo}:{porta}'.ljust(9))} {c('35', hs[:28].ljust(28))} "
               f"{c('32', info[:20])}  {c('2', f'{ms}ms')}")
        if UI.color:
            sys.stdout.write("\r\033[K" + txt + "\n")
        else:
            print(txt, flush=True)

    async def worker(ip):
        nonlocal done
        # Executa todos os pares HOST x SNI para cada modo/porta e registra
        # TODOS os pares que funcionaram, separadamente — não só o primeiro.
        # Assim dá pra ver, por exemplo, que na porta 80 funcionou Host A
        # com SNI X e também Host B com SNI Y, cada um como um resultado
        # próprio (porta + host + sni), em vez de agrupado num só "80 ok".
        pares_ip = [(h or s or ip, s or h or ip) for h, s in host_sni_pairs]
        res = await asyncio.gather(*(
            probe_combo(ip, args, ssl_ctx, ranges, m, p, pair)
            for m, p in combos for pair in pares_ip
        ))
        done += 1
        achou = False
        idx = 0
        for m, p in combos:
            oks = res[idx:idx + len(pares_ip)]
            idx += len(pares_ip)
            for (host_v, sni_v), ok in zip(pares_ip, oks):
                if not ok:
                    continue
                chave = (ip, m, p, host_v, sni_v)
                if chave in vistos:
                    continue
                vistos.add(chave)
                achou = True
                hits.append((ip, m, p, host_v, sni_v, ok[0], ok[1]))
                show_hit(ip, m, p, host_v, sni_v, ok[0], ok[1])
        redraw(achou)
        if not UI.color and done % 1000 == 0:
            print(f"... {done} testados, {len(hits)} ok", flush=True)

    tasks = set()
    pend = set()
    enviados = skip
    try:
        async for t in targets:
            await sem.acquire()
            pos = enviados
            enviados += 1
            pend.add(pos)
            tk = asyncio.create_task(worker(t))
            tasks.add(tk)
            tk.add_done_callback(tasks.discard)
            tk.add_done_callback(lambda _f, p=pos: pend.discard(p))
            # libera a vaga SEMPRE que a task termina (mesmo se for cancelada)
            tk.add_done_callback(lambda _f: sem.release())
            if cp.devido():
                cp.salvar(min(pend) if pend else enviados, hits)
        while tasks:
            await asyncio.wait(set(tasks))
    except (KeyboardInterrupt, asyncio.CancelledError):
        interrupted = True
        cp.salvar(min(pend) if pend else enviados, hits, force=True)
        for tk in list(tasks):
            tk.cancel()
        await asyncio.gather(*list(tasks), return_exceptions=True)

    if UI.color:
        sys.stdout.write("\r\033[K")
    if not interrupted:
        cp.concluir()
    summary_combo(args, combos, hits, done, time.monotonic() - start, interrupted,
                  base_done=skip, n_pares=len(host_sni_pairs))
    mostrar_rapido()
    if interrupted and cp.ativo:
        print(c("33", " Progresso salvo. Rode de novo com as mesmas opções para retomar."))
        print()

    if getattr(args, "ranking", False) and hits and not interrupted:
        itens = [(h[0], f"{h[1]}:{h[2]}",
                  lambda ip=h[0], m=h[1], p=h[2]: combo_ms(ip, args, ssl_ctx, ranges, m, p))
                 for h in hits]
        try:
            mostrar_ranking(args, await ranquear(itens))
        except (KeyboardInterrupt, asyncio.CancelledError):
            pass


def sanitizar_nome_arquivo(s):
    """Deixa um Host/SNI seguro para usar no nome de um arquivo."""
    return re.sub(r"[^A-Za-z0-9_.-]+", "_", s).strip("_")[:40] or "x"


def agrupar_por_host_sni(hits_subset):
    """Agrupa uma lista de hits (mesma porta/modo) por par (host, sni),
    devolvendo [((host, sni), [ips...]), ...] do maior pro menor."""
    grupos = {}
    for h in hits_subset:
        grupos.setdefault((h[3], h[4]), []).append(h[0])
    return sorted(grupos.items(), key=lambda kv: -len(kv[1]))


def summary_combo(args, combos, hits, done, dur, interrupted, base_done=0, n_pares=1):
    print()
    line("═", "1;36")
    print(c("1;97", " RESULTADO (interrompido)" if interrupted else " RESULTADO"))
    line("═", "1;36")
    rate = (done - base_done) / dur if dur > 0 else 0
    print(f" {c('2', 'Testados')}  {fmt(done)}    {c('2', 'Tempo')}  {dur:.0f}s    {c('2', 'Vel.')}  {rate:.0f} ip/s")
    for m, p in combos:
        pl = args.payload_ssh if m == "ssh" else args.payload
        print(f" {c('2', f'Payload {p}')}  {pl.replace(chr(10), ' ')[:60]}")
    print()

    # Cada porta/modo é mostrado separado; dentro dele, cada Host/SNI que
    # funcionou também aparece como uma linha própria (não some num total só).
    mostrar_hs = n_pares > 1
    print(c("1", " Quem funcionou, por configuração:"))
    for m, p in combos:
        subset = [h for h in hits if h[1] == m and h[2] == p]
        n = len(subset)
        cor = "1;32" if n else "2"
        print(f"   {c('1;36', f'{m}:{p}'.ljust(10))} {c(cor, str(n))}")
        if mostrar_hs and subset:
            for (host_v, sni_v), ips in agrupar_por_host_sni(subset):
                rotulo = host_v if host_v == sni_v else f"{host_v}  ·  SNI {sni_v}"
                print(f"      {c('2', '↳')} {c('35', rotulo.ljust(32)[:32])} {c('1;32', str(len(ips)))}")

    ips_ok = sorted({h[0] for h in hits})
    print(f"\n {c('1', 'IPs que funcionaram')}  {c('1;32', str(len(ips_ok)))}")
    for h in hits[:20]:
        hs = h[3] if h[3] == h[4] else f"{h[3]}/{h[4]}"
        print(f"   {h[0].ljust(15)} {f'{h[1]}:{h[2]}'.ljust(9)} {hs[:22].ljust(22)} {h[5][:20]}")
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
        caminho = output_path(nome)
        with open(caminho, "w", encoding="utf-8") as f:
            for ip, m, p, host_v, sni_v, info, ms in hits:
                f.write(f"{ip}:{p};{m};{host_v};{sni_v};{info};{ms}ms\n")
        saved.append((caminho, len(hits)))
        for m, p in combos:
            subset = [h for h in hits if h[1] == m and h[2] == p]
            ips = [h[0] for h in subset]
            if ips and len(combos) > 1:
                caminho = output_path(f"{base}_{m}_{p}.txt")
                with open(caminho, "w", encoding="utf-8") as f:
                    f.write("\n".join(ips) + "\n")
                saved.append((caminho, len(ips)))
            # Um arquivo por combinação Host/SNI dentro dessa porta, só
            # quando há mais de um par configurado (senão seria redundante
            # com o arquivo da porta acima).
            if mostrar_hs:
                for (host_v, sni_v), ips_hs in agrupar_por_host_sni(subset):
                    nome_hs = sanitizar_nome_arquivo(host_v)
                    if sni_v != host_v:
                        nome_hs += "__sni_" + sanitizar_nome_arquivo(sni_v)
                    caminho = output_path(f"{base}_{m}_{p}_{nome_hs}.txt")
                    with open(caminho, "w", encoding="utf-8") as f:
                        f.write("\n".join(ips_hs) + "\n")
                    saved.append((caminho, len(ips_hs)))
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
    args.payload = pedir_payload("Payload 443", args) if tem_tls else DEFAULT_PAYLOAD
    args.payload_ssh = pedir_payload("Payload 80", args) if tem_80 else ""

    etapa("ETAPA 4 · Host, SNI e status")
    usados = ([args.payload] if tem_tls else []) + ([args.payload_ssh] if tem_80 else [])
    precisa_host = any("[host]" in p for p in usados)
    if precisa_host:
        print(c("2", " Host = valor do [host] no payload"))
    if tem_tls:
        print(c("2", " SNI  = nome do handshake TLS (só na 443)"))
    if precisa_host or tem_tls:
        print()
    args.host = pedir_host_sni(args, "Host", "host") if precisa_host else None
    if tem_tls:
        args.sni = pedir_host_sni(args, "SNI", "sni")
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


def ask_num(texto, padrao, tipo=int):
    """Como ask(), mas só aceita número válido (não derruba o script)."""
    while True:
        try:
            return tipo(ask(texto, padrao))
        except ValueError:
            print(c("31", " Digite um número válido."))


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
    args.ranking = True
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
    args.max_ips = 0   # 0 = testa TODOS os IPs (sem amostra)

    args.modo = None
    ask_busca(args)

    if args.avancado:
        if not args.modo:   # Só Proxy: opção de confirmar com status real
            args.confirmar = ask("Confirmar com status real (101/200)? (s/n)", "n").lower().startswith("s")
            if args.confirmar:
                print(c("33", " A confirmação só bate se o Host/SNI forem os certos"))
                print(c("33", " dessa CDN/operadora (o mesmo valor que funciona na sua VPN)."))
                args.payload = pedir_payload(f"Payload {args.port}", args)
                args.host = pedir_host_sni(args, "Host (vai no payload)", "host")
                args.status = ask("Status de sucesso", args.status)
                args.tentativas = ask_num("Tentativas por IP", args.tentativas)
        args.max_ips = ask_num("Quantos IPs testar (0 = todos)", args.max_ips)
        args.threads = ask_num("Threads", args.threads)
        args.timeout = ask_num("Timeout (s)", args.timeout, float)
        args.ranking = ask("Ranking de latência dos IPs achados? (s/n)", "s").lower().startswith("s")
        if not args.max_ips:
            print(c("33", " Modo rápido testa amostras de cada /24 e pode perder IPs isolados."))
            args.rapido = ask("Ativar modo rápido? (s/n)", "n").lower().startswith("s")

    amostra = bool(args.max_ips) and args.max_ips < total
    sel = args.max_ips if amostra else total
    print()
    line("═", "1;36")
    info_row("CDN", c("1", ", ".join(nomes)))
    info_row("Faixas", f"{len(cidrs)}  ·  {fmt(sel)} IPs" + (c("2", "  (amostra)") if amostra else ""))
    if args.modo:
        info_row("Busca", c("1", "Proxy + Payload"))
        info_row("Portas", " + ".join(f"{p} ({m})" for m, p in build_combos(args)))
        if getattr(args, "_hosts_pool", None):
            info_row("Host", c("1", f"{len(args._hosts_pool)} em rodízio") + c("2", f"  ({args._hosts_pool[0]}, ...)"))
        elif args.host:
            info_row("Host", args.host)
        if args.modo in ("ssl", "ambos") and getattr(args, "_sni_pool", None):
            info_row("SNI", c("1", f"{len(args._sni_pool)} em rodízio") + c("2", f"  ({args._sni_pool[0]}, ...)"))
        elif args.modo in ("ssl", "ambos") and args.sni:
            info_row("SNI", args.sni)
        info_row("Status", args.status)
    else:
        info_row("Busca", c("1", "Só Proxy") + c("2", "  (sem payload)"))
        info_row("Portas", " + ".join(map(str, resolve_ports(args))))
        if args.confirmar:
            info_row("Status", args.status)
    info_row("Threads", f"{args.threads}  ·  timeout {args.timeout:g}s")
    if rapido_ativo(args):
        info_row("Modo", c("33", "rápido (2 fases)"))
    line("═", "1;36")
    print(c("2", " Ctrl+C para parar"))
    print()
    return args


# ============================ diagnóstico ============================
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
        await fechar(w)


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
    p.add_argument("--version", action="version", version=f"DROPNET SCANNER v{VERSION}")
    g = p.add_argument_group("alvos")
    g.add_argument("--cidr", action="append", help="faixa CIDR (pode repetir)")
    g.add_argument("--cidr-file", help="arquivo com um CIDR por linha")
    g.add_argument("--providers", default="providers.json", help="arquivo providers.json")
    g.add_argument("--provider", action="append", help="nome do provedor (azion, cloudflare...)")
    g.add_argument("--hosts", help="arquivo com hosts/IPs (um por linha)")
    g.add_argument("--max-ips", type=int, default=0, help="limite de IPs (0 = todos)")
    g.add_argument("--shuffle", action="store_true", help="embaralha as faixas (por blocos /24)")

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
    c_.add_argument("--hosts-lista", help="arquivo com vários Hosts (um por linha); sorteia um diferente a cada requisição em vez de usar sempre o mesmo")
    c_.add_argument("--sni-lista", help="arquivo com várias SNIs (um por linha); sorteia uma diferente a cada requisição em vez de usar sempre a mesma")
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
    r.add_argument("--ranking", action="store_true", help="depois do scan, mede a latência dos IPs achados e ordena")
    r.add_argument("--rapido", action="store_true", help="modo rápido: testa amostras de cada /24 e só varre blocos que responderam (pode perder IPs isolados)")
    r.add_argument("--rapido-amostras", type=int, default=3, help="amostras por bloco /24 no modo rápido")
    r.add_argument("--retomar", action="store_true", help="retoma automaticamente o último scan interrompido")
    r.add_argument("--novo", action="store_true", help="ignora o progresso salvo e começa do zero")
    r.add_argument("--no-color", action="store_true", help="sem cores")

    g2 = p.add_argument_group("gerar payload / testar hosts / perfis")
    g2.add_argument("--gerar-payload", metavar="IP", help="testa várias variações de payload nesse IP e mostra as que funcionaram")
    g2.add_argument("--testar-hosts", metavar="ARQUIVO", help="testa uma lista de hosts/SNI (um por linha) com o --payload atual; use com --ip")
    g2.add_argument("--ip", help="IP alvo para --testar-hosts")
    g2.add_argument("--porta-gerar", type=int, default=443, help="porta usada por --gerar-payload / --testar-hosts")
    g2.add_argument("--split-delay", type=float, default=2.0, help="segundos de espera no [delay_split] (padrão 2.0)")
    g2.add_argument("--salvar-perfil", metavar="NOME", help="salva modo/host/sni/payload atuais como um perfil de rede")
    g2.add_argument("--usar-perfil", metavar="NOME", help="carrega um perfil salvo (modo/host/sni/payload) antes de rodar")
    g2.add_argument("--listar-perfis", action="store_true", help="lista os perfis salvos e sai")
    return p


def main():
    args = build_parser().parse_args()
    if args.no_color:
        UI.color = False
    carregar_pools(args)

    if args.diag:
        try:
            asyncio.run(diag(args))
        except KeyboardInterrupt:
            pass
        return

    if args.listar_perfis:
        listar_perfis()
        return

    if args.salvar_perfil:
        if not args.modo:
            sys.exit("--salvar-perfil precisa de --modo (ssl/ssh/ambos) com payload/host/sni definidos.")
        perfil_salvar(args, args.salvar_perfil)
        return

    if args.gerar_payload:
        args.ip = args.gerar_payload
        try:
            asyncio.run(gerar_payload(args))
        except KeyboardInterrupt:
            pass
        return

    if args.testar_hosts:
        if not args.ip:
            sys.exit("--testar-hosts precisa de --ip IP.")
        try:
            asyncio.run(testar_hosts(args))
        except KeyboardInterrupt:
            pass
        return

    if args.usar_perfil:
        perfil_carregar(args, args.usar_perfil)

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
