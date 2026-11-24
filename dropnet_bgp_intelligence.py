#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
DROPNET BGP INTELLIGENCE
Consulta pública de ASN, IP, CIDR e domínio.
Requer Python 3.8+; usa apenas a biblioteca padrão.
"""
import ipaddress
import json
import os
import re
import shutil
import socket
import subprocess
import sys
import urllib.parse
import urllib.request
import urllib.error
from datetime import datetime

VERSION = "2.0"
TIMEOUT = 18
UA = "Dropnet-BGP-Intelligence/2.0 (public-network-research)"
RIPE = "https://stat.ripe.net/data/"
DOH = "https://dns.google/resolve"

def request_json(url, headers=None):
    req_headers = {
        "User-Agent": UA,
        "Accept": "application/rdap+json, application/json;q=0.9, */*;q=0.8",
    }
    if headers:
        req_headers.update(headers)
    req = urllib.request.Request(url, headers=req_headers)
    try:
        with urllib.request.urlopen(req, timeout=TIMEOUT) as response:
            raw = response.read().decode("utf-8", "replace")
            return json.loads(raw)
    except urllib.error.HTTPError as exc:
        raise RuntimeError(f"HTTP {exc.code} em {urllib.parse.urlparse(url).netloc}") from exc
    except urllib.error.URLError as exc:
        raise RuntimeError(f"Falha de conexão: {exc.reason}") from exc
    except json.JSONDecodeError as exc:
        raise RuntimeError("A fonte retornou uma resposta que não é JSON.") from exc

def get_ripe(dataset, resource, extra=""):
    q = urllib.parse.urlencode({"resource": resource})
    if extra:
        q += "&" + extra
    return request_json(RIPE + dataset + "/data.json?" + q)

def print_json(title, obj, limit=9000):
    print("\n" + "=" * 72)
    print(title)
    print("=" * 72)
    text = json.dumps(obj, ensure_ascii=False, indent=2)
    print(text[:limit])
    if len(text) > limit:
        print("\n[Resultado abreviado; consulte a fonte original.]")

def safe_data(obj):
    return obj.get("data", obj) if isinstance(obj, dict) else obj

def dns_lookup(domain, record):
    url = DOH + "?" + urllib.parse.urlencode({"name": domain, "type": record})
    obj = request_json(url)
    answers = obj.get("Answer", [])
    return [{"name": x.get("name"), "type": x.get("type"), "ttl": x.get("TTL"),
             "data": x.get("data")} for x in answers]

def domain_report(domain):
    print(f"\n[DNS] {domain}")
    for record in ("A", "AAAA", "MX", "NS", "TXT", "SOA", "CAA"):
        try:
            rows = dns_lookup(domain, record)
            if rows:
                print(f"\n{record}:")
                for row in rows:
                    print("  " + str(row["data"]))
            else:
                print(f"\n{record}: nenhum registro retornado")
        except Exception as exc:
            print(f"\n{record}: consulta indisponível ({exc})")
    try:
        print("\n[RDAP / REGISTRO DO DOMÍNIO]")
        # RDAP de domínio tem suporte variável; endpoint do rdap.org redireciona
        url = "https://rdap.org/domain/" + urllib.parse.quote(domain, safe=".-")
        print_json("RDAP do domínio", request_json(url), 6500)
    except Exception as exc:
        print(f"RDAP: {exc}")
    try:
        print("\n[SUBDOMÍNIOS EM CERTIFICADOS PÚBLICOS - crt.sh]")
        url = "https://crt.sh/?q=%25." + urllib.parse.quote(domain, safe=".-") + "&output=json"
        certs = request_json(url)
        names = set()
        for cert in certs[:250]:
            for name in str(cert.get("name_value", "")).splitlines():
                name = name.strip().lower().lstrip("*.")
                if name.endswith(domain):
                    names.add(name)
        for name in sorted(names)[:100]:
            print("  " + name)
        if not names:
            print("  Nenhum subdomínio encontrado na resposta.")
    except Exception as exc:
        print(f"Consulta crt.sh indisponível: {exc}")

def ip_report(ip):
    print(f"\n[IP] {ip}")
    try:
        print_json("RIPEstat - rede, prefixo e ASN de origem",
                   safe_data(get_ripe("network-info", ip)), 6000)
    except Exception as exc:
        print(f"RIPEstat network-info: {exc}")
    try:
        print_json("RDAP - registro do endereço IP",
                   request_json("https://rdap.org/ip/" + urllib.parse.quote(ip)), 6500)
    except Exception as exc:
        print(f"RDAP: {exc}")
    try:
        # O endpoint RPKI do RIPEstat exige ASN de origem e prefixo.
        # Reaproveita os dados já obtidos em network-info.
        net_info = safe_data(get_ripe("network-info", ip))
        asns = net_info.get("asns", []) if isinstance(net_info, dict) else []
        prefix = net_info.get("prefix") if isinstance(net_info, dict) else None
        if asns and prefix:
            for origin_asn in asns:
                rpki = get_ripe(
                    "rpki-validation",
                    str(origin_asn),
                    "prefix=" + urllib.parse.quote(str(prefix), safe="")
                )
                print_json(
                    f"RIPEstat - RPKI para {prefix} / AS{origin_asn}",
                    safe_data(rpki), 6000
                )
        else:
            print("RPKI: não foi possível identificar ASN de origem e prefixo.")
    except Exception as exc:
        print(f"RPKI: consulta indisponível ({exc})")
    try:
        ptr = socket.gethostbyaddr(ip)
        print(f"\nDNS reverso: {ptr[0]}")
        if ptr[1]:
            print("Aliases: " + ", ".join(ptr[1]))
    except Exception:
        print("\nDNS reverso: nenhum PTR encontrado ou consulta indisponível")
    try:
        print("\n[BLACKLIST / RBL]")
        reversed_ip = ".".join(reversed(ip.split("."))) if "." in ip else None
        if reversed_ip:
            for zone in ("zen.spamhaus.org", "bl.spamcop.net"):
                try:
                    print(f"  {zone}: {socket.gethostbyname(reversed_ip + '.' + zone)} (listado)")
                except socket.gaierror:
                    print(f"  {zone}: sem resposta de listagem")
        else:
            print("  Verificação automática básica disponível apenas para IPv4.")
    except Exception as exc:
        print(f"  RBL: {exc}")

def prefix_report(prefix):
    net = ipaddress.ip_network(prefix, strict=False)
    print(f"\n[CIDR] {net}")
    print(f"Versão IP: IPv{net.version}")
    print(f"Endereço de rede: {net.network_address}")
    print(f"Prefixo: /{net.prefixlen}")
    print(f"Total de endereços: {net.num_addresses}")
    try:
        print_json("RIPEstat - informações do prefixo",
                   safe_data(get_ripe("network-info", str(net))), 6000)
    except Exception as exc:
        print(f"RIPEstat network-info: {exc}")
    try:
        print_json("RIPEstat - validação RPKI",
                   safe_data(get_ripe("rpki-validation", str(net))), 6000)
    except Exception as exc:
        print(f"RPKI: {exc}")
    print("\nObservação: a visibilidade BGP pode variar entre coletores e pontos de observação.")

def asn_report(asn):
    asn = asn.upper()
    if not asn.startswith("AS"):
        asn = "AS" + asn
    number = asn[2:]
    if not number.isdigit():
        raise ValueError("ASN inválido. Exemplo: AS52580")
    print(f"\n[ASN] {asn}")
    jobs = [
        ("Informações de rede / ASN", "network-info"),
        ("Prefixos anunciados", "announced-prefixes"),
        ("Peers BGP observados", "looking-glass"),
        ("Validação RPKI", "rpki-validation"),
        ("Informações WHOIS", "whois"),
    ]
    for title, dataset in jobs:
        try:
            result = get_ripe(dataset, asn)
            print_json("RIPEstat - " + title, safe_data(result), 7500)
        except Exception as exc:
            print(f"\n{title}: fonte indisponível ({exc})")
    print("\n[CONSULTAS COMPLEMENTARES]")
    print("Perfil HE: https://bgp.he.net/" + asn)
    print("Prefixos HE: https://bgp.he.net/" + asn + "#_prefixes")
    print("Peers HE: https://bgp.he.net/" + asn + "#_peers")
    print("RIPEstat: https://stat.ripe.net/" + asn)

def active_tools(target):
    print("\n[DIAGNÓSTICO LOCAL]")
    for cmd, label in ((["ping", "-c", "4", "-W", "2", target], "PING"),
                       (["traceroute", "-m", "15", "-w", "2", target], "TRACEROUTE")):
        if not shutil.which(cmd[0]):
            print(f"{label}: comando não instalado neste aparelho.")
            continue
        print(f"\n{label}:")
        try:
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=45)
            print((result.stdout or result.stderr or "Sem saída.")[:6500])
        except subprocess.TimeoutExpired:
            print("Tempo limite excedido.")
        except Exception as exc:
            print(f"Não foi possível executar: {exc}")

def cert_search(domain):
    url = "https://crt.sh/?q=%25." + urllib.parse.quote(domain, safe=".-") + "&output=json"
    data = request_json(url)
    print_json("CERTIFICADOS PÚBLICOS (crt.sh)", data[:80], 9000)

def toolkit_menu():
    links = [
        ("BGP Prefix Report", "https://bgp.he.net/report"),
        ("BGP Peer Report", "https://bgp.he.net/report/peers"),
        ("Super Traceroute", "https://bgp.he.net/traceroute"),
        ("Super Looking Glass", "https://bgp.he.net/looking-glass"),
        ("Cert Search", "https://bgp.he.net/cert"),
        ("Exchange Report", "https://bgp.he.net/exchange"),
        ("Bogon Routes", "https://bgp.he.net/bogon"),
        ("World Report", "https://bgp.he.net/report/world"),
        ("Multi Origin Routes", "https://bgp.he.net/report/multi-origin"),
        ("DNS Report", "https://bgp.he.net/dns"),
        ("Top Host Report", "https://bgp.he.net/report/top-host"),
        ("RPKI & ASPA Report", "https://bgp.he.net/report/rpki"),
        ("Internet Statistics", "https://bgp.he.net/report/stats"),
        ("IPv6 Certification", "https://ipv6.he.net/certification/"),
        ("IPv6 Progress", "https://www.worldipv6launch.org/measurements/"),
    ]
    print("\n[CATÁLOGO DE FERRAMENTAS DO BGP TOOLKIT]")
    for name, url in links:
        print(f"- {name}: {url}")
    print("\nNota: links abrem as ferramentas públicas originais; não são executadas localmente pelo Dropnet.")

def detect(value):
    value = value.strip()
    if not value:
        raise ValueError("Digite um ASN, IP, CIDR ou domínio.")
    if re.fullmatch(r"(?i)AS\d+", value):
        return "asn", value
    if re.fullmatch(r"\d+", value):
        return "asn", value
    try:
        ipaddress.ip_address(value)
        return "ip", value
    except ValueError:
        pass
    try:
        ipaddress.ip_network(value, strict=False)
        if "/" in value:
            return "cidr", value
    except ValueError:
        pass
    domain = value.rstrip(".").lower()
    if len(domain) <= 253 and re.fullmatch(r"(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)(?:\.(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?))+", domain):
        return "domain", domain
    raise ValueError("Formato não reconhecido. Exemplos: AS52580, 8.8.8.8, 2804:cf8::/48, google.com")

def main():
    print("=" * 72)
    print(f"             DROPNET BGP INTELLIGENCE v{VERSION}")
    print("       Consultas públicas de roteamento, ASN, IP e DNS")
    print("=" * 72)
    while True:
        print("\nDigite ASN, IP, CIDR ou domínio (ou 'ferramentas' / 'sair')")
        try:
            value = input("Dropnet > ").strip()
        except (EOFError, KeyboardInterrupt):
            print("\nEncerrando.")
            break
        if value.lower() in ("sair", "exit", "quit"):
            break
        if value.lower() in ("ferramentas", "menu", "help"):
            toolkit_menu()
            continue
        try:
            kind, target = detect(value)
            print(f"\nTipo identificado automaticamente: {kind.upper()}")
            if kind == "asn":
                asn_report(target)
            elif kind == "ip":
                ip_report(target)
                active_tools(target)
            elif kind == "cidr":
                prefix_report(target)
            elif kind == "domain":
                domain_report(target)
                try:
                    ip = socket.gethostbyname(target)
                    print(f"\nIPv4 resolvido: {ip}")
                    print("\nDeseja executar ping/traceroute local? (s/N)")
                    if input("> ").strip().lower() == "s":
                        active_tools(target)
                except socket.gaierror:
                    pass
        except Exception as exc:
            print(f"\nERRO: {exc}")
        print("\n" + "=" * 72)
        print("CONSULTA FINALIZADA")
        print("=" * 72)
        try:
            choice = input("\n[0] Fazer outro scan   [ENTER] Voltar ao menu principal\nDropnet > ").strip()
        except (EOFError, KeyboardInterrupt):
            print("\nVoltando ao menu principal...")
            return

        if choice == "0":
            continue
        if choice == "":
            print("Voltando ao menu principal...")
            return

        print("Opção inválida. Digite 0 para fazer outro scan ou pressione ENTER para voltar.")
        while True:
            try:
                choice = input("Dropnet > ").strip()
            except (EOFError, KeyboardInterrupt):
                print("\nVoltando ao menu principal...")
                return
            if choice == "0":
                break
            if choice == "":
                print("Voltando ao menu principal...")
                return
            print("Opção inválida. Digite 0 ou pressione ENTER.")
        continue

if __name__ == "__main__":
    main()
