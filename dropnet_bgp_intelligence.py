#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""DROPNET BGP INTELLIGENCE — consulta passiva de dados públicos do bgp.he.net."""
import ipaddress
import os
import re
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime
from html.parser import HTMLParser
from pathlib import Path

VERSION = "1.0"
BASE_URL = "https://bgp.he.net"
OUT = Path.home() / "storage" / "downloads" / "DROPNET-SCANNER"
C, G, Y, R, W, D, X = ("\033[96m", "\033[92m", "\033[93m", "\033[91m", "\033[97m", "\033[90m", "\033[0m")

class PageParser(HTMLParser):
    def __init__(self):
        super().__init__()
        self.parts, self.links = [], []
        self.skip = 0
    def handle_starttag(self, tag, attrs):
        attrs = dict(attrs)
        if tag in ("script", "style", "noscript"):
            self.skip += 1
        if tag == "a" and attrs.get("href"):
            self.links.append((attrs["href"], ""))
        if tag in ("br", "tr", "p", "h1", "h2", "h3", "li", "td", "th") and not self.skip:
            self.parts.append("\n")
    def handle_endtag(self, tag):
        if tag in ("script", "style", "noscript") and self.skip:
            self.skip -= 1
        if tag in ("tr", "p", "h1", "h2", "h3", "li") and not self.skip:
            self.parts.append("\n")
    def handle_data(self, data):
        if not self.skip:
            text = " ".join(data.split())
            if text:
                self.parts.append(text)
                if self.links and not self.links[-1][1]:
                    href, _ = self.links[-1]
                    self.links[-1] = (href, text)

def clear():
    os.system("cls" if os.name == "nt" else "clear")

def clean_target(raw):
    value = raw.strip()
    if not value:
        raise ValueError("Informe um alvo para consulta.")
    value = re.sub(r"^https?://", "", value, flags=re.I).strip()
    if "/" in value and not re.fullmatch(r"[^/]+/\d{1,3}", value):
        value = value.split("/", 1)[0]
    if re.fullmatch(r"AS\d+", value, re.I):
        return "asn", "AS" + value[2:]
    try:
        return "ip", str(ipaddress.ip_address(value))
    except ValueError:
        pass
    try:
        net = ipaddress.ip_network(value, strict=False)
        return "prefix", str(net)
    except ValueError:
        pass
    if len(value) <= 253 and re.fullmatch(r"(?i)(?=.{1,253}$)[a-z0-9](?:[a-z0-9.-]*[a-z0-9])?", value):
        return "domain", value.lower()
    raise ValueError("Alvo inválido. Use ASN, IP, prefixo CIDR ou domínio.")

def fetch(target_type, target):
    if target_type == "domain":
        path = "/dns/" + urllib.parse.quote(target, safe=".-")
    else:
        path = "/" + urllib.parse.quote(target, safe=".:/")
    url = BASE_URL + path
    request = urllib.request.Request(url, headers={
        "User-Agent": "DROPNET-BGP-Intelligence/1.0 (public network inventory)",
        "Accept": "text/html,application/xhtml+xml"
    })
    with urllib.request.urlopen(request, timeout=18) as response:
        raw = response.read(2_500_000)
        charset = response.headers.get_content_charset() or "utf-8"
        html = raw.decode(charset, errors="replace")
    parser = PageParser()
    parser.feed(html)
    lines = []
    for line in " ".join(parser.parts).replace("\r", " ").split("\n"):
        line = re.sub(r"\s+", " ", line).strip()
        if line and (not lines or lines[-1] != line):
            lines.append(line)
    text = "\n".join(lines)
    # Remove navigation clutter while retaining tables and report content.
    useful = [x for x in lines if x.lower() not in {"home", "quick links", "bgp toolkit home"}]
    return url, "\n".join(useful), parser.links

def show_result(kind, target, url, content, links):
    clear()
    print(C + "╔════════════════════════════════════════════════════╗")
    print("║             DROPNET BGP INTELLIGENCE               ║")
    print("╚════════════════════════════════════════════════════╝" + X)
    print(f"{D}Consulta passiva • Fonte: Hurricane Electric BGP Toolkit{X}")
    print(f"\n{W}TIPO:{X} {kind.upper()}   {W}ALVO:{X} {target}")
    print(f"{W}FONTE:{X} {url}\n")
    print(C + "─" * 56 + X)
    if not content.strip():
        print(Y + "A página abriu, mas não retornou conteúdo legível." + X)
    else:
        for line in content.splitlines()[:180]:
            if any(word in line.lower() for word in ("query limit", "too many", "temporarily unavailable")):
                print(Y + line[:180] + X)
            else:
                print(line[:190])
    print(C + "─" * 56 + X)
    print(f"\n{D}Consulta realizada em {datetime.now().strftime('%d/%m/%Y %H:%M:%S')}{X}")
    choice = input("\n[S] Salvar relatório  [N] Nova consulta  [0] Voltar: ").strip().lower()
    if choice == "s":
        OUT.mkdir(parents=True, exist_ok=True)
        safe = re.sub(r"[^A-Za-z0-9_.-]", "_", target)
        path = OUT / f"dropnet_bgp_{safe}.txt"
        path.write_text(f"DROPNET BGP INTELLIGENCE\nAlvo: {target}\nTipo: {kind}\nFonte: {url}\nData: {datetime.now()}\n\n{content}\n", encoding="utf-8")
        print(G + f"Relatório salvo em: {path}" + X)
        input("Enter para continuar...")
    return choice

def main():
    while True:
        clear()
        print(C + "╔════════════════════════════════════════════════════╗")
        print("║             DROPNET BGP INTELLIGENCE               ║")
        print("║                 CONSULTA DE REDE                  ║")
        print("╚════════════════════════════════════════════════════╝" + X)
        print("\n  Consulte dados públicos de roteamento e DNS")
        print("  1) ASN       2) Endereço IP       3) Prefixo CIDR")
        print("  4) Domínio / DNS")
        raw = input("\n  Digite ASN, IP, CIDR ou domínio: ").strip()
        try:
            kind, target = clean_target(raw)
            print(Y + "\nConsultando a fonte pública..." + X)
            url, content, links = fetch(kind, target)
            choice = show_result(kind, target, url, content, links)
            if choice in ("0", "n"):
                if choice == "0":
                    return
                continue
        except urllib.error.HTTPError as exc:
            print(R + f"Erro HTTP {exc.code}: a fonte recusou ou limitou a consulta." + X)
            input("Enter para voltar...")
        except urllib.error.URLError as exc:
            print(R + f"Falha de conexão: {exc.reason}" + X)
            input("Enter para voltar...")
        except (TimeoutError, OSError) as exc:
            print(R + f"Não foi possível concluir: {exc}" + X)
            input("Enter para voltar...")
        except ValueError as exc:
            print(R + str(exc) + X)
            input("Enter para tentar novamente...")
        except KeyboardInterrupt:
            return

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\nDROPNET BGP INTELLIGENCE encerrado.")
