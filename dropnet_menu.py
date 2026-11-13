#!/usr/bin/env python3
"""Menu principal do DROPNET SCANNER — interface adaptável para Termux."""
import datetime
import json
import os
import re
import shutil
import subprocess
import sys
import time
from pathlib import Path

BASE = Path(__file__).resolve().parent
PYTHON = sys.executable
OUT = Path.home() / "storage" / "downloads" / "DROPNET-SCANNER"
RESET = "\033[0m"
BOLD = "\033[1m"
CYAN = "\033[36m"
GREEN = "\033[32m"
YELLOW = "\033[33m"
DIM = "\033[2m"


def command_json(command, timeout=4):
    """Executa um comando do Termux:API e devolve JSON, se disponível."""
    executable = shutil.which(command)
    if not executable:
        return None
    try:
        result = subprocess.run(
            [executable], capture_output=True, text=True,
            timeout=timeout, check=True
        )
        return json.loads(result.stdout)
    except (OSError, subprocess.SubprocessError, json.JSONDecodeError):
        return None


def command_text(command, timeout=3):
    """Executa comando local simples e retorna texto, se disponível."""
    executable = shutil.which(command[0])
    if not executable:
        return ""
    try:
        result = subprocess.run(
            [executable, *command[1:]], capture_output=True,
            text=True, timeout=timeout, check=True
        )
        return result.stdout.strip()
    except (OSError, subprocess.SubprocessError):
        return ""


def device_status():
    now = datetime.datetime.now().strftime("%d/%m/%Y %H:%M")

    # Primeiro tenta a Termux:API; depois usa informações nativas do Android.
    battery = "indisponível"
    battery_data = command_json("termux-battery-status")
    if isinstance(battery_data, dict) and battery_data.get("percentage") is not None:
        try:
            battery = f"{int(battery_data['percentage'])}%"
        except (TypeError, ValueError):
            pass
    if battery == "indisponível":
        dump = command_text(["dumpsys", "battery"])
        match = re.search(r"(?m)^\\s*level:\\s*(\\d+)", dump)
        if match:
            battery = f"{match.group(1)}%"

    operator = "não identificada"
    phone_data = command_json("termux-telephony-deviceinfo")
    if isinstance(phone_data, dict):
        operator = (
            phone_data.get("network_operator_name")
            or phone_data.get("sim_operator_name")
            or phone_data.get("network_operator")
            or phone_data.get("sim_operator")
            or operator
        )
    if not isinstance(operator, str) or not operator.strip():
        operator = "não identificada"
    if operator == "não identificada":
        # getprop pode funcionar mesmo quando a API não está instalada.
        props = command_text(["getprop", "gsm.operator.alpha"])
        if not props:
            props = command_text(["getprop", "gsm.sim.operator.alpha"])
        if props:
            operator = props.split(",")[0].strip()

    # Evita despejar objetos/listas ou textos enormes no cabeçalho.
    if not isinstance(operator, str):
        operator = "não identificada"
    operator = " ".join(operator.split())[:24] or "não identificada"

    try:
        is_root = os.geteuid() == 0
    except AttributeError:
        is_root = False
    root = "Root" if is_root else "Sem root"
    return now, battery, operator, root


def terminal_width():
    return max(30, min(shutil.get_terminal_size((40, 24)).columns, 72))


def fit(text, width):
    text = str(text)
    if len(text) > width:
        return text[:max(0, width - 1)] + "…"
    return text + " " * (width - len(text))


def panel(title, lines, width):
    inner = width - 2
    print("┌" + "─" * inner + "┐")
    print("│" + fit(title.center(inner), inner) + "│")
    print("├" + "─" * inner + "┤")
    for line in lines:
        print("│" + fit(line, inner) + "│")
    print("└" + "─" * inner + "┘")


def header():
    now, battery, operator, root = device_status()
    width = terminal_width()
    inner = width - 2
    os.system("clear")
    title = "DROPNET SCANNER"
    print(f"{BOLD}{CYAN}┌{'─' * inner}┐{RESET}")
    print(f"{BOLD}{CYAN}│{RESET}{fit(title.center(inner), inner)}{BOLD}{CYAN}│{RESET}")
    print(f"{BOLD}{CYAN}│{RESET}{fit('Versão 4.0'.center(inner), inner)}{BOLD}{CYAN}│{RESET}")
    print(f"{BOLD}{CYAN}├{'─' * inner}┤{RESET}")
    status_lines = [
        f"Data: {now}",
        f"Bateria: {battery}  |  {root}",
        f"Rede móvel: {operator}",
    ]
    for line in status_lines:
        print(f"{CYAN}│{RESET}{fit(line, inner)}{CYAN}│{RESET}")
    print(f"{BOLD}{CYAN}├{'─' * inner}┤{RESET}")
    print(f"{BOLD}{CYAN}│{RESET}{fit('MENU PRINCIPAL'.center(inner), inner)}{BOLD}{CYAN}│{RESET}")
    menu = [
        "1) Iniciar scanner",
        "2) Escolher CDN / provedor",
        "3) Verificar atualização",
        "4) Configurações",
        "5) Histórico de resultados",
        "6) Sobre / ajuda",
        "0) Sair",
    ]
    for line in menu:
        print(f"{CYAN}│{RESET}{fit('  ' + line, inner)}{CYAN}│{RESET}")
    print(f"{BOLD}{CYAN}└{'─' * inner}┘{RESET}")


def pause():
    input("\nPressione Enter para voltar ao menu...")


def start_scanner():
    script = BASE / "ipv4scanner.py"
    if not script.exists():
        print("\n[ERRO] ipv4scanner.py não encontrado.")
        pause()
        return
    print("\nIniciando DROPNET SCANNER...\n")
    try:
        subprocess.run([PYTHON, str(script)], cwd=str(BASE), check=False)
    except KeyboardInterrupt:
        print("\nScanner interrompido pelo usuário.")
    OUT.mkdir(parents=True, exist_ok=True)
    for file in BASE.glob("dropnet_*.txt"):
        try:
            shutil.copy2(file, OUT / file.name)
        except OSError:
            pass
    pause()


def providers():
    path = BASE / "providers.json"
    print("\nCDNs / PROVEDORES DISPONÍVEIS\n")
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
        items = data.get("providers", [])
        if not items:
            print("Nenhum provedor cadastrado.")
        else:
            width = terminal_width()
            page_size = max(5, min(15, shutil.get_terminal_size((40, 24)).lines - 8))
            pages = (len(items) + page_size - 1) // page_size
            page = 0
            while True:
                os.system("clear")
                start = page * page_size
                print(f"CDNs / PROVEDORES — página {page + 1}/{pages}\n")
                for i, item in enumerate(items[start:start + page_size], start + 1):
                    name = str(item.get("name", "Sem nome"))
                    print(f"{i:>4}) {name[:width - 7]}")
                print(f"\nTotal: {len(items)} provedores")
                if pages > 1:
                    print("[N] próxima página  [P] anterior")
                print("[Enter] voltar")
                action = input("> ").strip().lower()
                if action == "n" and page + 1 < pages:
                    page += 1
                elif action == "p" and page > 0:
                    page -= 1
                else:
                    return
        print("\nA seleção de provedor ainda não está conectada ao fluxo do scanner.")
        pause()
    except Exception as exc:
        print(f"Não foi possível ler providers.json: {exc}")
        pause()


def update():
    if not (BASE / ".git").exists():
        print("\nEsta cópia não possui repositório Git. Atualize pelo instalador oficial.")
    elif shutil.which("git"):
        print("\nVerificando atualizações...\n")
        subprocess.run(["git", "-C", str(BASE), "pull", "--ff-only"], check=False)
    else:
        print("Git não está instalado. Execute: pkg install git")
    pause()


def settings():
    rc = Path.home() / ".bashrc"
    content = rc.read_text(encoding="utf-8", errors="ignore") if rc.exists() else ""
    enabled = "DROPNET_AUTO_MENU_BEGIN" in content
    print("\nCONFIGURAÇÕES\n")
    print("Inicialização automática: " + ("ATIVADA" if enabled else "DESATIVADA"))
    print("Para alterar: dropnet-autostart on  ou  dropnet-autostart off")
    print("\nStatus do aparelho depende do Termux:API e das permissões Android.")
    pause()


def history():
    print("\nHISTÓRICO DE RESULTADOS\n")
    OUT.mkdir(parents=True, exist_ok=True)
    files = sorted(OUT.glob("*.txt"), key=lambda p: p.stat().st_mtime, reverse=True)
    if not files:
        print("Nenhum resultado salvo ainda.")
    else:
        for file in files[:30]:
            print(f" {file.name} ({file.stat().st_size} bytes)")
    print(f"\nPasta: {OUT}")
    pause()


def help_page():
    print("\nDROPNET SCANNER v4.0")
    print("Ferramenta para verificar conectividade em hosts e faixas")
    print("que você tem autorização para testar.")
    print("Resultados: Downloads/DROPNET-SCANNER")
    print("\nPara bateria e operadora, instale o app Termux:API,")
    print("execute: pkg install termux-api")
    print("Depois conceda as permissões de telefone ao Termux:API.")
    pause()


def main():
    while True:
        header()
        try:
            choice = input("\n  Escolha uma opção: ").strip()
        except (EOFError, KeyboardInterrupt):
            print("\nAté mais!")
            return
        if choice == "1":
            start_scanner()
        elif choice == "2":
            providers()
        elif choice == "3":
            update()
        elif choice == "4":
            settings()
        elif choice == "5":
            history()
        elif choice == "6":
            help_page()
        elif choice == "0":
            print("\nDROPNET SCANNER encerrado. Até mais!")
            return
        else:
            print("\nOpção inválida.")
            time.sleep(1)


if __name__ == "__main__":
    main()
