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
import threading
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


_STATUS_LOCK = threading.Lock()
_STATUS = {
    "now": datetime.datetime.now().strftime("%d/%m/%Y %H:%M"),
    "battery": "consultando",
    "network": "identificando...",
    "root": "verificando...",
}
_STATUS_THREAD_STARTED = False


def read_file(path):
    try:
        return Path(path).read_text(encoding="utf-8", errors="ignore").strip()
    except OSError:
        return ""


def fast_battery():
    # Leitura direta do kernel: não depende de serviço Android/API.
    for path in (
        "/sys/class/power_supply/battery/capacity",
        "/sys/class/power_supply/BAT0/capacity",
    ):
        value = read_file(path)
        if value.isdigit():
            return f"{int(value)}%"
    return ""


def default_route_interface():
    # /proc/net/route é local e rápido; wlan* indica Wi-Fi.
    try:
        lines = Path("/proc/net/route").read_text().splitlines()[1:]
        for line in lines:
            fields = line.split()
            if len(fields) > 3 and fields[1] == "00000000":
                flags = int(fields[3], 16)
                if flags & 1:
                    return fields[0]
    except (OSError, ValueError, IndexError):
        pass
    # Fallback para IPv6 quando disponível.
    try:
        for line in Path("/proc/net/ipv6_route").read_text().splitlines():
            fields = line.split()
            if len(fields) >= 10 and fields[0] == "0" * 32:
                return fields[-1]
    except OSError:
        pass
    return ""


def getprop(name, timeout=0.6):
    executable = shutil.which("getprop")
    if not executable:
        return ""
    try:
        result = subprocess.run(
            [executable, name], capture_output=True, text=True,
            timeout=timeout, check=False
        )
        value = result.stdout.strip()
        if value and value.lower() not in ("unknown", "null"):
            return value
    except (OSError, subprocess.SubprocessError):
        pass
    return ""


def fast_network():
    iface = default_route_interface()
    if iface.startswith(("wlan", "wifi")):
        return "Wi-Fi"

    # Propriedade gsm.operator.alpha reflete a rede registrada, não só o SIM.
    operator = getprop("gsm.operator.alpha")
    if operator:
        names = [part.strip() for part in operator.split(",") if part.strip()]
        if names:
            return " / ".join(dict.fromkeys(names))[:24]

    # Se a rota padrão for móvel, tenta identificar a operadora do registro.
    if iface.startswith(("rmnet", "ccmni", "pdp", "wwan", "v4-rmnet")):
        return "Rede móvel"

    # Propriedade de Wi-Fi como fallback, sem confundir SIM com conexão ativa.
    wifi_state = getprop("wifi.interface")
    if wifi_state and iface.startswith(("wlan", "wifi")):
        return "Wi-Fi"
    return "sem conexão identificada" if not iface else "rede: " + iface[:16]


def detect_root():
    """Verifica autorização do su sem executar o scanner inteiro como root."""
    su = shutil.which("su")
    if not su:
        return "SEM ROOT"
    try:
        result = subprocess.run(
            [su, "-c", "id -u"],
            capture_output=True, text=True, timeout=4, check=False
        )
        if result.returncode == 0 and result.stdout.strip() == "0":
            return "ROOT ATIVO"
        if result.returncode != 0:
            return "ROOT NEGADO"
    except subprocess.TimeoutExpired:
        return "ROOT NÃO DETECTADO"
    except OSError:
        return "SEM ROOT"
    return "SEM ROOT"


def refresh_status():
    """Atualiza os dados em segundo plano para nunca atrasar a abertura do menu."""
    while True:
        now = datetime.datetime.now().strftime("%d/%m/%Y %H:%M")
        battery = fast_battery()
        network = fast_network()
        root = detect_root()

        # Termux:API é fallback; timeout curto para não prender a atualização.
        if not battery:
            data = command_json("termux-battery-status", timeout=1.0)
            if isinstance(data, dict) and data.get("percentage") is not None:
                try:
                    battery = f"{int(data['percentage'])}%"
                except (TypeError, ValueError):
                    battery = ""
        if not battery:
            battery = "indisponível"

        # Consulta de telefonia somente se a rota indicar rede móvel e getprop falhar.
        if network == "Rede móvel":
            phone = command_json("termux-telephony-deviceinfo", timeout=1.0)
            if isinstance(phone, dict):
                candidate = (
                    phone.get("network_operator_name")
                    or phone.get("network_operator")
                )
                if isinstance(candidate, str) and candidate.strip():
                    network = " ".join(candidate.split())[:24]

        with _STATUS_LOCK:
            _STATUS.update({
                "now": now,
                "battery": battery,
                "network": network,
                "root": root,
            })
        time.sleep(20)


def start_status_worker():
    global _STATUS_THREAD_STARTED
    if _STATUS_THREAD_STARTED:
        return
    _STATUS_THREAD_STARTED = True

    # Primeira leitura é local e rápida; APIs lentas rodam só na thread.
    with _STATUS_LOCK:
        _STATUS["now"] = datetime.datetime.now().strftime("%d/%m/%Y %H:%M")
        _STATUS["battery"] = fast_battery() or "consultando..."
        _STATUS["network"] = fast_network()

    worker = threading.Thread(target=refresh_status, daemon=True)
    worker.start()


def device_status():
    with _STATUS_LOCK:
        return (
            _STATUS["now"],
            _STATUS["battery"],
            _STATUS["network"],
            _STATUS["root"],
        )


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
    print(f"{BOLD}{CYAN}│{RESET}{fit('Versão 5.0'.center(inner), inner)}{BOLD}{CYAN}│{RESET}")
    print(f"{BOLD}{CYAN}├{'─' * inner}┤{RESET}")
    status_lines = [
        f"Data: {now}",
        f"Bateria: {battery}  |  {root}",
        f"Conexão: {operator}",
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
    print("\nDROPNET SCANNER v5.0")
    print("Ferramenta para verificar conectividade em hosts e faixas")
    print("que você tem autorização para testar.")
    print("Resultados: Downloads/DROPNET-SCANNER")
    print("\nPara bateria e operadora, instale o app Termux:API,")
    print("execute: pkg install termux-api")
    print("Depois conceda as permissões de telefone ao Termux:API.")
    pause()


def main():
    start_status_worker()
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
