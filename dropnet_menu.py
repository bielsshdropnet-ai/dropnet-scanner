#!/usr/bin/env python3
"""Menu inicial do DROPNET SCANNER para Termux."""
import datetime
import json
import os
import shutil
import subprocess
import sys
import time
from pathlib import Path

BASE = Path(__file__).resolve().parent
PYTHON = sys.executable
OUT = Path.home() / "storage" / "downloads" / "DROPNET-SCANNER"


def status_device():
    now = datetime.datetime.now().strftime("%d/%m/%Y   %H:%M")
    root = "Com Root" if hasattr(os, "geteuid") and os.geteuid() == 0 else "Sem Root"
    battery = "--%"
    cmd = shutil.which("termux-battery-status")
    if cmd:
        try:
            data = json.loads(subprocess.check_output([cmd], text=True, timeout=3))
            battery = f"{data.get('percentage', '--')}%"
        except Exception:
            pass
    return now, root, battery


def header():
    now, root, battery = status_device()
    print("\033[2J\033[H", end="")
    print("╔════════════════════════════════════════════╗")
    print("║        D R O P N E T   S C A N N E R       ║")
    print("║                 Versão 3.0                 ║")
    print("╠════════════════════════════════════════════╣")
    print(f"║  📅 {now:<22}              ║")
    print(f"║  📶 Termux   🔋 {battery:<5}  {'🛡️ ' + root:<17}║")
    print("╠════════════════════════════════════════════╣")
    print("║             M E N U   P R I N C I P A L    ║")
    print("║                                            ║")
    print("║   1) 🚀 Iniciar Scanner                    ║")
    print("║   2) 📋 Escolher CDN / Provedor            ║")
    print("║   3) 🔄 Verificar Atualização              ║")
    print("║   4) ⚙️  Configurações                     ║")
    print("║   5) 📊 Histórico de Resultados            ║")
    print("║   6) ❓ Sobre / Ajuda                      ║")
    print("║   0) 🚪 Sair                               ║")
    print("║                                            ║")
    print("╠════════════════════════════════════════════╣")


def pause():
    input("\nPressione Enter para voltar ao menu...")


def start_scanner():
    script = BASE / "ipv4scanner.py"
    if not script.exists():
        print("[ERRO] ipv4scanner.py não encontrado.")
        pause()
        return
    print("\nIniciando DROPNET SCANNER...\n")
    try:
        subprocess.run([PYTHON, str(script)], cwd=str(BASE), check=False)
    except KeyboardInterrupt:
        print("\nScanner interrompido pelo usuário.")
    OUT.mkdir(parents=True, exist_ok=True)
    for f in BASE.glob("dropnet_*.txt"):
        try:
            shutil.copy2(f, OUT / f.name)
        except OSError:
            pass
    pause()


def providers():
    path = BASE / "providers.json"
    print("\nCDNs / PROVEDORES DISPONÍVEIS\n")
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
        items = data.get("providers", [])
        for i, item in enumerate(items, 1):
            print(f" {i:>3}) {item.get('name', 'Sem nome')}")
        print(f"\nTotal: {len(items)} provedores")
        print("A seleção de provedor será integrada ao fluxo do scanner na próxima etapa.")
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
    print("Para alterar, execute no Termux: dropnet-autostart on  ou  dropnet-autostart off")
    pause()


def history():
    print("\nHISTÓRICO DE RESULTADOS\n")
    OUT.mkdir(parents=True, exist_ok=True)
    files = sorted(OUT.glob("*.txt"), key=lambda p: p.stat().st_mtime, reverse=True)
    if not files:
        print("Nenhum resultado salvo ainda.")
    else:
        for f in files[:30]:
            size = f.stat().st_size
            print(f" {f.name}  ({size} bytes)")
    print(f"\nPasta: {OUT}")
    pause()


def help_page():
    print("\nDROPNET SCANNER v3.0")
    print("Ferramenta para verificar conectividade em faixas e hosts que você tem autorização para testar.")
    print("Use a opção 1 para abrir o scanner original. Os resultados são copiados para Downloads/DROPNET-SCANNER.")
    pause()


def main():
    while True:
        header()
        try:
            choice = input("║  ► Escolha uma opção: ").strip()
        except (EOFError, KeyboardInterrupt):
            print("\nAté mais!")
            return
        if choice == "1": start_scanner()
        elif choice == "2": providers()
        elif choice == "3": update()
        elif choice == "4": settings()
        elif choice == "5": history()
        elif choice == "6": help_page()
        elif choice == "0":
            print("\nDROPNET SCANNER encerrado. Até mais!")
            return
        else:
            print("\nOpção inválida.")
            time.sleep(1)


if __name__ == "__main__":
    main()
