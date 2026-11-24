# DROPNET - MENU DE SCANNERS
# Tela secundária simplificada.
# Esta função exibe o menu e retorna a opção digitada.

def mostrar_menu_scanners():
    print()
    print("╔══════════════════════════════════════╗")
    print("║          DROPNET - SCANNERS           ║")
    print("╠══════════════════════════════════════╣")
    print("║                                      ║")
    print("║  [1] SCAN DE CDN                     ║")
    print("║  [2] SCAN DE PROXY                   ║")
    print("║  [3] SCAN DE REDE                    ║")
    print("║  [4] BGP INTELLIGENCE                ║")
    print("║                                      ║")
    print("║  [0] VOLTAR AO MENU PRINCIPAL        ║")
    print("║                                      ║")
    print("╚══════════════════════════════════════╝")
    return input("\nDigite a opção: ").strip()


if __name__ == "__main__":
    opcao = mostrar_menu_scanners()
    print(f"Opção selecionada: {opcao}")
