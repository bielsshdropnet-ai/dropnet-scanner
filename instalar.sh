
#!/data/data/com.termux/files/usr/bin/bash
# ============================================
#  DROPNET SCANNER - Instalador para Termux
# ============================================

REPO="https://github.com/bielsshdropnet-ai/dropnet-scanner.git"
DIR="$HOME/dropnet-scanner"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SAIDA="$HOME/storage/downloads/DROPNET-SCANNER"

verde="\033[1;32m"; vermelho="\033[1;31m"; amarelo="\033[1;33m"; reset="\033[0m"

ok()   { echo -e "${verde}[OK]${reset} $1"; }
info() { echo -e "${amarelo}[..]${reset} $1"; }
erro() { echo -e "${vermelho}[ERRO]${reset} $1"; exit 1; }

clear
echo "=========================================="
echo "       DROPNET SCANNER - INSTALADOR"
echo "=========================================="
echo

# 1. Atualizar pacotes
info "Atualizando pacotes..."
yes | pkg update -y || erro "Falha ao atualizar pacotes."
yes | pkg upgrade -y || erro "Falha ao atualizar pacotes."
ok "Pacotes atualizados"

# 2. Instalar dependências
info "Instalando Python, Git, Curl e Wget..."
yes | pkg install python git curl wget -y || erro "Falha ao instalar dependências."
ok "Dependências instaladas"

# 3. Permissão de armazenamento
if [ ! -d "$HOME/storage/downloads" ]; then
    info "Solicitando permissão de armazenamento..."
    termux-setup-storage

    for i in $(seq 1 20); do
        [ -d "$HOME/storage/downloads" ] && break
        sleep 1
    done
fi

[ -d "$HOME/storage/downloads" ] || erro "Permissão de armazenamento não concedida."
ok "Armazenamento liberado"

# 4. Instalar arquivos do pacote atual (inclui o novo menu)
if [ -f "$SCRIPT_DIR/ipv4scanner.py" ] && [ -f "$SCRIPT_DIR/providers.json" ]; then
    info "Instalando arquivos do pacote DROPNET..."
    mkdir -p "$DIR" || erro "Falha ao criar pasta do scanner."
    cp "$SCRIPT_DIR/ipv4scanner.py" "$SCRIPT_DIR/providers.json" "$DIR/" || erro "Falha ao copiar arquivos principais."
    [ ! -f "$SCRIPT_DIR/dropnet_menu.py" ] || cp "$SCRIPT_DIR/dropnet_menu.py" "$DIR/" || erro "Falha ao copiar menu principal."
    [ ! -f "$SCRIPT_DIR/dropnet_menu.py" ] && erro "dropnet_menu.py não encontrado no pacote."
else
    if [ -d "$DIR/.git" ]; then
        info "Scanner já existe, atualizando pelo Git..."
        git -C "$DIR" pull || erro "Falha ao atualizar scanner."
    else
        info "Baixando scanner pelo Git..."
        git clone "$REPO" "$DIR" || erro "Falha ao clonar scanner."
    fi
fi

ok "Scanner pronto"

# 5. Verificar arquivos
[ -f "$DIR/ipv4scanner.py" ] || erro "ipv4scanner.py não encontrado."
[ -f "$DIR/providers.json" ] || erro "providers.json não encontrado."

ok "Arquivos conferidos"

# 6. Criar pasta de resultados e testar gravação
mkdir -p "$SAIDA" || erro "Falha ao criar pasta de resultados."

python -c "import os; p=os.path.expanduser('~/storage/downloads/DROPNET-SCANNER/teste_python.txt'); open(p,'w').write('SALVAMENTO OK'); print('Arquivo salvo:',p)" || erro "Falha ao testar gravação."

ok "Salvamento testado"

# 7. Criar menu principal e comandos
MENU_LAUNCHER="$PREFIX/bin/menu"
cat > "$MENU_LAUNCHER" << 'EOF'
#!/data/data/com.termux/files/usr/bin/bash
DIR="$HOME/dropnet-scanner"
cd "$DIR" || exit 1
exec python "$DIR/dropnet_menu.py"
EOF
chmod +x "$MENU_LAUNCHER"

# Comando para ativar/desativar a abertura automática do menu
AUTO_CMD="$PREFIX/bin/dropnet-autostart"
cat > "$AUTO_CMD" << 'EOF'
#!/data/data/com.termux/files/usr/bin/bash
MODE="${1:-status}"
FILES=("$HOME/.bashrc" "$HOME/.bash_profile")
BEGIN="# DROPNET_AUTO_MENU_BEGIN"
END="# DROPNET_AUTO_MENU_END"
case "$MODE" in
  on)
    for FILE in "${FILES[@]}"; do
      touch "$FILE"
      if ! grep -qF "$BEGIN" "$FILE"; then
        cat >> "$FILE" << 'BLOCK'
# DROPNET_AUTO_MENU_BEGIN
case $- in
  *i*)
    if [ -z "${DROPNET_AUTO_MENU_ACTIVE:-}" ] && [ -x "$PREFIX/bin/menu" ]; then
      export DROPNET_AUTO_MENU_ACTIVE=1
      menu
    fi
    ;;
esac
# DROPNET_AUTO_MENU_END
BLOCK
      fi
    done
    echo "[OK] Menu automático ativado. Feche e abra o Termux novamente."
    ;;
  off)
    for FILE in "${FILES[@]}"; do
      [ -f "$FILE" ] || continue
      TMP="$FILE.dropnet.tmp"
      awk -v b="$BEGIN" -v e="$END" '$0==b {skip=1; next} $0==e {skip=0; next} !skip {print}' "$FILE" > "$TMP"
      mv "$TMP" "$FILE"
    done
    echo "[OK] Menu automático desativado."
    ;;
  status)
    if grep -qF "$BEGIN" "${FILES[@]}" 2>/dev/null; then
      echo "Menu automático: ATIVADO"
    else
      echo "Menu automático: DESATIVADO"
    fi
    echo "Use: dropnet-autostart on | off"
    ;;
  *) echo "Uso: dropnet-autostart on|off|status"; exit 1 ;;
esac
EOF
chmod +x "$AUTO_CMD"

# 8. Ativar inicialização automática
"$AUTO_CMD" on || erro "Não foi possível configurar a inicialização automática."
ok "Menu principal criado e configurado para abrir com o Termux"

# 9. Finalização
echo
echo "=========================================="
echo -e "${verde} INSTALAÇÃO CONCLUÍDA!${reset}"
echo "=========================================="
echo
echo "O menu abrirá automaticamente ao iniciar o Termux."
echo "Para abrir manualmente: menu"
echo "Para desativar a abertura automática: dropnet-autostart off"
echo "Para ativar novamente: dropnet-autostart on"
echo
echo "Resultados: Downloads/DROPNET-SCANNER"
echo "=========================================="
