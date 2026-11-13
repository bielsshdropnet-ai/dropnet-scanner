
#!/data/data/com.termux/files/usr/bin/bash
# ============================================
#  DROPNET SCANNER - Instalador para Termux
# ============================================

REPO="https://github.com/bielsshdropnet-ai/dropnet-scanner.git"
DIR="$HOME/dropnet-scanner"
SAIDA="$HOME/storage/downloads/DROPNET-SCANNER"

verde="\033[1;32m"; vermelho="\033[1;31m"; amarelo="\033[1;33m"; reset="\033[0m"
ok()   { echo -e "${verde}[OK]${reset} $1"; }
info() { echo -e "${amarelo}[..]${reset} $1"; }
erro() { echo -e "${vermelho}[ERRO]${reset} $1"; exit 1; }

clear
echo "=========================================="
echo "     DROPNET SCANNER - INSTALADOR"
echo "=========================================="
echo

# 1. Atualizar pacotes
info "Atualizando pacotes..."
yes | pkg update -y || erro "Falha ao atualizar pacotes."
yes | pkg upgrade -y || erro "Falha ao atualizar pacotes."
ok "Pacotes atualizados"

# 2. Instalar dependências
info "Instalando python, git, curl e wget..."
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

# 4. Baixar ou atualizar scanner
if [ -d "$DIR/.git" ]; then
  info "Scanner já existe, atualizando..."
  git -C "$DIR" pull || erro "Falha ao atualizar scanner."
else
  info "Baixando scanner..."
  git clone "$REPO" "$DIR" || erro "Falha ao clonar scanner."
fi
ok "Scanner pronto"

# 5. Verificar arquivos
[ -f "$DIR/ipv4scanner.py" ] || erro "ipv4scanner.py não encontrado."
[ -f "$DIR/providers.json" ] || erro "providers.json não encontrado."
ok "Arquivos conferidos"

# 6. Pasta de resultados
mkdir -p "$SAIDA" || erro "Falha ao criar pasta."

python -c "import os; p=os.path.expanduser('~/storage/downloads/DROPNET-SCANNER/teste_python.txt'); open(p,'w').write('SALVAMENTO OK'); print('Arquivo salvo:',p)" || erro "Falha ao testar gravação."
ok "Salvamento testado"

# 7. Criar comando de inicialização
LAUNCHER="$PREFIX/bin/dropnet"

cat > "$LAUNCHER" << 'EOF'
#!/data/data/com.termux/files/usr/bin/bash

DIR="$HOME/dropnet-scanner"
SAIDA="$HOME/storage/downloads/DROPNET-SCANNER"

cd "$DIR" || exit 1
mkdir -p "$SAIDA"

python ipv4scanner.py

for f in "$DIR"/dropnet_*.txt; do
  [ -f "$f" ] && cp "$f" "$SAIDA/" && echo "Salvo: $SAIDA/$(basename "$f")"
done
EOF

chmod +x "$LAUNCHER"
ok "Comando criado: dropnet"

echo
echo "=========================================="
echo -e "${verde} INSTALAÇÃO CONCLUÍDA!${reset}"
echo "=========================================="
echo "Para abrir o scanner, digite:"
echo "     dropnet"
echo
echo "Resultados ficam em:"
echo "     Downloads/DROPNET-SCANNER"
echo "=========================================="
