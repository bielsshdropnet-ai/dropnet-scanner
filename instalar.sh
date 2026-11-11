#!/data/data/com.termux/files/usr/bin/bash
# DROPNET SCANNER — instalador para Termux
# Uso: bash instalar.sh
# Também pode ser executado por: curl -fsSL URL_RAW | bash

set -Eeuo pipefail

REPO_URL="${DROPNET_REPO:-https://github.com/bielsshdropnet-ai/dropnet-scanner.git}"
DIR="$HOME/dropnet-scanner"
ARQ="ipv4scanner.py"
PREFIX="${PREFIX:-/data/data/com.termux/files/usr}"
LOG="$HOME/.dropnet_install.log"

VERDE='\033[1;32m'
AMAR='\033[1;33m'
VERM='\033[1;31m'
CIAN='\033[1;36m'
RST='\033[0m'

ok()    { printf "${VERDE}[OK] %s${RST}\n" "$*"; }
info()  { printf "${CIAN}[*] %s${RST}\n" "$*"; }
aviso() { printf "${AMAR}[AVISO] %s${RST}\n" "$*"; }
erro()  { printf "${VERM}[ERRO] %s${RST}\n" "$*" >&2; }

falha() {
    local rc=$?
    erro "A instalação foi interrompida na linha ${BASH_LINENO[0]:-desconhecida} (código $rc)."
    erro "Consulte o log completo: $LOG"
    exit "$rc"
}
trap falha ERR

# Registra a saída completa do instalador em um arquivo, sem esconder
# o que está acontecendo na tela.
mkdir -p "$HOME"
touch "$LOG"
exec > >(tee -a "$LOG") 2>&1

executar() {
    info "Executando: $*"
    "$@"
}

mostrar_titulo() {
    printf "\n${CIAN}"
    printf '╔════════════════════════════════════════════╗\n'
    printf '║          DROPNET SCANNER INSTALLER         ║\n'
    printf '╚════════════════════════════════════════════╝\n'
    printf "${RST}\n"
}

main() {
    mostrar_titulo

    if ! command -v pkg >/dev/null 2>&1; then
        erro "Este instalador precisa ser executado dentro do Termux."
        erro "O comando 'pkg' não foi encontrado."
        exit 1
    fi

    if [[ ! -d "$PREFIX/bin" ]]; then
        erro "Diretório de comandos do Termux não encontrado: $PREFIX/bin"
        exit 1
    fi

    # 1. Atualização do Termux
    printf "\n${CIAN}========== [1/7] ATUALIZANDO O TERMUX ==========${RST}\n"
    executar pkg update -y
    executar pkg upgrade -y
    ok "Termux atualizado."

    # 2. Dependências
    printf "\n${CIAN}========== [2/7] INSTALANDO DEPENDÊNCIAS ==========${RST}\n"
    info "Pacotes solicitados: Python, Git, cURL e Wget."
    executar pkg install python git curl wget -y

    for pacote in python git curl wget; do
        if ! command -v "$pacote" >/dev/null 2>&1; then
            erro "O comando '$pacote' não foi encontrado após a instalação."
            exit 1
        fi
        ok "$pacote instalado: $(command -v "$pacote")"
    done

    info "Versões instaladas:"
    python --version
    git --version
    curl --version | head -n 1
    wget --version | head -n 1

    # 3. Armazenamento
    printf "\n${CIAN}========== [3/7] CONFIGURANDO ARMAZENAMENTO ==========${RST}\n"
    if [[ ! -d "$HOME/storage/downloads" ]]; then
        aviso "O acesso ao armazenamento pode solicitar autorização do Android."
        executar termux-setup-storage
    else
        ok "Atalho do armazenamento já existe."
    fi

    if [[ -d "$HOME/storage/downloads" ]]; then
        executar mkdir -p "$HOME/storage/downloads/DROPNET-SCANNER"
        ok "Pasta de resultados: $HOME/storage/downloads/DROPNET-SCANNER"
    else
        aviso "A pasta Download ainda não está acessível."
        aviso "Depois de permitir o acesso no Android, execute:"
        aviso "termux-setup-storage"
        aviso "mkdir -p ~/storage/downloads/DROPNET-SCANNER"
    fi

    # 4. Repositório
    printf "\n${CIAN}========== [4/7] BAIXANDO / ATUALIZANDO GITHUB ==========${RST}\n"
    if [[ -d "$DIR/.git" ]]; then
        info "Repositório existente encontrado em $DIR"
        executar git -C "$DIR" pull --ff-only
        ok "Repositório atualizado pelo GitHub."
    else
        if [[ -e "$DIR" ]]; then
            BACKUP="${DIR}.backup.$(date +%Y%m%d-%H%M%S)"
            executar mv "$DIR" "$BACKUP"
            aviso "Pasta anterior guardada em: $BACKUP"
        fi
        executar git clone "$REPO_URL" "$DIR"
        ok "Repositório baixado."
    fi

    # 5. Verificação dos arquivos
    printf "\n${CIAN}========== [5/7] VERIFICANDO ARQUIVOS ==========${RST}\n"
    if [[ ! -f "$DIR/$ARQ" ]]; then
        erro "Arquivo obrigatório não encontrado: $DIR/$ARQ"
        erro "Confira se o repositório contém $ARQ e tente novamente."
        exit 1
    fi
    ok "$ARQ encontrado."

    if [[ ! -f "$DIR/providers.json" ]]; then
        erro "Arquivo providers.json não encontrado em $DIR."
        erro "O guia do DROPNET espera esse arquivo no repositório."
        exit 1
    fi
    ok "providers.json encontrado."

    info "Verificando a sintaxe do arquivo Python..."
    executar python -m py_compile "$DIR/$ARQ"
    ok "Sintaxe Python verificada."

    # 6. Comandos rápidos
    printf "\n${CIAN}========== [6/7] CRIANDO COMANDOS ==========${RST}\n"

    info "Criando comando dropnet..."
    cat > "$PREFIX/bin/dropnet" <<'DROP'
#!/data/data/com.termux/files/usr/bin/bash
termux-wake-lock 2>/dev/null || true
cd "$HOME/dropnet-scanner" || exit 1
exec python ipv4scanner.py "$@"
DROP
    chmod 755 "$PREFIX/bin/dropnet"
    ok "Comando dropnet criado."

    info "Criando comando dropnet-update..."
    cat > "$PREFIX/bin/dropnet-update" <<'UPDATE'
#!/data/data/com.termux/files/usr/bin/bash
set -e
cd "$HOME/dropnet-scanner" || exit 1
echo "[*] Buscando atualizações no GitHub..."
git pull --ff-only
echo "[*] Verificando o arquivo Python..."
python -m py_compile ipv4scanner.py
echo "[OK] DROPNET SCANNER atualizado."
UPDATE
    chmod 755 "$PREFIX/bin/dropnet-update"
    ok "Comando dropnet-update criado."

    # 7. Finalização
    printf "\n${CIAN}========== [7/7] FINALIZANDO ==========${RST}\n"
    ok "Instalação concluída."
    printf "\nComandos disponíveis:\n"
    printf "  dropnet          - abrir o scanner\n"
    printf "  dropnet-update   - atualizar pelo GitHub\n"
    printf "\nPasta de resultados esperada:\n"
    printf "  Download/DROPNET-SCANNER\n"
    printf "\nLog completo da instalação:\n  %s\n" "$LOG"

    printf "\n${AMAR}IMPORTANTE:${RST} o instalador cria a pasta de resultados, mas o salvamento\n"
    printf "automático depende de o ipv4scanner.py gravar os arquivos nesse caminho.\n"

    # Permite abrir o scanner mesmo quando o instalador foi chamado por curl | bash.
    if { true </dev/tty; } 2>/dev/null; then
        printf "\n${CIAN}Abrir o scanner agora? [Enter = sim / n = não]: ${RST}"
        read -r RESPOSTA </dev/tty || RESPOSTA="n"
        if [[ "${RESPOSTA,,}" != "n" ]]; then
            exec "$PREFIX/bin/dropnet"
        fi
    fi
}

main "$@"
