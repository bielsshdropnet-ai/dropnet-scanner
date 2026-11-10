#!/data/data/com.termux/files/usr/bin/bash
# =====================================================================
#  DROPNET SCANNER — instalador completo para Termux (v3.1)
#  Rode UMA vez:   bash instalar.sh
#  ou direto do GitHub: curl -fsSL <URL-raw-do-instalar.sh> | bash
#  Faz tudo do guia: atualiza o Termux, instala python/git/curl/wget,
#  libera o armazenamento, clona o repositório do GitHub, cria os
#  comandos e já abre o scanner.
#      dropnet          -> scanner normal (sem root)
#      dropnet-root     -> scanner com SYN scan (precisa de root)
#      dropnet-update   -> git pull (atualiza pelo GitHub)
# =====================================================================
set -u

REPO_URL="${DROPNET_REPO:-https://github.com/bielsshdropnet-ai/dropnet-scanner.git}"
ARQ="ipv4scanner.py"

VERDE='\033[1;32m'; AMAR='\033[1;33m'; VERM='\033[1;31m'; CIAN='\033[1;36m'; RST='\033[0m'
ok()   { printf "${VERDE} ✔ %s${RST}\n" "$*"; }
info() { printf "${CIAN} ➜ %s${RST}\n" "$*"; }
aviso(){ printf "${AMAR} ! %s${RST}\n" "$*"; }
erro() { printf "${VERM} ✖ %s${RST}\n" "$*"; }

if ! command -v pkg >/dev/null 2>&1; then
    erro "Este instalador é para o Termux (comando 'pkg' não encontrado)."
    exit 1
fi

PREFIX="${PREFIX:-/data/data/com.termux/files/usr}"
DIR="$HOME/dropnet-scanner"
SELF_DIR="$(cd "$(dirname "${BASH_SOURCE[0]:-$0}")" 2>/dev/null && pwd)"

echo
printf "${CIAN}╔══════════════════════════════════════╗\n║   DROPNET SCANNER · instalador       ║\n╚══════════════════════════════════════╝${RST}\n\n"

# ---------- 1) atualizar o Termux ----------
info "1/5  Atualizando o Termux (pode demorar um pouco)..."
export DEBIAN_FRONTEND=noninteractive
pkg update -y >/dev/null 2>&1 || apt-get update -y >/dev/null 2>&1 || aviso "Não consegui atualizar a lista de pacotes (sem internet?). Continuando..."
apt-get -y -o Dpkg::Options::="--force-confold" upgrade >/dev/null 2>&1 || aviso "Upgrade parcial. Continuando..."
ok "Termux atualizado"

# ---------- 2) dependências ----------
info "2/5  Instalando python, git, curl, wget e root (tsu)..."
pkg install -y python git curl wget >/dev/null 2>&1
if ! command -v python >/dev/null 2>&1; then
    erro "Falhou instalar o Python. Verifique a internet e rode de novo."
    exit 1
fi
pkg install -y tsu termux-tools >/dev/null 2>&1 || aviso "Não consegui instalar o 'tsu' (só afeta o modo root)."
ok "Python $(python -V 2>&1 | awk '{print $2}') · git $(git --version 2>/dev/null | awk '{print $3}')"

# ---------- 3) armazenamento ----------
info "3/5  Liberando acesso ao armazenamento (onde ficam os resultados)..."
if [ ! -d "$HOME/storage/downloads" ]; then
    termux-setup-storage >/dev/null 2>&1
    aviso "Se aparecer um pedido de permissão na tela, toque em PERMITIR."
    for _ in 1 2 3 4 5 6 7 8 9 10; do
        [ -d "$HOME/storage/downloads" ] && break
        sleep 1
    done
fi
if [ -d "$HOME/storage/downloads" ]; then
    mkdir -p "$HOME/storage/downloads/DROPNET-SCANNER" 2>/dev/null
    ok "Resultados serão salvos em Download/DROPNET-SCANNER"
else
    aviso "Sem acesso ao armazenamento ainda. Rode 'termux-setup-storage' depois."
fi

# ---------- 4) repositório do GitHub ----------
info "4/5  Baixando o scanner do GitHub..."
PROV_ANTIGO=""
if [ -d "$DIR/.git" ]; then
    ( cd "$DIR" && git pull --ff-only ) >/dev/null 2>&1 && ok "Repositório atualizado (git pull)" \
        || aviso "git pull falhou (alterações locais?). Mantendo os arquivos atuais."
else
    if [ -d "$DIR" ]; then
        [ -f "$DIR/providers.json" ] && { PROV_ANTIGO="$HOME/.providers_anterior.json"; cp -f "$DIR/providers.json" "$PROV_ANTIGO"; }
        mv "$DIR" "$DIR.bak.$(date +%s)"
        aviso "Pasta antiga (sem git) guardada como $DIR.bak.*"
    fi
    if git clone "$REPO_URL" "$DIR" >/dev/null 2>&1; then
        ok "Repositório clonado"
    else
        aviso "Não consegui clonar o GitHub (sem internet ou repositório privado)."
        mkdir -p "$DIR"
    fi
fi
mkdir -p "$DIR"

if [ ! -f "$DIR/$ARQ" ]; then
    erro "Não consegui baixar o $ARQ do GitHub (sem internet ou repositório privado)."
    erro "Confira a internet e rode o instalador de novo."
    exit 1
fi
chmod +x "$DIR/$ARQ"
if grep -q -- "--syn-espera" "$DIR/$ARQ"; then
    ok "Scanner com modo root ($ARQ)"
else
    aviso "O $ARQ do GitHub é uma versão SEM modo root. O 'dropnet' funciona normal;"
    aviso "o 'dropnet-root' só funciona depois que você publicar a v3.1 no repositório."
fi

# providers.json: o do repositório; senão procura o seu; senão cria modelo
if [ ! -f "$DIR/providers.json" ]; then
    for cand in "$PROV_ANTIGO" "$SELF_DIR/providers.json" "$HOME/storage/downloads/providers.json" \
                "$HOME/storage/shared/Download/providers.json" "$HOME/providers.json"; do
        if [ -n "$cand" ] && [ -f "$cand" ]; then cp -f "$cand" "$DIR/providers.json"; ok "providers.json copiado de $cand"; break; fi
    done
fi
if [ ! -f "$DIR/providers.json" ]; then
    cat > "$DIR/providers.json" <<'PJ'
{
  "providers": [
    { "name": "exemplo", "cidrs": ["192.0.2.0/24"] }
  ]
}
PJ
    aviso "providers.json NÃO encontrado. Criei um modelo de exemplo em $DIR/providers.json"
    aviso "Troque pelo seu (mesmo formato)."
else
    ok "providers.json presente"
fi

# ---------- 5) comandos ----------
info "5/5  Criando os comandos dropnet, dropnet-root e dropnet-update..."
cat > "$PREFIX/bin/dropnet" <<'L1'
#!/data/data/com.termux/files/usr/bin/bash
termux-wake-lock 2>/dev/null
cd "$HOME/dropnet-scanner" || exit 1
exec python ipv4scanner.py "$@"
L1

cat > "$PREFIX/bin/dropnet-root" <<'L2'
#!/data/data/com.termux/files/usr/bin/bash
# Roda o scanner como root (SYN scan). Precisa de aparelho com root.
if ! command -v su >/dev/null 2>&1; then
    echo "su não encontrado: aparelho sem root. Use o comando 'dropnet'."
    exit 1
fi
termux-wake-lock 2>/dev/null
CMD="export HOME='$HOME' PREFIX='$PREFIX' PATH='$PATH' LD_LIBRARY_PATH='$PREFIX/lib' TERM='${TERM:-xterm-256color}'; cd '$HOME/dropnet-scanner' && python ipv4scanner.py --root"
for a in "$@"; do CMD+=" $(printf '%q' "$a")"; done
exec su -c "$CMD"
L2

cat > "$PREFIX/bin/dropnet-update" <<'L3'
#!/data/data/com.termux/files/usr/bin/bash
cd "$HOME/dropnet-scanner" || exit 1
git pull --ff-only && echo "Atualizado."
L3
chmod +x "$PREFIX/bin/dropnet" "$PREFIX/bin/dropnet-root" "$PREFIX/bin/dropnet-update"
ok "Comandos criados"

echo
printf "${VERDE}══════════════════════════════════════\n  INSTALAÇÃO CONCLUÍDA\n══════════════════════════════════════${RST}\n"
echo "  dropnet          -> scanner normal (sem root)"
echo "  dropnet-root     -> scanner com SYN scan (root)"
echo "  dropnet-update   -> atualiza pelo GitHub (git pull)"
echo "  Resultados:      Download/DROPNET-SCANNER (salvos sozinhos)"
echo

if { true </dev/tty; } 2>/dev/null; then
    printf "${CIAN}Abrir agora? [Enter = normal · r = root · n = sair]: ${RST}"
    read -r R </dev/tty
    case "${R,,}" in
        n) exit 0 ;;
        r) exec dropnet-root ;;
        *) exec dropnet ;;
    esac
fi
