#!/bin/sh
# AutoPwn AI installer — Linux and macOS.
#
#   curl -fsSL https://raw.githubusercontent.com/AshrafMostafaNmap/autopwn-ai/main/install.sh | sh
#
# Options (after `sh -s --` when piped):
#   --ref <tag|branch>   install a specific version (default: main)
#   --with-browser       add Playwright browser recon (downloads Chromium)
#   --with-pdf           add PDF reports (needs pango/cairo system libraries)
#   --from <path|url>    install from a local checkout or another git URL
#   --no-setup           do not open the setup wizard afterwards
#   --uninstall          remove AutoPwn AI (your settings and keys are kept)
#
# It installs uv (https://docs.astral.sh/uv) if missing, then the `autopwnai`
# command into an isolated environment with its own Python. Nothing runs as root.
set -eu

REPO="${AUTOPWN_REPO:-https://github.com/AshrafMostafaNmap/autopwn-ai}"
PACKAGE="autopwn-ai"
REF="main"
SOURCE=""
EXTRAS=""
BROWSER=0
RUN_SETUP=1
UNINSTALL=0

if [ -t 1 ]; then
    G="$(printf '\033[32m')"; R="$(printf '\033[31m')"; D="$(printf '\033[2m')"
    B="$(printf '\033[1m')"; N="$(printf '\033[0m')"
else
    G=""; R=""; D=""; B=""; N=""
fi
say()  { printf '%s\n' "$*"; }
step() { printf '%s›%s %s\n' "$G" "$N" "$*"; }
fail() { printf '%s✗ %s%s\n' "$R" "$*" "$N" >&2; exit 1; }

add_extra() { EXTRAS="${EXTRAS:+$EXTRAS,}$1"; }

while [ $# -gt 0 ]; do
    case "$1" in
        --ref) [ $# -ge 2 ] || fail "--ref needs a value"; REF="$2"; shift 2 ;;
        --from) [ $# -ge 2 ] || fail "--from needs a value"; SOURCE="$2"; shift 2 ;;
        --with-browser) add_extra browser; BROWSER=1; shift ;;
        --with-pdf) add_extra pdf; shift ;;
        --no-setup) RUN_SETUP=0; shift ;;
        --uninstall) UNINSTALL=1; shift ;;
        -h|--help) sed -n '2,16p' "$0" 2>/dev/null | sed 's/^# \{0,1\}//'; exit 0 ;;
        *) fail "unknown option: $1 (see --help)" ;;
    esac
done

case "$(uname -s)" in
    Linux|Darwin) ;;
    *) fail "this installer supports Linux and macOS. On Windows: install uv, then run
   uv tool install git+$REPO" ;;
esac

find_uv() {
    if command -v uv >/dev/null 2>&1; then command -v uv; return; fi
    for c in "$HOME/.local/bin/uv" "$HOME/.cargo/bin/uv"; do
        [ -x "$c" ] && { echo "$c"; return; }
    done
}

if [ "$UNINSTALL" = 1 ]; then
    UV="$(find_uv)"
    [ -n "$UV" ] || fail "uv not found — nothing to uninstall"
    "$UV" tool uninstall "$PACKAGE" && say "${G}✓${N} AutoPwn AI removed. Settings and keys stay in ~/.config/autopwn (delete it to forget them)."
    exit 0
fi

say ""
say "${B}AutoPwn AI${N} ${D}— purple-team vulnerability discovery agent${N}"
say ""

UV="$(find_uv)"
if [ -z "$UV" ]; then
    step "installing uv (Python package manager) into ~/.local/bin"
    command -v curl >/dev/null 2>&1 || fail "curl is required"
    curl -LsSf https://astral.sh/uv/install.sh | env UV_NO_MODIFY_PATH=1 sh >/dev/null
    UV="$(find_uv)"
    [ -n "$UV" ] || fail "uv installation failed — see https://docs.astral.sh/uv/getting-started/installation/"
fi
step "using $("$UV" --version)"

if [ -n "$SOURCE" ]; then
    case "$SOURCE" in
        http*://*|git+*|ssh://*|git@*) TARGET="git+${SOURCE#git+}" ;;
        *) [ -e "$SOURCE" ] || fail "--from: $SOURCE not found"; TARGET="$(cd "$SOURCE" && pwd)" ;;
    esac
else
    TARGET="git+$REPO@$REF"
fi
SPEC="$PACKAGE"
[ -n "$EXTRAS" ] && SPEC="${PACKAGE}[${EXTRAS}]"

step "installing $SPEC from ${TARGET#git+}  ${D}(first install downloads ~100 MB)${N}"
"$UV" tool install --force --python ">=3.12" "$SPEC @ $TARGET" || fail "installation failed (see the output above)"

BIN_DIR="$("$UV" tool dir --bin 2>/dev/null || echo "$HOME/.local/bin")"
TOOL_DIR="$("$UV" tool dir)"
APP="$BIN_DIR/autopwnai"
[ -x "$APP" ] || fail "install finished but $APP is missing"

if [ "$BROWSER" = 1 ]; then
    step "downloading Chromium for browser recon"
    "$TOOL_DIR/$PACKAGE/bin/python" -m playwright install chromium >/dev/null || \
        say "${D}  could not download Chromium — run later: $TOOL_DIR/$PACKAGE/bin/python -m playwright install chromium${N}"
fi

say ""
say "${G}✓${N} installed: $("$APP" --version 2>/dev/null || echo autopwnai)"

case ":$PATH:" in
    *":$BIN_DIR:"*) ON_PATH=1 ;;
    *) ON_PATH=0 ;;
esac
if [ "$ON_PATH" = 0 ]; then
    "$UV" tool update-shell >/dev/null 2>&1 || true
    say "  ${B}$BIN_DIR${N} was added to your PATH — open a new terminal (or run: export PATH=\"$BIN_DIR:\$PATH\")"
fi

say ""
say "  start:      ${B}autopwnai${N}"
say "  setup:      ${B}autopwnai setup${N}   ${D}(providers, keys, model)${N}"
say "  update:     ${B}curl -fsSL <this script> | sh${N}"
say "  uninstall:  ${B}curl -fsSL <this script> | sh -s -- --uninstall${N}"
say ""

if [ "$RUN_SETUP" = 1 ] && [ -t 1 ] && [ -r /dev/tty ] && [ -z "${CI:-}" ]; then
    printf '%s' "Open the setup wizard now? [Y/n] "
    read -r answer </dev/tty || answer="n"
    case "$answer" in
        n|N|no|NO) say "Run ${B}autopwnai setup${N} whenever you are ready." ;;
        *) exec "$APP" setup </dev/tty ;;
    esac
fi
