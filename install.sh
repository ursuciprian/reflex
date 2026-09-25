#!/usr/bin/env bash
# Reflex installer: fetch the package from GitHub Packages and hook it into every coding agent
# found on this machine (shadow mode by default).
#
#   gh api repos/ursuciprian/reflex/contents/install.sh -H 'Accept: application/vnd.github.raw' | bash
#   ... | bash -s -- --mode enforce --agents claude,codex --version 0.2.0
#   ... | bash -s -- --uninstall
#
# Options (or the matching environment variables):
#   --version X      package version            REFLEX_VERSION   (default: latest)
#   --agents LIST    claude,codex,pi,omp,...    REFLEX_AGENTS    (default: all agents found)
#   --mode M         shadow | enforce | off     REFLEX_MODE      (default: shadow)
#   --allow A        off | shadow | on          REFLEX_ALLOW     (default: off)
#   --prefix DIR     where the package lives    REFLEX_PREFIX    (default: ~/.local/share/reflex)
#   --keychain NAME  macOS Keychain item with the TypeSafe key   REFLEX_KEYCHAIN_SERVICE (default: typesafe-api-key)
#   --package SPEC   npm spec or local .tgz     REFLEX_PACKAGE   (testing: install from `npm pack`)
#   --uninstall      remove the hooks and the package (logs in ~/.local/state/reflex are kept)
#
# GitHub Packages always needs a token, even to read. The installer uses GITHUB_TOKEN if set,
# otherwise your `gh` login (scope read:packages), through a temporary npmrc that is deleted on
# exit; nothing is written to ~/.npmrc.
set -euo pipefail

SCOPE="@ursuciprian"
NAME="$SCOPE/reflex"
REGISTRY="https://npm.pkg.github.com"
VERSION="${REFLEX_VERSION:-latest}"
AGENTS="${REFLEX_AGENTS:-all}"
MODE="${REFLEX_MODE:-shadow}"
ALLOW="${REFLEX_ALLOW:-off}"
PREFIX="${REFLEX_PREFIX:-$HOME/.local/share/reflex}"
PACKAGE="${REFLEX_PACKAGE:-}"
BIN_DIR="$HOME/.local/bin"
UNINSTALL=0

while [ $# -gt 0 ]; do
  case "$1" in
    --version) VERSION="$2"; shift 2 ;;
    --agents) AGENTS="$2"; shift 2 ;;
    --mode) MODE="$2"; shift 2 ;;
    --allow) ALLOW="$2"; shift 2 ;;
    --prefix) PREFIX="$2"; shift 2 ;;
    --keychain) REFLEX_KEYCHAIN_SERVICE="$2"; shift 2 ;;
    --package) PACKAGE="$2"; shift 2 ;;
    --uninstall) UNINSTALL=1; shift ;;
    -h|--help) sed -n '2,22p' "$0" 2>/dev/null || true; exit 0 ;;
    *) echo "reflex: unknown option $1" >&2; exit 2 ;;
  esac
done

say() { printf '\033[1mreflex\033[0m %s\n' "$*"; }
die() { printf '\033[31mreflex: %s\033[0m\n' "$*" >&2; exit 1; }

command -v node >/dev/null || die "Node.js 18+ is required (https://nodejs.org or: brew install node)"
command -v npm >/dev/null || die "npm is required (it ships with Node.js)"
NODE="$(command -v node)"
major="$("$NODE" -p 'process.versions.node.split(".")[0]')"
[ "$major" -ge 18 ] || die "Node.js 18+ is required, found $("$NODE" --version)"
case "$MODE" in shadow|enforce|off) ;; *) die "--mode must be shadow, enforce or off" ;; esac
case "$ALLOW" in off|shadow|on) ;; *) die "--allow must be off, shadow or on" ;; esac

PKG_DIR="$PREFIX/lib/node_modules/$NAME"

if [ "$UNINSTALL" = 1 ]; then
  if [ -f "$PKG_DIR/install.mjs" ]; then
    "$NODE" "$PKG_DIR/install.mjs" --agent all --uninstall --node "$NODE" || true
  fi
  rm -rf "$PREFIX" && rm -f "$BIN_DIR/reflex" "${XDG_CONFIG_HOME:-$HOME/.config}/reflex/config.json"
  say "removed. Logs are kept in ${REFLEX_DATA_DIR:-$HOME/.local/state/reflex}."
  exit 0
fi

# --- fetch the package -------------------------------------------------------------------------
TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT
if [ -n "$PACKAGE" ]; then
  SPEC="$PACKAGE"
  NPM_ARGS=()
else
  TOKEN="${GITHUB_TOKEN:-}"
  if [ -z "$TOKEN" ] && command -v gh >/dev/null; then
    TOKEN="$(gh auth token 2>/dev/null || true)"
  fi
  [ -n "$TOKEN" ] || die "no GitHub token: run 'gh auth login' (or set GITHUB_TOKEN with read:packages)"
  # The token only ever lives in this temporary npmrc.
  umask 077
  printf '%s:registry=%s\n//npm.pkg.github.com/:_authToken=%s\n' "$SCOPE" "$REGISTRY" "$TOKEN" > "$TMP/npmrc"
  SPEC="$NAME@$VERSION"
  NPM_ARGS=(--userconfig "$TMP/npmrc")
fi

say "installing $SPEC into $PREFIX"
if ! npm install --global --prefix "$PREFIX" --no-audit --no-fund --loglevel=error "${NPM_ARGS[@]}" "$SPEC" 2> "$TMP/npm.err"; then
  if grep -qE 'E401|E403|permission_denied|read:packages' "$TMP/npm.err"; then
    die "GitHub Packages refused the token. Grant it once with:  gh auth refresh -s read:packages   then rerun."
  fi
  cat "$TMP/npm.err" >&2
  die "npm install failed"
fi
[ -f "$PKG_DIR/install.mjs" ] || die "package installed but $PKG_DIR/install.mjs is missing"

mkdir -p "$BIN_DIR"
ln -sf "$PKG_DIR/bin/reflex" "$BIN_DIR/reflex"

# --- API key -----------------------------------------------------------------------------------
KEYCHAIN="${REFLEX_KEYCHAIN_SERVICE:-typesafe-api-key}"
if [ -z "${TYPESAFE_API_KEY:-}" ]; then
  if [ "$(uname)" = Darwin ] && ! security find-generic-password -s "$KEYCHAIN" >/dev/null 2>&1; then
    if [ -r /dev/tty ]; then
      say "no TypeSafe API key found. Create one at https://console.typesafe.ai/keys and paste it"
      say "(stored in the macOS Keychain as '$KEYCHAIN'; press Enter to skip):"
      IFS= read -rs key < /dev/tty || key=""
      echo
      if [ -n "$key" ]; then
        security add-generic-password -U -s "$KEYCHAIN" -a "$USER" -w "$key" && say "key stored in the Keychain"
      fi
      unset key
    fi
  fi
fi

# --- hook into the agents ----------------------------------------------------------------------
# The Keychain item name is recorded in ~/.config/reflex/config.json, so every hook finds the key
# whichever agent starts it.
"$NODE" "$PKG_DIR/install.mjs" --agent "$AGENTS" --mode "$MODE" --allow "$ALLOW" --node "$NODE" --keychain "$KEYCHAIN"

version="$("$NODE" -p "require('$PKG_DIR/package.json').version")"
say "Reflex $version installed ($MODE mode, allow $ALLOW)."
case ":$PATH:" in *":$BIN_DIR:"*) ;; *) say "add $BIN_DIR to PATH to use the 'reflex' command" ;; esac
cat <<EOF

Next:
  - restart your agent sessions
  - Codex: open Codex and trust the Reflex hooks in /hooks
  - Hermes: paste the printed block into each profile's config.yaml
  - check:   reflex check "git push --force origin main"
  - later:   reflex report      (then rerun this installer with --mode enforce)
EOF
