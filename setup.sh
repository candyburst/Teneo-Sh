#!/usr/bin/env bash
# ================================================================
#  Teneo Protocol Beacon — Hardened Multi-Account Manager
#  Source: github.com/TeneoProtocolAI/teneo-node-app-release-beta
#
#  Requirements: Ubuntu 20.04+, amd64 or arm64, bash 4+, sudo
#
#  Install:
#   chmod +x teneo-beacon-setup.sh
#   sudo ./teneo-beacon-setup.sh quicksetup
#
#  13 hardening layers applied by install/harden:
#   [1]  UFW              — deny-all + rate-limited SSH (6 conn/30s)
#   [2]  fail2ban         — SSH jail (2h) + recidive 1-week re-ban
#   [3]  SSH              — strong ciphers/MACs/KEX, no forwarding
#   [4]  Login banner     — legal warning on /etc/issue.net
#   [5]  Unused services  — avahi, cups, bluetooth, ModemManager off
#   [6]  Kernel sysctl    — ASLR, kptr_restrict, eBPF lockdown, TCP
#   [7]  Core dumps       — disabled via PAM limits + systemd
#   [8]  /tmp             — remounted nosuid, nodev, noexec
#   [9]  AppArmor         — enforce profile for teneo-beacon binary
#   [10] DNS-over-TLS     — Cloudflare primary, Google fallback, DNSSEC
#   [11] Auto-updates     — unattended-upgrades for security patches
#   [12] auditd           — syscall rules: identity/sudo/SSH/kernel/time
#   [13] Credential store — 700 dirs, 600 secrets, correct ownership
#
#  Commands:
#   sudo ./teneo-beacon-setup.sh quicksetup    — full install + wizard
#   sudo ./teneo-beacon-setup.sh install       — install binary + harden
#   sudo ./teneo-beacon-setup.sh add           — add isolated account
#   sudo ./teneo-beacon-setup.sh remove <n>    — remove an account
#        ./teneo-beacon-setup.sh list          — status of all accounts
#        ./teneo-beacon-setup.sh logs <n>      — live logs for account
#        ./teneo-beacon-setup.sh status <n>    — detailed systemd status
#   sudo ./teneo-beacon-setup.sh update        — upgrade binary + restart
#   sudo ./teneo-beacon-setup.sh harden        — re-apply hardening only
#        ./teneo-beacon-setup.sh --version     — print version
#        ./teneo-beacon-setup.sh --help        — print this usage
# ================================================================

# Guard: if invoked as 'sh teneo.sh' or 'sudo sh teneo.sh' instead of bash,
# re-exec under bash transparently. Must be POSIX sh-compatible (no [[, no (())).
if [ -z "${BASH_VERSION:-}" ]; then
  exec bash "$0" "$@" || { echo "ERROR: bash not found — install it with: sudo apt-get install bash" >&2; exit 1; }
fi

# -E: inherit ERR traps into functions and subshells
set -Eeuo pipefail
IFS=$'\n\t'

SCRIPT_VERSION="1.0.0"

# Normalise $0 so usage always shows an invocable path.
# 'sudo 5.sh' looks like a command name with no path — sudo won't find it.
# Rewrite to './5.sh' so the printed examples actually work.
[[ "$0" == */* ]] || exec bash "./$0" "$@"

# Require bash 4+ for associative arrays, [[ ]], and other features used here.
if (( BASH_VERSINFO[0] < 4 )); then
  echo "ERROR: bash 4.0+ required (running ${BASH_VERSION})." >&2
  exit 1
fi

# ── Colours ──────────────────────────────────────────────────────
# Honour https://no-color.org and degrade gracefully in pipes/CI/log files.
if [[ -t 1 && -z "${NO_COLOR:-}" ]]; then
  RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'
  CYAN='\033[0;36m'; BOLD='\033[1m';    RESET='\033[0m'
  MAGENTA='\033[1;35m'; DIM='\033[2m'
else
  RED=''; GREEN=''; YELLOW=''
  CYAN=''; BOLD='';  RESET=''
  MAGENTA=''; DIM=''
fi

# ── Globals ───────────────────────────────────────────────────────
GITHUB_REPO="TeneoProtocolAI/teneo-node-app-release-beta"
GITHUB_API="https://api.github.com/repos/${GITHUB_REPO}/releases/latest"

# When invoked as `sudo ./teneo.sh`, $USER and $HOME resolve to root.
# Use $SUDO_USER (set by sudo) to recover the real invoking user so that
# account data, service User=, and Environment=HOME= are all correct.
REAL_USER="${SUDO_USER:-$USER}"
REAL_HOME=$(getent passwd "$REAL_USER" 2>/dev/null | cut -d: -f6)
[[ -n "$REAL_HOME" ]] || REAL_HOME="$HOME"

ACCOUNTS_ROOT="$REAL_HOME/.teneo/accounts"
META_DIR="$REAL_HOME/.teneo/meta"
CONF_FILE="$REAL_HOME/.teneo/teneo.conf"
VERSION_FILE="$META_DIR/installed_version"
PREV_VERSION_FILE="$META_DIR/previous_version"
DISPLAY_BASE=100
OS_VER=""             # set by detect_ubuntu()
APP_BINARY=""
ARCH_PAT=""           # set by detect_arch()
DEB_CACHE=""          # set by _setup_tmpfiles()
LOCKFILE="/tmp/teneo-setup-${EUID}.lock"
SUDO=""               # set by require_sudo(); pre-initialized to satisfy set -u
_LOCK_HELD=false      # guard against double _acquire_lock calls
_SUDO_KEEPALIVE_PID="" # tracked so _cleanup can kill it

# ── Runtime flags — set via CLI args before dispatch ─────────────
DRY_RUN=false         # --dry-run   : print actions, don't execute
QUIET=false           # --quiet/-q  : suppress info/success output
VERBOSE=false         # --verbose/-v: extra detail
FORCE=false           # --force     : skip y/N confirmations
JSON_OUT=false        # --json      : machine-readable output
TIMESTAMPS=false      # --timestamps: prefix log lines with HH:MM:SS
DEBUG_MODE=false      # --debug     : enable set -x tracing
WATCH_INTERVAL=5      # seconds between watch refreshes

# ── Config defaults — overridden by CONF_FILE if present ─────────
WEBHOOK_URL=""        # POST crash/health alerts here
ALERT_EMAIL=""        # mail alerts here (requires sendmail/msmtp)
AUTO_BACKUP=false     # backup before every update
STAGED_UPDATE=false   # confirm before restarting each account
DEFAULT_PROXY=""      # pre-fill proxy prompt if set

# ── Temp-file registry — always cleaned up ────────────────────────
declare -a _TMP_FILES=()
_cleanup() {
  exec 9>&- 2>/dev/null || true   # release lock fd
  [[ -n "$_SUDO_KEEPALIVE_PID" ]] && kill "$_SUDO_KEEPALIVE_PID" 2>/dev/null || true
  # Use rm -rf so temp *directories* (added by cmd_backup/cmd_restore) are
  # removed too — rm -f silently fails on directories and leaks them.
  local _f; for _f in "${_TMP_FILES[@]+"${_TMP_FILES[@]}"}"; do
    rm -rf "$_f" 2>/dev/null || true
  done
}
trap _cleanup EXIT

# Clean abort on Ctrl-C / SIGTERM
_abort_int()  { echo -e "\n${YELLOW}[ABORTED]${RESET} Interrupted — partial changes may remain." >&2; exit 130; }
_abort_term() { echo -e "\n${YELLOW}[ABORTED]${RESET} Terminated — partial changes may remain."  >&2; exit 143; }
trap _abort_int  SIGINT
trap _abort_term SIGTERM

_setup_tmpfiles() {
  DEB_CACHE=$(mktemp /tmp/teneo-beacon-XXXXXX.deb)
  _TMP_FILES+=("$DEB_CACHE" "/tmp/teneo-dpkg-$$.err")
}

# Prevent concurrent script runs via flock
_acquire_lock() {
  [[ "$_LOCK_HELD" == true ]] && return 0   # already locked by this process
  exec 9>"$LOCKFILE"
  flock -n 9 || die "Another instance of $(basename "$0") is running. (lock: $LOCKFILE)"
  _LOCK_HELD=true
  _TMP_FILES+=("$LOCKFILE")
}

# ── Helpers ───────────────────────────────────────────────────────
_ts()     { [[ "$TIMESTAMPS" == true ]] && echo -n "$(date '+%H:%M:%S') " || true; }
info()    { [[ "$QUIET"   == true ]] && return 0; echo -e "$(_ts)${CYAN}[INFO]${RESET}  $*"; }
success() { [[ "$QUIET"   == true ]] && return 0; echo -e "$(_ts)${GREEN}[OK]${RESET}    $*"; }
warn()    { echo -e "$(_ts)${YELLOW}[WARN]${RESET}  $*"; }
die()     { echo -e "$(_ts)${RED}[ERROR]${RESET} $*" >&2; exit 1; }
verbose() { [[ "$VERBOSE" == true ]] && echo -e "$(_ts)${CYAN}[DBG]${RESET}   $*" || true; }
hr()      { echo -e "${CYAN}$(printf '━%.0s' {1..60})${RESET}"; }
section() { echo ""; hr; echo -e "${BOLD}  $*${RESET}"; hr; echo ""; }

# Load user config — simple KEY=VALUE, lines starting with # are comments
_load_config() {
  [[ -f "$CONF_FILE" ]] || return 0
  local line key val
  while IFS= read -r line; do
    [[ "$line" =~ ^[[:space:]]*# ]] && continue
    [[ "$line" =~ ^[[:space:]]*$ ]] && continue
    key="${line%%=*}"; val="${line#*=}"
    case "$key" in
      WEBHOOK_URL)    WEBHOOK_URL="$val" ;;
      ALERT_EMAIL)    ALERT_EMAIL="$val" ;;
      AUTO_BACKUP)    AUTO_BACKUP="$val" ;;
      STAGED_UPDATE)  STAGED_UPDATE="$val" ;;
      DEFAULT_PROXY)  DEFAULT_PROXY="$val" ;;
      TIMESTAMPS)     TIMESTAMPS="$val" ;;
      WATCH_INTERVAL) WATCH_INTERVAL="$val" ;;
    esac
  done < "$CONF_FILE"
}
_load_config

# Parse leading global flags before the command word.
# Usage: teneo.sh [flags] <command> [args]
_parse_flags() {
  local -a remaining=()
  while [[ $# -gt 0 ]]; do
    case "$1" in
      --dry-run)       DRY_RUN=true ;;
      --quiet|-q)      QUIET=true ;;
      --verbose|-v)    VERBOSE=true ;;
      --force)         FORCE=true ;;
      --json)          JSON_OUT=true ;;
      --timestamps)    TIMESTAMPS=true ;;
      --debug)         DEBUG_MODE=true; set -x ;;
      --no-color)      RED=''; GREEN=''; YELLOW=''; CYAN=''; BOLD=''; RESET=''; MAGENTA=''; DIM='' ;;
      --watch-interval=*) WATCH_INTERVAL="${1#*=}" ;;
      *)               remaining+=("$1") ;;
    esac
    shift
  done
  # Export remaining args back to positional parameters
  set -- "${remaining[@]+"${remaining[@]}"}"
  CMD="${1:-}"
  ARG2="${2:-}"
  ARG3="${3:-}"
}

# Dry-run-aware command executor
_exec() {
  if [[ "$DRY_RUN" == true ]]; then
    local _s; printf -v _s '%s ' "$@"
    echo -e "  ${YELLOW}[DRY-RUN]${RESET} ${_s% }"
  else
    "$@"
  fi
}

# Prompt for y/N; returns 0 for yes, 1 for no.
# With --force, always returns 0 (yes).
_confirm() {
  local prompt="${1:-Continue?}"
  if [[ "$FORCE" == true ]]; then
    verbose "Auto-confirming (--force): ${prompt}"
    return 0
  fi
  local C=""
  read -rp "  ${prompt} (y/N): " C
  [[ "$C" =~ ^[Yy]$ ]]
}

# Validate an account name exists on disk
_require_account() {
  local NAME="$1"
  [[ -n "$NAME" ]] || die "Account name required. Run: $0 list"
  [[ "$NAME" =~ ^[a-zA-Z0-9_-]+$ ]] || die "Invalid account name '${NAME}'."
  [[ -d "$ACCOUNTS_ROOT/$NAME" ]] || die "Account '${NAME}' not found. Run: $0 list"
}

# Pretty-print elapsed seconds as Xd Xh Xm Xs
_fmt_elapsed() {
  local s=${1:-0}
  local d=$(( s/86400 )) h=$(( (s%86400)/3600 )) m=$(( (s%3600)/60 )) r=$(( s%60 ))
  local out=""
  (( d > 0 )) && out+="${d}d "
  (( h > 0 )) && out+="${h}h "
  (( m > 0 )) && out+="${m}m "
  out+="${r}s"
  echo "$out"
}

# Format bytes to human-readable
_fmt_bytes() {
  local b=${1:-0}
  if   (( b >= 1073741824 )); then awk -v b="$b" 'BEGIN{printf "%.1fG", b/1073741824}'
  elif (( b >= 1048576    )); then awk -v b="$b" 'BEGIN{printf "%.1fM", b/1048576}'
  elif (( b >= 1024       )); then awk -v b="$b" 'BEGIN{printf "%.1fK", b/1024}'
  else echo "${b}B"; fi
}

# Send a webhook notification (non-fatal on failure)
_send_webhook() {
  local msg="$1"
  [[ -z "$WEBHOOK_URL" ]] && return 0
  local host; host=$(hostname -f 2>/dev/null || hostname)
  local payload
  if command -v jq &>/dev/null; then
    payload=$(jq -cn --arg text "[Teneo ${host}] ${msg}" '{"text":$text}')
  else
    # Escape \ and " so the JSON is never malformed by hostile input
    local safe_host safe_msg
    safe_host=$(printf '%s' "$host" | sed 's/\\/\\\\/g; s/"/\\"/g')
    safe_msg=$(printf  '%s' "$msg"  | sed 's/\\/\\\\/g; s/"/\\"/g')
    payload=$(printf '{"text":"[Teneo %s] %s"}' "$safe_host" "$safe_msg")
  fi
  curl -fsSL -X POST -H "Content-Type: application/json" \
    -d "$payload" "$WEBHOOK_URL" &>/dev/null || true
}

# Send email alert (non-fatal on failure)
_send_email() {
  local subject="$1" body="$2"
  [[ -z "$ALERT_EMAIL" ]] && return 0
  { echo "Subject: ${subject}"; echo ""; echo "$body"; } \
    | sendmail "$ALERT_EMAIL" 2>/dev/null \
    || mail -s "$subject" "$ALERT_EMAIL" <<< "$body" 2>/dev/null \
    || true
}

# Spinner for long-running silent operations
_spinner() {
  local pid=$1 msg="${2:-Working…}"
  local frames=('⠋' '⠙' '⠹' '⠸' '⠼' '⠴' '⠦' '⠧' '⠇' '⠏')
  local i=0
  [[ "$QUIET" == true || "$JSON_OUT" == true ]] && { wait "$pid" 2>/dev/null; return $?; }
  while kill -0 "$pid" 2>/dev/null; do
    printf "\r  %s %s" "${frames[$(( i % ${#frames[@]} ))]}" "$msg"
    i=$(( i+1 )); sleep 0.1
  done
  printf "\r%60s\r" ""   # clear line — intentionally before wait; exit code captured below
  local _rc
  wait "$pid" 2>/dev/null; _rc=$?
  return $_rc
}

require_sudo() {
  if [[ $EUID -eq 0 ]]; then
    SUDO=""
    return
  fi
  SUDO="sudo"
  # Guard: don't spawn a second keepalive if already authenticated
  # (cmd_quicksetup → cmd_install → cmd_harden all call require_sudo)
  [[ -n "$_SUDO_KEEPALIVE_PID" ]] && return 0
  sudo -v || die "sudo privileges required."
  # Keep sudo timestamp alive during long operations
  ( while true; do sleep 240; sudo -v 2>/dev/null; done ) &
  _SUDO_KEEPALIVE_PID=$!
}

# Run a command with sudo when required, or directly when already root.
# Avoids the leading-space / empty-word issue of expanding $SUDO inline.
run_sudo() { if [[ -n "$SUDO" ]]; then sudo "$@"; else "$@"; fi; }

detect_ubuntu() {
  [[ -f /etc/os-release ]] || die "Cannot detect OS (/etc/os-release missing)."
  # Source in a subshell to avoid polluting the global namespace with NAME,
  # VERSION_CODENAME, ID_LIKE, etc. defined by the os-release file.
  local _ID _VER
  _ID=$(  . /etc/os-release 2>/dev/null; echo "${ID:-}"         )
  _VER=$( . /etc/os-release 2>/dev/null; echo "${VERSION_ID:-0}" )
  [[ "$_ID" == "ubuntu" ]] || die "Ubuntu required. Detected: ${_ID:-unknown}"
  OS_VER="$_VER"
  dpkg --compare-versions "$OS_VER" ge "20.04" 2>/dev/null \
    || die "Ubuntu 20.04+ required. Got: ${OS_VER}"
}

detect_arch() {
  local ARCH; ARCH=$(dpkg --print-architecture 2>/dev/null || uname -m)
  case "$ARCH" in
    amd64|x86_64)  ARCH_PAT='amd64\.deb$' ;;
    arm64|aarch64) ARCH_PAT='arm64\.deb$' ;;
    *) die "Unsupported architecture: ${ARCH}. Only amd64 and arm64 are supported." ;;
  esac
}

require_jq() {
  command -v jq &>/dev/null || die "'jq' not found. Run: sudo apt-get install jq"
}

check_network() {
  info "Checking network connectivity…"
  # Use plain curl (no retry) — this is a fast ping, not a download.
  # _curl's 3 retries × 3s delay means a bad network waits 9+ seconds before dying.
  curl -fsSL --max-time 8 "https://api.github.com" -o /dev/null 2>/dev/null \
    || die "Cannot reach api.github.com. Check DNS, firewall, or proxy settings."
}

check_disk_space() {
  local TMP_MB USR_MB
  TMP_MB=$(df /tmp --output=avail -m 2>/dev/null | tail -1 | tr -d ' ')
  USR_MB=$(df /usr  --output=avail -m 2>/dev/null | tail -1 | tr -d ' ')
  [[ "${TMP_MB:-0}" -ge 300  ]] || die "Low space in /tmp (need ≥300 MB, have ${TMP_MB:-?} MB)"
  [[ "${USR_MB:-0}" -ge 1500 ]] || die "Low space in /usr (need ≥1500 MB, have ${USR_MB:-?} MB — webkit + icon themes + audio libs need ~1 GB)"
}

resolve_binary() {
  APP_BINARY=$(command -v teneo-beacon 2>/dev/null \
    || find /usr /opt -name "teneo-beacon" -type f 2>/dev/null | head -1 \
    || true)
  [[ -n "$APP_BINARY" ]] || die "teneo-beacon binary not found. Run: sudo $0 install"
}

# Atomic write — prevents half-written files surviving a crash.
# The temp file is created mode 600 immediately so sensitive content
# (e.g. proxy credentials in meta.env) is never world-readable even
# during the brief window before the caller applies its own chmod.
_write_atomic() {
  local DEST="$1"; shift
  local TMP; TMP=$(mktemp "${DEST}.XXXXXX")
  chmod 600 "$TMP"
  _TMP_FILES+=("$TMP")
  if [[ $# -gt 0 ]]; then printf '%s\n' "$*" > "$TMP"
  else cat > "$TMP"; fi
  mv "$TMP" "$DEST"
}

# Safely set KEY=VALUE in a KEY=VALUE file — immune to special chars in the value.
# Removes any existing line for the key, appends the new one.
# Uses grep+printf rather than sed to avoid injection via '&', '\', '|' in values.
_kv_set() {
  local file="$1" key="$2" val="$3"
  local perm; perm=$(stat -c %a "$file" 2>/dev/null || echo "600")
  local tmp; tmp=$(mktemp "${file}.XXXXXX")
  chmod "$perm" "$tmp"
  grep -v "^${key}=" "$file" > "$tmp" 2>/dev/null || true
  printf '%s=%s\n' "$key" "$val" >> "$tmp"
  mv "$tmp" "$file"
}

# Back up a file or directory before overwriting it
_backup() {
  local FILE="$1"
  local BAK="${FILE}.teneo-bak.$(date +%Y%m%d-%H%M%S)"
  if [[ -f "$FILE" ]]; then
    run_sudo cp -p "$FILE" "$BAK" 2>/dev/null && info "Backed up: $(basename "$FILE") → $(basename "$BAK")" || true
  elif [[ -d "$FILE" ]]; then
    run_sudo cp -rp "$FILE" "$BAK" 2>/dev/null && info "Backed up: $(basename "$FILE") → $(basename "$BAK")" || true
  fi
}

# curl with automatic retry
_curl() { curl --retry 3 --retry-delay 3 --retry-connrefused "$@"; }

# Poll until a systemd service reaches 'active'
_wait_for_service() {
  local SVC="$1" TIMEOUT="${2:-30}" i
  info "Waiting for ${SVC}…"
  for (( i=0; i<TIMEOUT; i++ )); do
    systemctl is-active --quiet "$SVC" 2>/dev/null && return 0
    sleep 1
  done
  warn "${SVC} did not become active within ${TIMEOUT}s"
  warn "  Check: journalctl -u ${SVC} -n 30 --no-pager"
  return 1
}

validate_proxy_url() {
  local URL="$1"
  [[ "$URL" =~ ^(http|https|socks5)://[^[:space:]]+$ ]] || {
    local REDACTED; REDACTED=$(echo "$URL" | sed 's|://[^:@]*:[^@]*@|://***@|')
    die "Invalid proxy URL '${REDACTED}'. Expected: http[s]://host:port or socks5://user:pass@host:port"
  }
}

check_proxy_unique() {
  local NEW="$1" SKIP="${2:-}"   # SKIP: account name to exclude from check (set-proxy self)
  [[ -z "$NEW" ]] && return 0
  local M EXISTING OWNER REDACTED
  for M in "$ACCOUNTS_ROOT"/*/meta.env; do
    [[ -f "$M" ]] || continue
    OWNER=$(basename "$(dirname "$M")")
    # Don't warn when an account is being updated to/from its own proxy.
    [[ -n "$SKIP" && "$OWNER" == "$SKIP" ]] && continue
    EXISTING=$(grep "^PROXY_URL=" "$M" 2>/dev/null | cut -d= -f2-)
    if [[ "$EXISTING" == "$NEW" ]]; then
      REDACTED=$(echo "$NEW" | sed 's|://[^:@]*:[^@]*@|://***@|')
      warn "Proxy '${REDACTED}' already used by account '${OWNER}'."
      warn "Teneo may block accounts sharing the same outbound IP."
      _confirm "Continue anyway?" || { info "Aborted."; exit 0; }
      return 0
    fi
  done
}

download_and_verify_deb() {
  local DEB_URL="$1" DEB_NAME="$2" API="$3"
  info "Downloading ${DEB_NAME}…"
  _curl -fL --progress-bar -o "$DEB_CACHE" "$DEB_URL"

  local SUM_URL
  SUM_URL=$(echo "$API" | jq -r \
    '.assets[] | select(.name | test("sha256|checksum|SHA256";"i")) | .browser_download_url' \
    2>/dev/null | head -1 || true)

  if [[ -n "$SUM_URL" ]]; then
    info "Verifying SHA256 checksum…"
    local SUM_FILE; SUM_FILE=$(mktemp /tmp/teneo-sums-XXXXXX.txt)
    _TMP_FILES+=("$SUM_FILE")
    _curl -fsSL -o "$SUM_FILE" "$SUM_URL"
    local EXPECTED; EXPECTED=$(awk -v name="$DEB_NAME" '$2==name{print $1;exit}' "$SUM_FILE")
    if [[ -n "$EXPECTED" ]]; then
      local ACTUAL; ACTUAL=$(sha256sum "$DEB_CACHE" | awk '{print $1}')
      [[ "$ACTUAL" == "$EXPECTED" ]] && success "SHA256 verified ✓" \
        || die "Checksum MISMATCH — may be corrupted or tampered.\n  Expected: ${EXPECTED}\n  Got:      ${ACTUAL}"
    else
      warn "No checksum row for '${DEB_NAME}' — skipping verification"
    fi
  else
    warn "No checksum asset in release — skipping verification"
  fi
}

banner() {
  local M="${MAGENTA}" C="${CYAN}" Y="${YELLOW}" B="${BOLD}" D="${DIM}" R="${RESET}"
  echo ""
  echo -e "${M}  ◈◇◈◇◈◇◈◇◈◇◈◇◈◇◈◇◈◇◈◇◈◇◈◇◈◇◈◇◈◇◈◇◈◇◈◇◈◇◈◇◈◇◈◇◈◇◈◇◈${R}"
  echo ""
  echo -e "${M}   ██████╗ █████╗ ███╗  ██╗██████╗ ██╗   ██╗${R}"
  echo -e "${M}  ██╔════╝██╔══██╗████╗ ██║██╔══██╗╚██╗ ██╔╝${R}"
  echo -e "${M}  ██║     ███████║██╔██╗██║██║  ██║ ╚████╔╝ ${R}"
  echo -e "${M}  ██║     ██╔══██║██║╚████║██║  ██║  ╚██╔╝  ${R}"
  echo -e "${M}  ╚██████╗██║  ██║██║ ╚███║██████╔╝   ██║   ${R}"
  echo -e "${M}   ╚═════╝╚═╝  ╚═╝╚═╝  ╚══╝╚═════╝   ╚═╝   ${R}"
  echo ""
  echo -e "${C}  ██████╗ ██╗   ██╗██████╗ ███████╗████████╗${R}"
  echo -e "${C}  ██╔══██╗██║   ██║██╔══██╗██╔════╝╚══██╔══╝${R}"
  echo -e "${C}  ██████╔╝██║   ██║██████╔╝███████╗   ██║   ${R}"
  echo -e "${C}  ██╔══██╗██║   ██║██╔══██╗╚════██║   ██║   ${R}"
  echo -e "${C}  ██████╔╝╚██████╔╝██║  ██║███████║   ██║   ${R}"
  echo -e "${C}  ╚═════╝  ╚═════╝ ╚═╝  ╚═╝╚══════╝   ╚═╝  ${R}"
  echo ""
  echo -e "${M}  ◈◇◈◇◈◇◈◇◈◇◈◇◈◇◈◇◈◇◈◇◈◇◈◇◈◇◈◇◈◇◈◇◈◇◈◇◈◇◈◇◈◇◈◇◈◇◈◇◈${R}"
  echo -e "  ${B}Hardened Multi-Account Node Manager${R}  ${D}@cryptoasuran${R}  ${C}v${SCRIPT_VERSION}${R}"
  echo ""
}

# ================================================================
#  SHARED: Build hardened systemd units (used by add + quicksetup)
#  Caller must set: ACCT_NAME, DISPLAY_ID, ACCT_DIR, JITTER,
#                   PROXY_BLOCK, APP_BINARY, REAL_USER, REAL_HOME
# ================================================================
_write_service_units() {
  [[ -n "$APP_BINARY" ]] || die "_write_service_units: APP_BINARY is empty — run resolve_binary first."
  # ── Xvfb unit ────────────────────────────────────────────────
  run_sudo tee "/etc/systemd/system/teneo-xvfb@${ACCT_NAME}.service" > /dev/null << XVFB
[Unit]
Description=Teneo Xvfb virtual display ${DISPLAY_ID} [${ACCT_NAME}]
After=network.target
StopWhenUnneeded=true

[Service]
Type=simple
ExecStart=/usr/bin/Xvfb ${DISPLAY_ID} -screen 0 1280x800x24 -ac +extension GLX +render -noreset
Restart=on-failure
RestartSec=5
TimeoutStartSec=30
TimeoutStopSec=15
KillMode=control-group
KillSignal=SIGTERM

NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=strict
ProtectHome=read-only
ReadWritePaths=/tmp
PrivateDevices=true
PrivateIPC=true
ProtectHostname=true
ProtectKernelTunables=true
ProtectKernelModules=true
ProtectKernelLogs=true
ProtectControlGroups=true
ProtectClock=true
ProtectProc=invisible
ProcSubset=pid
RestrictRealtime=true
RestrictSUIDSGID=true
RestrictNamespaces=true
LockPersonality=true
MemoryDenyWriteExecute=false
SystemCallArchitectures=native
RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6
CapabilityBoundingSet=
AmbientCapabilities=

MemoryMax=512M
CPUQuota=50%
TasksMax=64

StandardOutput=journal
StandardError=journal
SyslogIdentifier=teneo-xvfb-${ACCT_NAME}

[Install]
WantedBy=multi-user.target
XVFB

  # ── Beacon unit ───────────────────────────────────────────────
  run_sudo tee "/etc/systemd/system/teneo-beacon@${ACCT_NAME}.service" > /dev/null << BEACON
[Unit]
Description=Teneo Beacon — ${ACCT_NAME}
After=network-online.target teneo-xvfb@${ACCT_NAME}.service
Wants=network-online.target
Requires=teneo-xvfb@${ACCT_NAME}.service
StartLimitIntervalSec=180
StartLimitBurst=5

[Service]
Type=simple
User=${REAL_USER}

ExecStartPre=/bin/sleep ${JITTER}

Environment=DISPLAY=${DISPLAY_ID}
Environment=HOME=${REAL_HOME}
Environment=XDG_CONFIG_HOME=${ACCT_DIR}/config
Environment=XDG_DATA_HOME=${ACCT_DIR}/data
Environment=XDG_CACHE_HOME=${ACCT_DIR}/cache
Environment=XDG_RUNTIME_DIR=${ACCT_DIR}/run

${PROXY_BLOCK}

ExecStart=${APP_BINARY}
Restart=on-failure
RestartSec=20
TimeoutStartSec=120
TimeoutStopSec=30
KillMode=control-group
KillSignal=SIGTERM

NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=strict
ReadWritePaths=${ACCT_DIR} /tmp
ProtectHome=read-only
PrivateDevices=true
PrivateIPC=true
ProtectHostname=true
ProtectKernelTunables=true
ProtectKernelModules=true
ProtectKernelLogs=true
ProtectControlGroups=true
ProtectClock=true
ProtectProc=invisible
ProcSubset=pid
RestrictRealtime=true
RestrictSUIDSGID=true
LockPersonality=true
RestrictNamespaces=true
SystemCallArchitectures=native
SystemCallFilter=@system-service
MemoryDenyWriteExecute=false
RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6
CapabilityBoundingSet=
AmbientCapabilities=
SecureBits=noroot noroot-locked

MemoryMax=1G
CPUQuota=80%
TasksMax=128
LimitNOFILE=65536
LimitCORE=0

StandardOutput=append:${ACCT_DIR}/logs/beacon.log
StandardError=append:${ACCT_DIR}/logs/beacon.log
SyslogIdentifier=teneo-beacon-${ACCT_NAME}

[Install]
WantedBy=multi-user.target
BEACON

  # ── Log rotation ─────────────────────────────────────────────
  # logrotate's 'su' directive takes USER GROUP — must use the real primary
  # group name, not the username, or rotation fails when they differ.
  # NOTE: copytruncate copies then truncates the live file, so lines written
  # in the brief window between copy and truncate can be lost.  This is
  # acceptable here because the beacon binary holds the file open and does
  # not support SIGHUP-based log reopening; a create+postrotate restart would
  # cause a service interruption.  Improve this if the binary ever gains
  # proper log-reopen support.
  local REAL_GROUP; REAL_GROUP=$(id -gn "$REAL_USER" 2>/dev/null || echo "$REAL_USER")
  run_sudo tee "/etc/logrotate.d/teneo-beacon-${ACCT_NAME}" > /dev/null << LOGROTATE
${ACCT_DIR}/logs/beacon.log {
    daily
    rotate 7
    compress
    delaycompress
    missingok
    notifempty
    copytruncate
    su ${REAL_USER} ${REAL_GROUP}
}
LOGROTATE
}

# ================================================================
#  SYSTEM HARDENING
# ================================================================
cmd_harden() {
  require_sudo
  detect_ubuntu
  _acquire_lock
  if [[ "$DRY_RUN" == true ]]; then
    info "[DRY-RUN] harden: would apply 13 layers — UFW, fail2ban, SSH hardening, login banner, disable unused services, kernel sysctl, core dumps off, /tmp noexec, AppArmor, DNS-over-TLS, auto-updates, auditd, credential permissions"
    return 0
  fi
  section "System Hardening"

  # ── [1] UFW — rate-limited SSH ───────────────────────────────
  if ! command -v ufw &>/dev/null; then
    run_sudo apt-get install -y -qq ufw
  fi
  info "Configuring UFW firewall…"
  # Preserve any pre-existing rules before reset — user may have custom port allows
  local UFW_BAK="/etc/ufw/teneo-rules-bak.$(date +%Y%m%d-%H%M%S).txt"
  if run_sudo ufw status numbered 2>/dev/null | grep -q "^\["; then
    warn "Existing UFW rules will be replaced. Saving backup to ${UFW_BAK}"
    run_sudo ufw status verbose 2>/dev/null | run_sudo tee "$UFW_BAK" > /dev/null || true
  fi
  run_sudo ufw --force reset        > /dev/null
  run_sudo ufw default deny incoming  > /dev/null
  run_sudo ufw default deny forward   > /dev/null
  run_sudo ufw default allow outgoing > /dev/null
  # 'limit' = max 6 connections per 30s per source IP, then temp-ban
  run_sudo ufw limit ssh              > /dev/null
  run_sudo ufw --force enable         > /dev/null
  success "UFW: deny all + rate-limited SSH (6 conn/30s)"

  # ── [2] fail2ban — SSH + recidive permanent re-ban ───────────
  if ! dpkg -s fail2ban &>/dev/null; then
    run_sudo apt-get install -y -qq fail2ban
  fi
  _backup /etc/fail2ban/jail.local
  run_sudo tee /etc/fail2ban/jail.local > /dev/null << 'JAIL'
[DEFAULT]
bantime        = 2h
findtime       = 10m
maxretry       = 3
ignoreip       = 127.0.0.1/8 ::1
banaction      = iptables-multiport
banaction_allports = iptables-allports

[sshd]
enabled  = true
port     = ssh
logpath  = %(sshd_log)s
backend  = %(syslog_backend)s
maxretry = 3

# Permanent 1-week ban for IPs that get banned 3+ times
[recidive]
enabled   = true
logpath   = /var/log/fail2ban.log
banaction = %(banaction_allports)s
bantime   = 1w
findtime  = 1d
maxretry  = 3
JAIL
  run_sudo systemctl enable fail2ban --quiet 2>/dev/null || true
  run_sudo systemctl restart fail2ban 2>/dev/null \
    && success "fail2ban: SSH jail (2h) + recidive (1-week permanent ban)" \
    || warn "fail2ban restart failed — check: sudo systemctl status fail2ban"

  # ── [3] SSH — strong crypto + no forwarding ──────────────────
  local SSHD_CONF=/etc/ssh/sshd_config.d/99-teneo-harden.conf

  # Safety check: don't lock out by disabling password auth if no key exists
  local DISABLE_PASS_AUTH=true
  local AUTH_KEYS="$REAL_HOME/.ssh/authorized_keys"
  if [[ ! -f "$AUTH_KEYS" ]] || [[ ! -s "$AUTH_KEYS" ]]; then
    warn "No authorized_keys at ${AUTH_KEYS} — skipping PasswordAuthentication=no"
    warn "  Authorize your key first:  ssh-copy-id user@$(hostname)"
    warn "  Then re-run:               sudo $0 harden"
    DISABLE_PASS_AUTH=false
  fi

  _backup "$SSHD_CONF"
  {
    cat << 'SSH_STATIC'
# ── Teneo SSH Hardening ───────────────────────────────────────
Protocol 2
PermitRootLogin no
PermitEmptyPasswords no
# ChallengeResponseAuthentication was renamed in OpenSSH 9 (Ubuntu 24.04+)
ChallengeResponseAuthentication no
KbdInteractiveAuthentication no
KerberosAuthentication no
GSSAPIAuthentication no
UsePAM yes
PrintMotd no
PrintLastLog yes
LoginGraceTime 30
MaxAuthTries 3
MaxSessions 5
MaxStartups 5:50:10
ClientAliveInterval 300
ClientAliveCountMax 2
LogLevel VERBOSE
Banner /etc/issue.net

# Disable all forwarding — prevents use as a pivot tunnel
X11Forwarding no
AllowAgentForwarding no
AllowTcpForwarding no
PermitTunnel no
GatewayPorts no

# Strong ciphers only
Ciphers chacha20-poly1305@openssh.com,aes256-gcm@openssh.com,aes128-gcm@openssh.com,aes256-ctr,aes192-ctr,aes128-ctr
MACs hmac-sha2-512-etm@openssh.com,hmac-sha2-256-etm@openssh.com,hmac-sha2-512,hmac-sha2-256
KexAlgorithms curve25519-sha256,curve25519-sha256@libssh.org,diffie-hellman-group16-sha512,diffie-hellman-group18-sha512
SSH_STATIC
    [[ "$DISABLE_PASS_AUTH" == true ]] \
      && echo "PasswordAuthentication no" \
      || echo "# PasswordAuthentication yes  (no key found — left enabled to prevent lockout)"
  } | run_sudo tee "$SSHD_CONF" > /dev/null

  # Validate before reloading — avoids breaking SSH access
  if run_sudo sshd -t 2>/dev/null; then
    run_sudo systemctl reload ssh 2>/dev/null || run_sudo systemctl reload sshd 2>/dev/null || true
    success "SSH: strong ciphers, no root, no forwarding/tunneling, rate-limited"
  else
    warn "sshd config validation failed — not reloaded. Check: sudo sshd -t"
  fi
  [[ "$DISABLE_PASS_AUTH" == true ]] && \
    warn "  → Verify your SSH key works in another terminal before closing this session"

  # ── [4] Login banner ─────────────────────────────────────────
  run_sudo tee /etc/issue.net > /dev/null << 'BANNER'
╔══════════════════════════════════════════════════════════════╗
║  AUTHORIZED ACCESS ONLY                                      ║
║  Unauthorized access is strictly prohibited and monitored.   ║
║  All activity is logged and subject to legal action.         ║
╚══════════════════════════════════════════════════════════════╝
BANNER
  success "Login warning banner set"

  # ── [5] Disable unused services ──────────────────────────────
  info "Disabling unnecessary services…"
  for SVC in avahi-daemon cups bluetooth ModemManager snapd.socket; do
    run_sudo systemctl disable --now "$SVC" 2>/dev/null || true
  done
  success "Unused services disabled"

  # ── [6] Comprehensive kernel sysctl hardening ────────────────
  info "Applying kernel sysctl hardening…"
  _backup /etc/sysctl.d/99-teneo-harden.conf
  run_sudo tee /etc/sysctl.d/99-teneo-harden.conf > /dev/null << 'SYSCTL'
# ════════════════════════════════════════════════════════════════
#  Teneo Kernel Hardening
# ════════════════════════════════════════════════════════════════

# ── Network: TCP/IP ───────────────────────────────────────────
net.ipv4.tcp_syncookies                   = 1   # SYN flood protection
net.ipv4.tcp_rfc1337                      = 1   # prevent TIME-WAIT assassination
net.ipv4.tcp_timestamps                   = 0   # prevent OS fingerprinting
net.ipv4.conf.all.rp_filter               = 1   # reverse path filtering
net.ipv4.conf.default.rp_filter           = 1
net.ipv4.conf.all.accept_redirects        = 0   # ignore ICMP redirects
net.ipv4.conf.default.accept_redirects    = 0
net.ipv4.conf.all.secure_redirects        = 0
net.ipv4.conf.default.secure_redirects    = 0
net.ipv4.conf.all.send_redirects          = 0
net.ipv4.conf.default.send_redirects      = 0
net.ipv4.conf.all.accept_source_route     = 0   # no source routing
net.ipv4.conf.default.accept_source_route = 0
net.ipv4.conf.all.log_martians            = 1   # log spoofed/impossible packets
net.ipv4.conf.default.log_martians        = 1
net.ipv4.icmp_echo_ignore_broadcasts      = 1   # smurf attack prevention
net.ipv4.icmp_ignore_bogus_error_responses = 1
net.ipv6.conf.all.accept_redirects        = 0
net.ipv6.conf.default.accept_redirects    = 0
net.ipv6.conf.all.accept_source_route     = 0

# ── Kernel: memory + pointer security ─────────────────────────
kernel.randomize_va_space  = 2   # full ASLR (stack, heap, mmap, VDSO)
kernel.dmesg_restrict      = 1   # hide dmesg from unprivileged users
kernel.kptr_restrict       = 2   # hide all kernel pointers in /proc
kernel.yama.ptrace_scope   = 1   # restrict ptrace to parent process only
kernel.perf_event_paranoid = 3   # block perf_event_open for non-root
kernel.sysrq               = 0   # disable magic SysRq (console backdoor)

# ── Kernel: eBPF lockdown ─────────────────────────────────────
kernel.unprivileged_bpf_disabled = 1   # block unprivileged eBPF
net.core.bpf_jit_harden         = 2   # harden eBPF JIT against spraying

# ── Filesystem protections ────────────────────────────────────
fs.suid_dumpable       = 0   # no core dumps from SUID processes
fs.protected_hardlinks = 1   # block cross-owner hardlinks
fs.protected_symlinks  = 1   # block symlink following in sticky dirs
fs.protected_fifos     = 2   # block FIFO open in sticky world-writable dirs
fs.protected_regular   = 2   # block regular file open in sticky world-writable dirs
SYSCTL
  # sysctl --system exits non-zero if any key is unsupported (common in LXC/VMs
  # which restrict kernel namespaces). Use || warn so hardening continues.
  run_sudo sysctl --system -q 2>/dev/null \
    || warn "Some sysctl keys not supported on this kernel (container/VM?) — others applied"
  success "Kernel: ASLR, kptr_restrict, eBPF lockdown, TCP hardening, FS guards"

  # ── [7] Core dumps disabled ───────────────────────────────────
  info "Disabling core dumps…"
  run_sudo tee /etc/security/limits.d/99-teneo-nodump.conf > /dev/null << 'NODUMP'
*    hard    core    0
root hard    core    0
NODUMP
  run_sudo mkdir -p /etc/systemd/coredump.conf.d
  run_sudo tee /etc/systemd/coredump.conf.d/teneo.conf > /dev/null << 'COREDUMP'
[Coredump]
Storage=none
ProcessSizeMax=0
COREDUMP
  success "Core dumps disabled (PAM limits + systemd coredump)"

  # ── [8] /tmp — noexec, nosuid, nodev ─────────────────────────
  info "Hardening /tmp mount options…"
  run_sudo mkdir -p /etc/systemd/system/tmp.mount.d
  run_sudo tee /etc/systemd/system/tmp.mount.d/teneo-options.conf > /dev/null << 'TMPMOUNT'
[Mount]
Options=mode=1777,strictatime,nosuid,nodev,noexec,size=512M
TMPMOUNT
  run_sudo systemctl daemon-reload
  run_sudo systemctl restart tmp.mount 2>/dev/null \
    && success "/tmp remounted: nosuid, nodev, noexec" \
    || warn "/tmp remount skipped (may not be a systemd tmpfs — not fatal)"

  # ── [9] AppArmor enforce profile ─────────────────────────────
  if command -v apparmor_parser &>/dev/null; then
    info "Installing AppArmor enforce profile for teneo-beacon…"
    local AA="/etc/apparmor.d/usr.bin.teneo-beacon"
    _backup "$AA"
    run_sudo tee "$AA" > /dev/null << 'APPARMOR'
#include <tunables/global>

/usr/bin/teneo-beacon flags=(enforce) {
  #include <abstractions/base>
  #include <abstractions/nameservice>
  #include <abstractions/ssl_certs>
  #include <abstractions/gtk>
  #include <abstractions/fonts>
  #include <abstractions/xdg-open>

  /usr/bin/teneo-beacon   mr,
  /usr/lib/**             mr,
  /lib/**                 mr,
  /usr/share/**           r,

  owner @{HOME}/.teneo/accounts/*/**  rw,
  owner /tmp/teneo-*                  rw,

  /tmp/.X*                rw,
  /tmp/.X*-lock           rw,
  /tmp/.ICE-unix/**       rw,

  network inet  stream,
  network inet6 stream,
  network inet  dgram,
  network unix  stream,

  @{PROC}/@{pid}/**       r,
  @{PROC}/sys/net/**      r,

  deny /etc/shadow          r,
  deny /etc/sudoers         r,
  deny /etc/sudoers.d/**    r,
  deny /root/**             rw,
  deny /home/*/.ssh/**      rw,
  deny @{PROC}/*/mem        rw,
  deny @{PROC}/sysrq-trigger rw,
}
APPARMOR
    run_sudo apparmor_parser -r "$AA" 2>/dev/null \
      && success "AppArmor: enforce profile loaded" \
      || warn "AppArmor profile written — reload with: sudo apparmor_parser -r ${AA}"
  else
    warn "AppArmor not available on this system — skipping"
  fi

  # ── [10] DNS-over-TLS ────────────────────────────────────────
  info "Configuring DNS-over-TLS…"
  run_sudo mkdir -p /etc/systemd/resolved.conf.d
  _backup /etc/systemd/resolved.conf.d/dot.conf
  run_sudo tee /etc/systemd/resolved.conf.d/dot.conf > /dev/null << 'DOT'
[Resolve]
DNS=1.1.1.1#cloudflare-dns.com 1.0.0.1#cloudflare-dns.com
FallbackDNS=8.8.8.8#dns.google 8.8.4.4#dns.google
DNSOverTLS=yes
DNSSEC=yes
DNSStubListener=yes
ReadEtcHosts=yes
DOT
  run_sudo systemctl restart systemd-resolved 2>/dev/null \
    && success "DNS-over-TLS: Cloudflare primary, Google fallback, DNSSEC on" \
    || warn "systemd-resolved restart failed — DNS-over-TLS may not be active"

  # Without /etc/resolv.conf pointing to the stub resolver (127.0.0.53),
  # applications bypass systemd-resolved entirely and DoT has no effect.
  local STUB="/run/systemd/resolve/stub-resolv.conf"
  local CURRENT_RESOLV; CURRENT_RESOLV=$(readlink /etc/resolv.conf 2>/dev/null || true)
  if [[ "$CURRENT_RESOLV" != "$STUB" ]]; then
    info "Linking /etc/resolv.conf → ${STUB} (required for DNS-over-TLS to take effect)"
    run_sudo ln -sf "$STUB" /etc/resolv.conf \
      && success "resolv.conf: stub resolver linked" \
      || warn "Could not link resolv.conf — DNS-over-TLS will not apply to all processes"
  fi

  # ── [11] Automatic security updates ──────────────────────────
  info "Enabling automatic security updates…"
  if run_sudo apt-get install -y -qq unattended-upgrades; then
    run_sudo tee /etc/apt/apt.conf.d/51teneo-auto-upgrades > /dev/null << 'AU'
APT::Periodic::Update-Package-Lists "1";
APT::Periodic::Unattended-Upgrade "1";
APT::Periodic::AutocleanInterval "7";
Unattended-Upgrade::Automatic-Reboot "false";
Unattended-Upgrade::Mail "root";
Unattended-Upgrade::Remove-Unused-Dependencies "true";
AU
    run_sudo systemctl enable unattended-upgrades --quiet 2>/dev/null || true
    success "Automatic security updates enabled"
  else
    warn "Failed to install unattended-upgrades — skipping auto-update setup"
  fi

  # ── [12] auditd — system call auditing ───────────────────────
  if ! dpkg -s auditd &>/dev/null; then
    info "Installing auditd…"
    run_sudo apt-get install -y -qq auditd 2>/dev/null || true
  fi
  if command -v auditctl &>/dev/null; then
    # Write the audit rules file; the teneo_data watch path must reflect
    # the real user's home, so we cannot use a single-quoted heredoc here.
    run_sudo tee /etc/audit/rules.d/99-teneo.rules > /dev/null << AUDIT
## Teneo Audit Rules — loaded by auditd on startup
-D                                               # flush all existing rules first

# Privilege escalation tracking
-a always,exit -F arch=b64 -S execve -F euid=0 -k priv_exec
-a always,exit -F arch=b32 -S execve -F euid=0 -k priv_exec

# Identity file changes
-w /etc/passwd          -p wa -k identity
-w /etc/shadow          -p wa -k identity
-w /etc/group           -p wa -k identity
-w /etc/sudoers         -p wa -k sudoers
-w /etc/sudoers.d/      -p wa -k sudoers

# SSH configuration changes
-w /etc/ssh/sshd_config    -p wa -k sshd_config
-w /etc/ssh/sshd_config.d/ -p wa -k sshd_config

# Teneo account data tampering
-w ${REAL_HOME}/.teneo     -p wa -k teneo_data

# Kernel module loading (rootkit detection)
-a always,exit -F arch=b64 -S init_module -S finit_module -S delete_module -k kernel_modules

# Network configuration changes
-a always,exit -F arch=b64 -S sethostname -S setdomainname -k network_mods

# System time tampering
-a always,exit -F arch=b64 -S adjtimex -S settimeofday -S clock_settime -k time_change

# Make audit config immutable (requires reboot to change rules)
-e 2
AUDIT
    run_sudo systemctl enable auditd --quiet 2>/dev/null || true
    run_sudo systemctl restart auditd 2>/dev/null \
      && success "auditd: rules loaded (identity/sudo/SSH/kernel/time/teneo)" \
      || warn "auditd restart failed — rules load on next boot"
  else
    warn "auditd binary not found — skipping audit rules"
  fi

  # ── [13] Credential store permissions ────────────────────────
  if [[ -d "$REAL_HOME/.teneo" ]]; then
    _exec run_sudo chown -R "$REAL_USER" "$REAL_HOME/.teneo" 2>/dev/null || true
    _exec run_sudo chmod 700 "$REAL_HOME/.teneo"
    _exec run_sudo find "$ACCOUNTS_ROOT" -name "meta.env" -exec chmod 600 {} \; 2>/dev/null || true
    _exec run_sudo find "$ACCOUNTS_ROOT" -type d -exec chmod 700 {} \; 2>/dev/null || true
    success "Credential store: 700 dirs, 600 secrets"
  fi

  # ── Summary ───────────────────────────────────────────────────
  section "Hardening Complete"
  echo -e "  ${GREEN}✓${RESET} [1]  UFW: deny all + rate-limited SSH (6 conn/30s)"
  echo -e "  ${GREEN}✓${RESET} [2]  fail2ban: SSH jail (2h) + recidive (1-week re-ban)"
  echo -e "  ${GREEN}✓${RESET} [3]  SSH: strong ciphers/MACs/KEX, no forwarding/tunneling"
  echo -e "  ${GREEN}✓${RESET} [4]  Login warning banner (/etc/issue.net)"
  echo -e "  ${GREEN}✓${RESET} [5]  Unused services disabled (avahi, cups, bluetooth…)"
  echo -e "  ${GREEN}✓${RESET} [6]  Kernel: ASLR, kptr_restrict, eBPF lockdown, FS guards"
  echo -e "  ${GREEN}✓${RESET} [7]  Core dumps disabled (PAM limits + systemd)"
  echo -e "  ${GREEN}✓${RESET} [8]  /tmp: nosuid, nodev, noexec"
  echo -e "  ${GREEN}✓${RESET} [9]  AppArmor enforce profile for teneo-beacon"
  echo -e "  ${GREEN}✓${RESET} [10] DNS-over-TLS + DNSSEC (Cloudflare + Google)"
  echo -e "  ${GREEN}✓${RESET} [11] Automatic security updates (unattended-upgrades)"
  echo -e "  ${GREEN}✓${RESET} [12] auditd: identity/sudo/SSH/kernel/time/teneo tracking"
  echo -e "  ${GREEN}✓${RESET} [13] Credential store: 700 dirs, 600 secrets"
  echo ""
}

# ================================================================
#  INSTALL
# ================================================================
cmd_install() {
  # install --local <path>  →  delegate to offline-install
  if [[ "${ARG2:-}" == "--local" ]]; then
    [[ -n "${ARG3:-}" ]] || die "Usage: sudo $0 install --local <path/to/teneo-beacon.deb>"
    ARG2="$ARG3"; cmd_offline_install; return
  fi

  require_sudo
  detect_ubuntu
  detect_arch
  _acquire_lock
  _setup_tmpfiles
  check_disk_space
  section "Installing Teneo Beacon"

  info "Updating package lists…"
  run_sudo apt-get update -qq

  local WEBKIT_PKG
  dpkg --compare-versions "$OS_VER" ge "22.04" 2>/dev/null \
    && WEBKIT_PKG="libwebkit2gtk-4.1-0" \
    || WEBKIT_PKG="libwebkit2gtk-4.0-37"

  # libasound2 was renamed to libasound2t64 in Ubuntu 24.04 (Noble)
  local LIBASOUND_PKG
  dpkg --compare-versions "$OS_VER" ge "24.04" 2>/dev/null \
    && LIBASOUND_PKG="libasound2t64" \
    || LIBASOUND_PKG="libasound2"

  local DEPS=(curl jq xvfb iproute2 iptables util-linux
              libgtk-3-0 "$WEBKIT_PKG"
              libayatana-appindicator3-1 librsvg2-2
              libssl3 libglib2.0-0 libnss3 libxss1 "$LIBASOUND_PKG")
  local MISSING=()
  for p in "${DEPS[@]}"; do dpkg -s "$p" &>/dev/null || MISSING+=("$p"); done
  [[ ${#MISSING[@]} -gt 0 ]] && run_sudo apt-get install -y -qq "${MISSING[@]}"

  # If already installed, ask before re-downloading
  if command -v teneo-beacon &>/dev/null; then
    local CURRENT_VER; CURRENT_VER=$(cat "$VERSION_FILE" 2>/dev/null || echo "unknown")
    warn "teneo-beacon already installed (version: ${CURRENT_VER})."
    local RI=""
    read -rp "  Re-download and reinstall? (y/N): " RI
    if [[ ! "$RI" =~ ^[Yy]$ ]]; then
      info "Skipping download — applying harden only."
      resolve_binary   # ensure APP_BINARY is set for callers (e.g. cmd_quicksetup)
      cmd_harden; return
    fi
  fi

  info "Fetching latest release from GitHub…"
  check_network
  require_jq

  local API; API=$(_curl -fsSL -H "Accept: application/vnd.github+json" "$GITHUB_API") \
    || die "GitHub API unreachable."
  local TAG DEB_URL DEB_NAME
  TAG=$(echo "$API"      | jq -r '.tag_name')
  DEB_URL=$(echo "$API"  | jq -r --arg pat "$ARCH_PAT" \
    '.assets[] | select(.name | test($pat)) | .browser_download_url' | head -1)
  DEB_NAME=$(echo "$API" | jq -r --arg pat "$ARCH_PAT" \
    '.assets[] | select(.name | test($pat)) | .name' | head -1)
  # jq outputs the string "null" (not empty) when a field is absent — guard both
  [[ -n "$TAG"    && "$TAG"    != "null" ]] || die "GitHub API returned no tag_name. Check: ${GITHUB_API}"
  [[ -n "$DEB_URL" && "$DEB_URL" != "null" ]] || die "No ${ARCH_PAT} .deb asset found in release ${TAG}."

  download_and_verify_deb "$DEB_URL" "$DEB_NAME" "$API"

  info "Installing .deb package…"
  local DPKG_ERR="/tmp/teneo-dpkg-$$.err"
  run_sudo dpkg -i "$DEB_CACHE" 2>"$DPKG_ERR" || {
    run_sudo apt-get install -f -y -qq
    run_sudo dpkg -i "$DEB_CACHE" 2>>"$DPKG_ERR" || { cat "$DPKG_ERR"; die "Package installation failed."; }
  }

  mkdir -p "$META_DIR"
  # Dirs are created as root (sudo); chown so the real user can access list/status/logs
  chown "$REAL_USER" "$REAL_HOME/.teneo" "$META_DIR" 2>/dev/null || true
  _write_atomic "$VERSION_FILE" "$TAG"
  chown "$REAL_USER" "$VERSION_FILE" 2>/dev/null || true
  resolve_binary
  success "Teneo Beacon ${TAG} installed → ${APP_BINARY}"

  cmd_harden

  echo ""
  info "Next: add your first account"
  echo -e "  ${CYAN}sudo $0 add${RESET}"
}

# ================================================================
#  ADD ACCOUNT
# ================================================================
cmd_add() {
  require_sudo
  resolve_binary
  _acquire_lock
  section "Add New Account"

  local ACCT_NAME="" RAW_ACCT_NAME=""
  read -rp "  Account name (alphanumeric, e.g. acct1): " RAW_ACCT_NAME
  ACCT_NAME="${RAW_ACCT_NAME//[^a-zA-Z0-9_-]/}"
  [[ "$ACCT_NAME" != "$RAW_ACCT_NAME" ]] && [[ -n "$ACCT_NAME" ]] \
    && warn "Name sanitised: '${RAW_ACCT_NAME}' → '${ACCT_NAME}'"
  [[ ${#ACCT_NAME} -ge 2  ]] || die "Name must be at least 2 characters."
  [[ ${#ACCT_NAME} -le 32 ]] || die "Name must be 32 characters or fewer."
  [[ -d "$ACCOUNTS_ROOT/$ACCT_NAME" ]] && die "Account '${ACCT_NAME}' already exists."

  echo ""
  echo -e "  ${YELLOW}Each account requires a unique outbound IP.${RESET}"
  echo -e "  ${YELLOW}Teneo blocks multiple accounts sharing the same IP.${RESET}"
  echo ""
  echo -e "  Proxy formats:  ${CYAN}http://host:port${RESET}  |  ${CYAN}http://user:pass@host:port${RESET}  |  ${CYAN}socks5://user:pass@host:port${RESET}"
  echo ""
  local PROXY_URL="${DEFAULT_PROXY:-}"
  read -rp "  Proxy URL${DEFAULT_PROXY:+ [default: ${DEFAULT_PROXY}]}: " PROXY_URL
  PROXY_URL="${PROXY_URL:-$DEFAULT_PROXY}"

  if [[ -n "$PROXY_URL" ]]; then
    validate_proxy_url "$PROXY_URL"
    check_proxy_unique "$PROXY_URL"
  else
    warn "No proxy — using server's bare IP."
  fi

  local DISP_NUM; DISP_NUM=$(_next_display)
  local DISPLAY_ID=":${DISP_NUM}"
  local ACCT_DIR="$ACCOUNTS_ROOT/$ACCT_NAME"
  local JITTER; JITTER=$(( RANDOM % 60 + 1 ))

  mkdir -p "$ACCT_DIR"/{config,data,cache,logs,run}
  chmod 700 "$ACCT_DIR" "$ACCT_DIR"/{config,data,cache,logs,run}

  # Use printf so special chars in PROXY_URL ($, \, backticks) are never expanded.
  {
    printf 'ACCT_NAME=%s\n'  "$ACCT_NAME"
    printf 'DISPLAY_NUM=%s\n' "$DISP_NUM"
    printf 'PROXY_URL=%s\n'  "$PROXY_URL"
    printf 'JITTER_SEC=%s\n' "$JITTER"
    printf 'CREATED=%s\n'    "$(date '+%Y-%m-%d %H:%M:%S')"
  } | _write_atomic "$ACCT_DIR/meta.env"
  chmod 600 "$ACCT_DIR/meta.env"
  # Restore ownership so the real user can run list/logs/status without sudo
  chown -R "$REAL_USER" "$ACCT_DIR"

  local PROXY_BLOCK=""
  if [[ -n "$PROXY_URL" ]]; then
    PROXY_BLOCK="Environment=http_proxy=${PROXY_URL}
Environment=https_proxy=${PROXY_URL}
Environment=HTTP_PROXY=${PROXY_URL}
Environment=HTTPS_PROXY=${PROXY_URL}
Environment=ALL_PROXY=${PROXY_URL}
Environment=no_proxy=localhost,127.0.0.1,::1"
  fi

  _write_service_units

  run_sudo systemctl daemon-reload
  run_sudo systemctl enable "teneo-xvfb@${ACCT_NAME}"  --quiet
  run_sudo systemctl enable "teneo-beacon@${ACCT_NAME}" --quiet
  run_sudo systemctl start  "teneo-xvfb@${ACCT_NAME}"
  _wait_for_service "teneo-xvfb@${ACCT_NAME}" 30 || warn "Xvfb may still be initializing"
  run_sudo systemctl start "teneo-beacon@${ACCT_NAME}"
  _wait_for_service "teneo-beacon@${ACCT_NAME}" 90 || warn "Beacon may still be starting (${JITTER}s jitter)"

  success "Account '${ACCT_NAME}' running — display ${DISPLAY_ID}, jitter ${JITTER}s"
  echo ""
  echo -e "  ${YELLOW}${BOLD}First-time login required:${RESET}"
  local SRV_IP; SRV_IP=$(hostname -I 2>/dev/null | awk '{print $1}' || echo "your-server")
  echo -e "  ${CYAN}ssh user@${SRV_IP}${RESET}"
  echo -e "  ${CYAN}DISPLAY=${DISPLAY_ID} XDG_CONFIG_HOME=${ACCT_DIR}/config XDG_DATA_HOME=${ACCT_DIR}/data ${APP_BINARY}${RESET}"
  echo ""
  echo -e "  Then restart to run headlessly:"
  echo -e "  ${CYAN}sudo systemctl restart teneo-beacon@${ACCT_NAME}${RESET}"
  echo ""
}

# ================================================================
#  REMOVE
# ================================================================
cmd_remove() {
  local NAME="${ARG2:-}"
  [[ -n "$NAME" ]] || { echo "Usage: sudo $0 remove <account-name>"; exit 1; }
  [[ "$NAME" =~ ^[a-zA-Z0-9_-]+$ ]] || die "Invalid account name '${NAME}' (only a-z A-Z 0-9 _ - allowed)."
  [[ -d "$ACCOUNTS_ROOT/$NAME" ]] || die "Account '${NAME}' not found."
  require_sudo
  _acquire_lock
  section "Remove Account: ${NAME}"

  _confirm "Permanently remove '${NAME}' and all its data?" || { info "Aborted."; exit 0; }

  for SVC in "teneo-beacon@${NAME}" "teneo-xvfb@${NAME}"; do
    run_sudo systemctl stop    "$SVC" 2>/dev/null || true
    run_sudo systemctl disable "$SVC" 2>/dev/null || true
    run_sudo rm -f "/etc/systemd/system/${SVC}.service"
  done
  run_sudo rm -f "/etc/logrotate.d/teneo-beacon-${NAME}"
  run_sudo systemctl daemon-reload

  # Paranoia: validate path before rm -rf
  [[ "$ACCOUNTS_ROOT" == "$REAL_HOME/.teneo/accounts" ]] \
    || die "Unexpected ACCOUNTS_ROOT '${ACCOUNTS_ROOT}' — refusing rm -rf for safety."
  rm -rf "${ACCOUNTS_ROOT:?}/${NAME:?}"
  success "Account '${NAME}' removed."
}

# ================================================================
#  LIST
# ================================================================
cmd_list() {
  local VER="not installed"
  [[ -f "$VERSION_FILE" ]] && VER=$(<"$VERSION_FILE")

  local _any; _any=("$ACCOUNTS_ROOT"/*/)
  if [[ ! -d "$ACCOUNTS_ROOT" ]] || [[ ! -d "${_any[0]}" ]]; then
    if [[ "$JSON_OUT" == true ]]; then
      echo '{"accounts":[]}'
    else
      echo ""; hr
      echo -e "${BOLD}  Teneo Beacon  —  ${VER}${RESET}"; hr; echo ""
      echo -e "  ${YELLOW}No accounts yet.${RESET}  Run: ${CYAN}sudo $0 add${RESET}"; echo ""
    fi
    return
  fi

  if [[ "$JSON_OUT" == true ]]; then
    local first=true; echo -n '{"version":"'"$VER"'","accounts":['
    for D in "$ACCOUNTS_ROOT"/*/; do
      [[ -d "$D" ]] || continue
      local N; N=$(basename "$D")
      local META="${D}meta.env"; [[ -f "$META" ]] || continue
      local DISP_NUM; DISP_NUM=$(grep "^DISPLAY_NUM=" "$META" | cut -d= -f2)
      local PX; PX=$(grep "^PROXY_URL=" "$META" | cut -d= -f2-)
      local BS; BS=$(systemctl is-active "teneo-beacon@${N}" 2>/dev/null || echo dead)
      local XS; XS=$(systemctl is-active "teneo-xvfb@${N}"  2>/dev/null || echo dead)
      local MEM; MEM=$(systemctl show "teneo-beacon@${N}" --property=MemoryCurrent \
        2>/dev/null | cut -d= -f2)
      local RESTARTS; RESTARTS=$(systemctl show "teneo-beacon@${N}" --property=NRestarts \
        2>/dev/null | cut -d= -f2)
      [[ "$first" == true ]] && first=false || echo -n ','
      printf '{"name":"%s","display":%s,"beacon":"%s","xvfb":"%s","memory_bytes":%s,"restarts":%s,"proxy":"%s"}' \
        "$N" "${DISP_NUM:-0}" "$BS" "$XS" "${MEM:-0}" "${RESTARTS:-0}" \
        "$(echo "$PX" | sed 's|://[^:@]*:[^@]*@|://***@|')"
    done
    echo ']}'; return
  fi

  echo ""; hr
  echo -e "${BOLD}  Teneo Beacon  —  ${VER}${RESET}"; hr; echo ""
  printf "  %-14s %-8s %-10s %-10s %-8s %-8s %-5s %s\n" \
    "NAME" "DISPLAY" "XVFB" "BEACON" "MEMORY" "UPTIME" "RST" "PROXY"
  echo "  $(printf '─%.0s' {1..90})"

  # Support both:  list active         (ARG2=active)
  #               list --filter active  (ARG2=--filter, ARG3=active)
  local FILTER="all"
  if [[ "${ARG2:-}" == "--filter" ]]; then
    FILTER="${ARG3:-all}"
  elif [[ "${ARG2:-}" =~ ^(active|dead)$ ]]; then
    FILTER="${ARG2}"
  fi
  local D N META DISP_NUM PX XS BS XC BC PD MEM MEM_STR UPTIME_STR RESTARTS
  for D in "$ACCOUNTS_ROOT"/*/; do
    [[ -d "$D" ]] || continue
    N=$(basename "$D")
    META="${D}meta.env"; [[ -f "$META" ]] || continue

    DISP_NUM=$(grep "^DISPLAY_NUM=" "$META" 2>/dev/null | cut -d= -f2)
    PX=$(grep        "^PROXY_URL="   "$META" 2>/dev/null | cut -d= -f2-)

    XS=$(systemctl is-active "teneo-xvfb@${N}"   2>/dev/null || echo "dead")
    BS=$(systemctl is-active "teneo-beacon@${N}"  2>/dev/null || echo "dead")

    # Apply filter
    [[ "$FILTER" == "active" && "$BS" != "active" ]] && continue
    [[ "$FILTER" == "dead"   && "$BS" == "active" ]] && continue

    # Memory
    MEM=$(systemctl show "teneo-beacon@${N}" --property=MemoryCurrent 2>/dev/null | cut -d= -f2)
    if [[ "$MEM" =~ ^[0-9]+$ ]] && (( MEM > 0 )); then
      MEM_STR=$(_fmt_bytes "$MEM")
    else
      MEM_STR="—"
    fi

    # Uptime
    local SINCE; SINCE=$(systemctl show "teneo-beacon@${N}" \
      --property=ActiveEnterTimestamp 2>/dev/null | cut -d= -f2-)
    UPTIME_STR="—"
    if [[ -n "$SINCE" && "$SINCE" != "n/a" && "$BS" == "active" ]]; then
      local epoch; epoch=$(date -d "$SINCE" +%s 2>/dev/null || true)
      [[ -n "$epoch" ]] && UPTIME_STR=$(_fmt_elapsed $(( $(date +%s) - epoch )) )
    fi

    # Restart count
    RESTARTS=$(systemctl show "teneo-beacon@${N}" --property=NRestarts 2>/dev/null | cut -d= -f2)

    PD="${PX:-none}"; PD=$(echo "$PD" | sed 's|://[^:@]*:[^@]*@|://***@|')

    local XS_PAD BC_PAD
    XS_PAD=$(printf '%-10s' "$XS"); BC_PAD=$(printf '%-10s' "$BS")
    [[ "$XS" == "active" ]] && XC="${GREEN}${XS_PAD}${RESET}" || XC="${RED}${XS_PAD}${RESET}"
    [[ "$BS" == "active" ]] && BC="${GREEN}${BC_PAD}${RESET}" || BC="${RED}${BC_PAD}${RESET}"

    printf "  %-14s %-8s " "$N" ":${DISP_NUM:-?}"
    printf '%b' "$XC"; printf '%b' "$BC"
    printf "%-8s %-8s %-5s %s\n" "$MEM_STR" "$UPTIME_STR" "${RESTARTS:-0}" "$PD"
  done

  echo ""
  echo -e "  ${CYAN}$0 stats <n>${RESET}   ${CYAN}$0 logs <n>${RESET}   ${CYAN}$0 status <n>${RESET}   ${CYAN}sudo $0 restart <n>${RESET}"
  echo ""
}

# ================================================================
#  LOGS
# ================================================================
cmd_logs() {
  local N="${ARG2:-}"; [[ -n "$N" ]] || { echo "Usage: $0 logs <account-name>"; exit 1; }
  [[ "$N" =~ ^[a-zA-Z0-9_-]+$ ]] || die "Invalid account name '${N}'."
  [[ -d "$ACCOUNTS_ROOT/$N" ]] || die "Account '${N}' not found."
  local LINES="${ARG3:-50}"
  [[ "$LINES" =~ ^[0-9]+$ ]] || LINES=50
  local F="$ACCOUNTS_ROOT/$N/logs/beacon.log"
  if [[ -f "$F" ]]; then
    info "Tailing ${F} (Ctrl-C to stop)"
    tail -n "$LINES" -f "$F"
  else
    info "No log file yet — falling back to journalctl"
    journalctl -u "teneo-beacon@${N}" -f --no-pager -n "$LINES"
  fi
}

# ================================================================
#  STATUS
# ================================================================
cmd_status() {
  local N="${ARG2:-}"; [[ -n "$N" ]] || { echo "Usage: $0 status <account-name>"; exit 1; }
  [[ "$N" =~ ^[a-zA-Z0-9_-]+$ ]] || die "Invalid account name '${N}'."
  [[ -d "$ACCOUNTS_ROOT/$N" ]] || die "Account '${N}' not found."

  echo ""; hr; echo -e "${BOLD}  Status: ${N}${RESET}"; hr; echo ""

  local META="$ACCOUNTS_ROOT/$N/meta.env"
  if [[ -f "$META" ]]; then
    echo -e "  ${BOLD}Meta:${RESET}"
    grep -v "^PROXY_URL=" "$META" | sed 's/^/    /'
    local PX; PX=$(grep "^PROXY_URL=" "$META" | cut -d= -f2- | sed 's|://[^:@]*:[^@]*@|://***@|')
    echo "    PROXY_URL=${PX:-none}"
    echo ""
  fi

  for SVC in "teneo-xvfb@${N}" "teneo-beacon@${N}"; do
    echo -e "  ${CYAN}${SVC}${RESET}"
    systemctl status "$SVC" --no-pager --lines=15 2>/dev/null || true
    echo ""
  done
}

# ================================================================
#  UPDATE
# ================================================================
cmd_update() {
  # --staged can be passed as a CLI flag or set in teneo.conf
  [[ "${ARG2:-}" == "--staged" ]] && STAGED_UPDATE=true

  require_sudo
  detect_ubuntu
  detect_arch
  _acquire_lock
  _setup_tmpfiles
  require_jq
  check_network
  check_disk_space

  info "Checking for updates…"
  local API; API=$(_curl -fsSL -H "Accept: application/vnd.github+json" "$GITHUB_API") \
    || die "GitHub API unreachable."
  local LATEST; LATEST=$(echo "$API" | jq -r '.tag_name')
  local CURRENT="none"; [[ -f "$VERSION_FILE" ]] && CURRENT=$(<"$VERSION_FILE")
  # jq outputs the string "null" (not empty) when a field is absent
  [[ -n "$LATEST" && "$LATEST" != "null" ]] || die "GitHub API returned no tag_name. Check: ${GITHUB_API}"

  if [[ "$LATEST" == "$CURRENT" ]]; then
    success "Already on latest: ${CURRENT}"; return
  fi

  info "Upgrading ${CURRENT} → ${LATEST}"
  # Auto-backup before update if configured
  if [[ "$AUTO_BACKUP" == true ]]; then
    info "AUTO_BACKUP enabled — creating pre-update backup…"
    ARG2=""; cmd_backup   # uses default timestamped filename
  fi
  local DEB_URL DEB_NAME
  DEB_URL=$(echo "$API"  | jq -r --arg pat "$ARCH_PAT" \
    '.assets[] | select(.name | test($pat)) | .browser_download_url' | head -1)
  DEB_NAME=$(echo "$API" | jq -r --arg pat "$ARCH_PAT" \
    '.assets[] | select(.name | test($pat)) | .name' | head -1)
  [[ -n "$DEB_URL" && "$DEB_URL" != "null" ]] || die "No ${ARCH_PAT} .deb found in release ${LATEST}."

  download_and_verify_deb "$DEB_URL" "$DEB_NAME" "$API"

  local DPKG_ERR="/tmp/teneo-dpkg-$$.err"
  run_sudo dpkg -i "$DEB_CACHE" 2>"$DPKG_ERR" || {
    run_sudo apt-get install -f -y -qq
    run_sudo dpkg -i "$DEB_CACHE" 2>>"$DPKG_ERR" || { cat "$DPKG_ERR"; die "Package update failed."; }
  }
  # Track previous version for potential rollback
  [[ -f "$VERSION_FILE" ]] && cp "$VERSION_FILE" "$PREV_VERSION_FILE" 2>/dev/null || true
  _write_atomic "$VERSION_FILE" "$LATEST"
  chown "$REAL_USER" "$VERSION_FILE" 2>/dev/null || true
  success "Binary updated to ${LATEST} (previous: ${CURRENT})"

  local D N
  for D in "$ACCOUNTS_ROOT"/*/; do
    [[ -d "$D" ]] || continue
    N=$(basename "$D")
    systemctl is-active --quiet "teneo-beacon@${N}" 2>/dev/null || continue
    if [[ "$STAGED_UPDATE" == true ]]; then
      _confirm "Restart ${N}?" || { info "Skipping ${N}."; continue; }
    fi
    info "Restarting ${N}…"
    run_sudo systemctl restart "teneo-beacon@${N}"
  done
  success "All active accounts restarted."
}

# ================================================================
#  QUICK SETUP
# ================================================================
cmd_quicksetup() {
  require_sudo
  _acquire_lock
  banner

  echo -e "  ${BOLD}Quick Setup — Single Account Node${RESET}"
  echo -e "  This wizard will:"
  echo -e "   ${CYAN}1.${RESET} Install Teneo Beacon binary"
  echo -e "   ${CYAN}2.${RESET} Apply full system hardening (13 layers)"
  echo -e "   ${CYAN}3.${RESET} Create and start one account as a hardened system service"
  echo ""
  echo -e "  ${YELLOW}Requirements:${RESET} Ubuntu 20.04+, amd64 or arm64, sudo access"
  echo ""
  read -rp "  Press ENTER to begin, or Ctrl-C to cancel… "
  echo ""

  section "Step 1 / 3 — Install & Harden"
  cmd_install

  section "Step 2 / 3 — Account Setup"

  local ACCT_NAME="main"
  local RAW_NAME="" INPUT_NAME="" ACCT_DIR="" DISP_NUM=""
  read -rp "  Account name [default: main]: " RAW_NAME
  INPUT_NAME="${RAW_NAME//[^a-zA-Z0-9_-]/}"
  if [[ -n "$RAW_NAME" && -z "$INPUT_NAME" ]]; then
    warn "Name '${RAW_NAME}' contains only invalid characters — falling back to: main"
  elif [[ -n "$INPUT_NAME" ]]; then
    ACCT_NAME="$INPUT_NAME"
    [[ "$INPUT_NAME" != "$RAW_NAME" ]] && warn "Name sanitised: '${RAW_NAME}' → '${INPUT_NAME}'"
  fi
  info "Account name: ${ACCT_NAME}"
  [[ ${#ACCT_NAME} -ge 2  ]] || die "Account name must be at least 2 characters."
  [[ ${#ACCT_NAME} -le 32 ]] || die "Account name must be 32 characters or fewer."

  if [[ -d "$ACCOUNTS_ROOT/$ACCT_NAME" ]]; then
    warn "Account '${ACCT_NAME}' already exists — skipping creation."
    warn "Use '$0 list' to see its status, or '$0 remove ${ACCT_NAME}' to reset it."
  else
    echo ""
    echo -e "  ${YELLOW}Proxy (optional):${RESET} for a single account, your server IP is fine."
    echo -e "  Formats: ${CYAN}http://host:port${RESET}  |  ${CYAN}http://user:pass@host:port${RESET}  |  ${CYAN}socks5://user:pass@host:port${RESET}"
    echo ""
    local PROXY_URL=""
    read -rp "  Proxy URL [leave blank to skip]: " PROXY_URL

    if [[ -n "$PROXY_URL" ]]; then
      validate_proxy_url "$PROXY_URL"
      check_proxy_unique "$PROXY_URL"
    else
      info "No proxy — using server's bare IP."
    fi

    DISP_NUM=$(_next_display)
    local DISPLAY_ID=":${DISP_NUM}"
    ACCT_DIR="$ACCOUNTS_ROOT/$ACCT_NAME"
    local JITTER=3   # short fixed jitter for single account

    mkdir -p "$ACCT_DIR"/{config,data,cache,logs,run}
    chmod 700 "$ACCT_DIR" "$ACCT_DIR"/{config,data,cache,logs,run}

    {
      printf 'ACCT_NAME=%s\n'  "$ACCT_NAME"
      printf 'DISPLAY_NUM=%s\n' "$DISP_NUM"
      printf 'PROXY_URL=%s\n'  "$PROXY_URL"
      printf 'JITTER_SEC=%s\n' "$JITTER"
      printf 'CREATED=%s\n'    "$(date '+%Y-%m-%d %H:%M:%S')"
    } | _write_atomic "$ACCT_DIR/meta.env"
    chmod 600 "$ACCT_DIR/meta.env"
    # Restore ownership so the real user can run list/logs/status without sudo
    chown -R "$REAL_USER" "$ACCT_DIR"

    local PROXY_BLOCK=""
    if [[ -n "$PROXY_URL" ]]; then
      PROXY_BLOCK="Environment=http_proxy=${PROXY_URL}
Environment=https_proxy=${PROXY_URL}
Environment=HTTP_PROXY=${PROXY_URL}
Environment=HTTPS_PROXY=${PROXY_URL}
Environment=ALL_PROXY=${PROXY_URL}
Environment=no_proxy=localhost,127.0.0.1,::1"
    fi

    _write_service_units

    run_sudo systemctl daemon-reload
    run_sudo systemctl enable "teneo-xvfb@${ACCT_NAME}"  --quiet
    run_sudo systemctl enable "teneo-beacon@${ACCT_NAME}" --quiet
    run_sudo systemctl start  "teneo-xvfb@${ACCT_NAME}"
    _wait_for_service "teneo-xvfb@${ACCT_NAME}"  30 || warn "Xvfb may still be starting"
    run_sudo systemctl start "teneo-beacon@${ACCT_NAME}"
    _wait_for_service "teneo-beacon@${ACCT_NAME}" 60 || warn "Beacon may still be starting"

    success "Account '${ACCT_NAME}' created and running"
  fi

  section "Step 3 / 3 — All Done!"
  local SERVER_IP; SERVER_IP=$(hostname -I 2>/dev/null | awk '{print $1}' || echo "your-server")
  ACCT_DIR="$ACCOUNTS_ROOT/$ACCT_NAME"
  DISP_NUM=$(grep "^DISPLAY_NUM=" "$ACCT_DIR/meta.env" 2>/dev/null | cut -d= -f2 || echo "100")

  echo -e "  ${GREEN}${BOLD}✓ Teneo Beacon is installed, hardened, and running.${RESET}"
  echo ""
  echo -e "  ${BOLD}Next — authenticate once (required):${RESET}"
  echo -e "  ${CYAN}# From your local machine:${RESET}"
  echo -e "  ${CYAN}ssh user@${SERVER_IP}${RESET}"
  echo ""
  echo -e "  ${CYAN}# On the server — launch to log in:${RESET}"
  echo -e "  ${CYAN}DISPLAY=:${DISP_NUM} XDG_CONFIG_HOME=${ACCT_DIR}/config XDG_DATA_HOME=${ACCT_DIR}/data ${APP_BINARY}${RESET}"
  echo ""
  echo -e "  ${BOLD}Then restart to run headlessly:${RESET}"
  echo -e "  ${CYAN}sudo systemctl restart teneo-beacon@${ACCT_NAME}${RESET}"
  echo ""
  hr
  echo -e "  ${BOLD}Day-to-day:${RESET}"
  echo -e "  ${CYAN}$0 list${RESET}               — running status"
  echo -e "  ${CYAN}$0 logs ${ACCT_NAME}${RESET}        — tail live logs"
  echo -e "  ${CYAN}$0 status ${ACCT_NAME}${RESET}      — detailed systemd status"
  echo -e "  ${CYAN}sudo $0 update${RESET}        — upgrade to latest release"
  echo -e "  ${CYAN}sudo $0 add${RESET}           — add more accounts later"
  hr
  echo ""
}

# ================================================================
#  INTERNAL HELPERS
# ================================================================
_next_display() {
  # Safe against concurrent allocation: every caller (cmd_add, cmd_quicksetup)
  # holds the flock via _acquire_lock before reaching this function, so two
  # simultaneous 'add' runs cannot race on the same display number.
  local NUM=$DISPLAY_BASE
  local TAKEN=false M D
  local MAX_DISPLAYS=500  # sanity cap — no legitimate use case needs more
  while (( NUM < DISPLAY_BASE + MAX_DISPLAYS )); do
    TAKEN=false
    for M in "$ACCOUNTS_ROOT"/*/meta.env; do
      [[ -f "$M" ]] || continue
      D=$(grep "^DISPLAY_NUM=" "$M" 2>/dev/null | cut -d= -f2)
      [[ "$D" == "$NUM" ]] && { TAKEN=true; break; }
    done
    [[ "$TAKEN" == false ]] && break
    NUM=$(( NUM + 1 ))
  done
  (( NUM < DISPLAY_BASE + MAX_DISPLAYS )) \
    || die "_next_display: exhausted display range [${DISPLAY_BASE}–$(( DISPLAY_BASE + MAX_DISPLAYS - 1 ))]"
  echo "$NUM"
}


# ================================================================
#  PAUSE — stop service without disabling (keeps autostart)
# ================================================================
cmd_pause() {
  local NAME="${ARG2:-}"; _require_account "$NAME"
  require_sudo
  section "Pause: ${NAME}"
  _exec run_sudo systemctl stop "teneo-beacon@${NAME}" 2>/dev/null || true
  _exec run_sudo systemctl stop "teneo-xvfb@${NAME}"   2>/dev/null || true
  success "Account '${NAME}' paused. Services remain enabled for next boot."
  info "Resume with: $0 resume ${NAME}"
}

# ================================================================
#  RESUME — start a paused account
# ================================================================
cmd_resume() {
  local NAME="${ARG2:-}"; _require_account "$NAME"
  require_sudo
  section "Resume: ${NAME}"
  _exec run_sudo systemctl start "teneo-xvfb@${NAME}"
  _wait_for_service "teneo-xvfb@${NAME}" 20 || warn "Xvfb slow to start"
  _exec run_sudo systemctl start "teneo-beacon@${NAME}"
  _wait_for_service "teneo-beacon@${NAME}" 60 || warn "Beacon slow to start"
  success "Account '${NAME}' resumed."
}

# ================================================================
#  RESTART — restart one account
# ================================================================
cmd_restart() {
  local NAME="${ARG2:-}"; _require_account "$NAME"
  require_sudo
  section "Restart: ${NAME}"
  _exec run_sudo systemctl restart "teneo-beacon@${NAME}"
  _wait_for_service "teneo-beacon@${NAME}" 60 || warn "Beacon slow to restart"
  success "Account '${NAME}' restarted."
}

# ================================================================
#  START-ALL / STOP-ALL / RESTART-ALL
# ================================================================
cmd_start_all() {
  require_sudo; section "Start All Accounts"
  local D N any=false
  for D in "$ACCOUNTS_ROOT"/*/; do
    [[ -d "$D" ]] || continue; N=$(basename "$D"); any=true
    info "Starting ${N}…"
    _exec run_sudo systemctl start "teneo-xvfb@${N}"   2>/dev/null || true
    _exec run_sudo systemctl start "teneo-beacon@${N}" 2>/dev/null || true
  done
  [[ "$any" == true ]] && success "All accounts started." || warn "No accounts found."
}

cmd_stop_all() {
  require_sudo; section "Stop All Accounts"
  local D N any=false
  for D in "$ACCOUNTS_ROOT"/*/; do
    [[ -d "$D" ]] || continue; N=$(basename "$D"); any=true
    info "Stopping ${N}…"
    _exec run_sudo systemctl stop "teneo-beacon@${N}" 2>/dev/null || true
    _exec run_sudo systemctl stop "teneo-xvfb@${N}"   2>/dev/null || true
  done
  [[ "$any" == true ]] && success "All accounts stopped." || warn "No accounts found."
}

cmd_restart_all() {
  require_sudo; section "Restart All Accounts"
  local D N any=false
  for D in "$ACCOUNTS_ROOT"/*/; do
    [[ -d "$D" ]] || continue; N=$(basename "$D"); any=true
    info "Restarting ${N}…"
    if [[ "$STAGED_UPDATE" == true ]]; then
      _confirm "Restart ${N}?" || { info "Skipped ${N}."; continue; }
    fi
    _exec run_sudo systemctl restart "teneo-beacon@${N}" 2>/dev/null || true
    _wait_for_service "teneo-beacon@${N}" 30 || warn "  ${N} slow to restart"
  done
  [[ "$any" == true ]] && success "All accounts restarted." || warn "No accounts found."
}

# ================================================================
#  RENAME — rename an account (meta + service units)
# ================================================================
cmd_rename() {
  local OLD="${ARG2:-}" NEW="${ARG3:-}"
  _require_account "$OLD"
  [[ -n "$NEW" ]] || die "Usage: sudo $0 rename <old-name> <new-name>"
  [[ "$NEW" =~ ^[a-zA-Z0-9_-]+$ ]] || die "New name '${NEW}' contains invalid characters."
  [[ ${#NEW} -ge 2 && ${#NEW} -le 32 ]] || die "New name must be 2–32 characters."
  [[ -d "$ACCOUNTS_ROOT/$NEW" ]] && die "Account '${NEW}' already exists."
  require_sudo; _acquire_lock
  section "Rename: ${OLD} → ${NEW}"

  info "Stopping services for '${OLD}'…"
  _exec run_sudo systemctl stop    "teneo-beacon@${OLD}" 2>/dev/null || true
  _exec run_sudo systemctl stop    "teneo-xvfb@${OLD}"   2>/dev/null || true
  _exec run_sudo systemctl disable "teneo-beacon@${OLD}" 2>/dev/null || true
  _exec run_sudo systemctl disable "teneo-xvfb@${OLD}"   2>/dev/null || true
  _exec run_sudo rm -f "/etc/systemd/system/teneo-beacon@${OLD}.service" \
                       "/etc/systemd/system/teneo-xvfb@${OLD}.service" \
                       "/etc/logrotate.d/teneo-beacon-${OLD}"

  info "Renaming account directory…"
  if [[ "$DRY_RUN" != true ]]; then
    mv "$ACCOUNTS_ROOT/$OLD" "$ACCOUNTS_ROOT/$NEW"
    # Update ACCT_NAME inside meta.env
    sed -i "s/^ACCT_NAME=.*/ACCT_NAME=${NEW}/" "$ACCOUNTS_ROOT/$NEW/meta.env" 2>/dev/null || true
  else
    echo -e "  ${YELLOW}[DRY-RUN]${RESET} mv ${ACCOUNTS_ROOT}/${OLD} → ${ACCOUNTS_ROOT}/${NEW}"
  fi

  info "Re-creating service units for '${NEW}'…"
  if [[ "$DRY_RUN" != true ]]; then
    local META="$ACCOUNTS_ROOT/$NEW/meta.env"
    local ACCT_NAME="$NEW"
    local ACCT_DIR="$ACCOUNTS_ROOT/$NEW"
    local DISP_NUM; DISP_NUM=$(grep "^DISPLAY_NUM=" "$META" | cut -d= -f2)
    local DISPLAY_ID=":${DISP_NUM}"
    local JITTER;   JITTER=$(grep  "^JITTER_SEC="  "$META" | cut -d= -f2)
    local PX;       PX=$(grep      "^PROXY_URL="   "$META" | cut -d= -f2-)
    local PROXY_BLOCK=""
    if [[ -n "$PX" ]]; then
      PROXY_BLOCK="Environment=http_proxy=${PX}
Environment=https_proxy=${PX}
Environment=HTTP_PROXY=${PX}
Environment=HTTPS_PROXY=${PX}
Environment=ALL_PROXY=${PX}
Environment=no_proxy=localhost,127.0.0.1,::1"
    fi
    resolve_binary
    _write_service_units
    run_sudo systemctl daemon-reload
    run_sudo systemctl enable "teneo-xvfb@${NEW}"  --quiet
    run_sudo systemctl enable "teneo-beacon@${NEW}" --quiet
    run_sudo systemctl start  "teneo-xvfb@${NEW}"
    _wait_for_service "teneo-xvfb@${NEW}"  20 || true
    run_sudo systemctl start  "teneo-beacon@${NEW}"
    _wait_for_service "teneo-beacon@${NEW}" 60 || true
  fi
  success "Account renamed: '${OLD}' → '${NEW}'"
}

# ================================================================
#  STATS — per-account resource usage
# ================================================================
cmd_stats() {
  local NAME="${ARG2:-}"; _require_account "$NAME"
  local SVC="teneo-beacon@${NAME}"

  if [[ "$JSON_OUT" == true ]]; then
    local mem cpu restarts ts
    mem=$(systemctl show "$SVC" --property=MemoryCurrent 2>/dev/null | cut -d= -f2)
    cpu=$(systemctl show "$SVC" --property=CPUUsageNSec  2>/dev/null | cut -d= -f2)
    restarts=$(systemctl show "$SVC" --property=NRestarts 2>/dev/null | cut -d= -f2)
    ts=$(systemctl show "$SVC"  --property=ActiveEnterTimestamp 2>/dev/null | cut -d= -f2-)
    printf '{"account":"%s","memory_bytes":%s,"cpu_ns":%s,"restarts":%s,"active_since":"%s"}\n' \
      "$NAME" "${mem:-0}" "${cpu:-0}" "${restarts:-0}" "$ts"
    return
  fi

  echo ""; hr; echo -e "${BOLD}  Stats: ${NAME}${RESET}"; hr; echo ""

  # Systemd properties
  local props; props=$(systemctl show "$SVC" \
    --property=ActiveState,SubState,MemoryCurrent,CPUUsageNSec,NRestarts,\
ActiveEnterTimestamp,ExecMainPID,TasksCurrent 2>/dev/null)

  local state;    state=$(    echo "$props" | grep '^ActiveState='   | cut -d= -f2)
  local substate; substate=$( echo "$props" | grep '^SubState='      | cut -d= -f2)
  local mem;      mem=$(      echo "$props" | grep '^MemoryCurrent='  | cut -d= -f2)
  local cpu_ns;   cpu_ns=$(   echo "$props" | grep '^CPUUsageNSec='  | cut -d= -f2)
  local restarts; restarts=$( echo "$props" | grep '^NRestarts='     | cut -d= -f2)
  local since;    since=$(    echo "$props" | grep '^ActiveEnterTimestamp=' | cut -d= -f2-)
  local pid;      pid=$(      echo "$props" | grep '^ExecMainPID='   | cut -d= -f2)
  local tasks;    tasks=$(    echo "$props" | grep '^TasksCurrent='  | cut -d= -f2)

  # Compute uptime from ActiveEnterTimestamp
  local uptime_str="—"
  if [[ -n "$since" && "$since" != "n/a" ]]; then
    local epoch_since; epoch_since=$(date -d "$since" +%s 2>/dev/null || true)
    if [[ -n "$epoch_since" ]]; then
      uptime_str=$(_fmt_elapsed $(( $(date +%s) - epoch_since )) )
    fi
  fi

  # CPU time in seconds from nanoseconds
  local cpu_s="—"
  if [[ "$cpu_ns" =~ ^[0-9]+$ ]] && (( cpu_ns > 0 )); then
    cpu_s="$(( cpu_ns / 1000000000 ))s CPU"
  fi

  local mem_str="—"
  if [[ "$mem" =~ ^[0-9]+$ ]] && (( mem > 0 )); then
    mem_str=$(_fmt_bytes "$mem")
  fi

  local state_col
  [[ "$state" == "active" ]] && state_col="${GREEN}${state} (${substate})${RESET}" \
                              || state_col="${RED}${state} (${substate})${RESET}"

  printf "  %-20s %b\n"   "State:"    "$state_col"
  printf "  %-20s %s\n"   "Uptime:"   "$uptime_str"
  printf "  %-20s %s\n"   "Memory:"   "$mem_str"
  printf "  %-20s %s\n"   "CPU used:" "$cpu_s"
  printf "  %-20s %s\n"   "Restarts:" "${restarts:-0}"
  printf "  %-20s %s\n"   "Tasks:"    "${tasks:-—}"
  printf "  %-20s %s\n"   "PID:"      "${pid:-—}"
  printf "  %-20s %s\n"   "Since:"    "${since:-—}"

  # Log file size
  local LOG="$ACCOUNTS_ROOT/$NAME/logs/beacon.log"
  if [[ -f "$LOG" ]]; then
    local log_bytes; log_bytes=$(stat -c%s "$LOG" 2>/dev/null || echo 0)
    local log_lines; log_lines=$(wc -l < "$LOG" 2>/dev/null || echo 0)
    printf "  %-20s %s (%s lines)\n" "Log file:" "$(_fmt_bytes "$log_bytes")" "$log_lines"
  else
    printf "  %-20s %s\n" "Log file:" "none yet"
  fi

  # Xvfb
  local xstate; xstate=$(systemctl is-active "teneo-xvfb@${NAME}" 2>/dev/null || echo dead)
  printf "  %-20s %s\n" "Xvfb:" "$xstate"
  echo ""
}

# ================================================================
#  WATCH — live-refresh list every N seconds
# ================================================================
cmd_watch() {
  local interval="${ARG2:-$WATCH_INTERVAL}"
  [[ "$interval" =~ ^[0-9]+$ ]] || interval=$WATCH_INTERVAL
  trap 'echo ""; exit 0' INT
  while true; do
    clear
    cmd_list
    echo -e "  ${CYAN}Refreshing every ${interval}s — Ctrl-C to exit${RESET}"
    sleep "$interval"
  done
}

# ================================================================
#  TAIL-ALL — aggregate live logs from all accounts
# ================================================================
cmd_tail_all() {
  local LOGS=()
  local D N F
  for D in "$ACCOUNTS_ROOT"/*/; do
    [[ -d "$D" ]] || continue
    N=$(basename "$D")
    F="${D}logs/beacon.log"
    [[ -f "$F" ]] && LOGS+=("$F")
  done
  if [[ ${#LOGS[@]} -eq 0 ]]; then
    info "No log files found — falling back to journalctl"
    local jctl_args=()
    for D in "$ACCOUNTS_ROOT"/*/; do
      N=$(basename "$D")
      jctl_args+=(-u "teneo-beacon@${N}")
    done
    journalctl -f --no-pager -n 50 "${jctl_args[@]}"
    return
  fi
  info "Tailing ${#LOGS[@]} log file(s) — Ctrl-C to stop"
  tail -f -n 20 "${LOGS[@]}"
}

# ================================================================
#  CHECK-PROXY — verify proxy works and show outbound IP
# ================================================================
cmd_check_proxy() {
  local NAME="${ARG2:-}"; _require_account "$NAME"
  local META="$ACCOUNTS_ROOT/$NAME/meta.env"
  local PX; PX=$(grep "^PROXY_URL=" "$META" 2>/dev/null | cut -d= -f2-)

  section "Proxy Check: ${NAME}"

  if [[ -z "$PX" ]]; then
    info "No proxy configured for '${NAME}'. Using bare server IP."
    local IP; IP=$(curl -fsSL --max-time 8 https://ifconfig.me 2>/dev/null || echo "unknown")
    echo -e "  Outbound IP: ${CYAN}${IP}${RESET}"
    return
  fi

  local REDACTED; REDACTED=$(echo "$PX" | sed 's|://[^:@]*:[^@]*@|://***@|')
  info "Testing proxy: ${REDACTED}"

  local START; START=$(date +%s%3N)
  local IP; IP=$(curl -fsSL --proxy "$PX" --max-time 15 https://ifconfig.me 2>/dev/null || true)
  local LATENCY=$(( $(date +%s%3N) - START ))

  if [[ -n "$IP" ]]; then
    success "Proxy reachable"
    echo -e "  Outbound IP:  ${CYAN}${IP}${RESET}"
    echo -e "  Latency:      ${LATENCY}ms"
  else
    warn "Proxy unreachable or returned no IP — check credentials and host"
  fi
}

# ================================================================
#  SET-PROXY — update proxy for an existing account
# ================================================================
cmd_set_proxy() {
  local NAME="${ARG2:-}"; _require_account "$NAME"
  require_sudo; _acquire_lock
  section "Set Proxy: ${NAME}"

  local NEW_PROXY="${ARG3:-}"
  if [[ -z "$NEW_PROXY" ]]; then
    echo -e "  Formats: ${CYAN}http://host:port${RESET}  |  ${CYAN}http://user:pass@host:port${RESET}  |  ${CYAN}socks5://user:pass@host:port${RESET}"
    echo -e "  Leave blank to remove proxy."
    read -rp "  New proxy URL: " NEW_PROXY
  fi

  if [[ -n "$NEW_PROXY" ]]; then
    validate_proxy_url "$NEW_PROXY"
    check_proxy_unique "$NEW_PROXY" "$NAME"   # skip self — account already owns its own proxy
  fi

  local META="$ACCOUNTS_ROOT/$NAME/meta.env"
  if [[ "$DRY_RUN" != true ]]; then
    _kv_set "$META" "PROXY_URL" "$NEW_PROXY"
    # Regenerate service unit with new proxy
    local ACCT_NAME="$NAME"
    local ACCT_DIR="$ACCOUNTS_ROOT/$NAME"
    local DISP_NUM; DISP_NUM=$(grep "^DISPLAY_NUM=" "$META" | cut -d= -f2)
    local DISPLAY_ID=":${DISP_NUM}"
    local JITTER;   JITTER=$(grep  "^JITTER_SEC="  "$META" | cut -d= -f2)
    local PROXY_BLOCK=""
    if [[ -n "$NEW_PROXY" ]]; then
      PROXY_BLOCK="Environment=http_proxy=${NEW_PROXY}
Environment=https_proxy=${NEW_PROXY}
Environment=HTTP_PROXY=${NEW_PROXY}
Environment=HTTPS_PROXY=${NEW_PROXY}
Environment=ALL_PROXY=${NEW_PROXY}
Environment=no_proxy=localhost,127.0.0.1,::1"
    fi
    resolve_binary
    _write_service_units
    run_sudo systemctl daemon-reload
    run_sudo systemctl restart "teneo-beacon@${NAME}" 2>/dev/null || true
    local REDACTED; REDACTED=$(echo "${NEW_PROXY:-none}" | sed 's|://[^:@]*:[^@]*@|://***@|')
    success "Proxy updated to: ${REDACTED}"
  else
    local REDACTED; REDACTED=$(echo "${NEW_PROXY:-none}" | sed 's|://[^:@]*:[^@]*@|://***@|')
    echo -e "  ${YELLOW}[DRY-RUN]${RESET} Would update proxy to ${REDACTED} and restart beacon@${NAME}"
  fi
}

# ================================================================
#  DOCTOR — full system health check
# ================================================================
cmd_doctor() {
  section "System Health Check"
  local PASS=0 WARN=0 FAIL=0
  local OK="${GREEN}✓${RESET}" WN="${YELLOW}⚠${RESET}" NG="${RED}✗${RESET}"

  _chk() {
    local label="$1" status="$2" detail="${3:-}"
    local icon
    case "$status" in
      ok)   icon="$OK"; PASS=$(( PASS+1 )) ;;
      warn) icon="$WN"; WARN=$(( WARN+1 )) ;;
      fail) icon="$NG"; FAIL=$(( FAIL+1 )) ;;
    esac
    printf "  %b  %-40s %s\n" "$icon" "$label" "${detail}"
  }

  # Binary
  if command -v teneo-beacon &>/dev/null; then
    _chk "teneo-beacon binary" ok "$(command -v teneo-beacon)"
  else
    _chk "teneo-beacon binary" fail "not found — run: sudo $0 install"
  fi

  # Version
  local ver; ver=$(cat "$VERSION_FILE" 2>/dev/null || echo "unknown")
  _chk "Installed version" ok "$ver"

  # Dependencies
  local dep missing_deps=0
  for dep in curl jq xvfb-run flock systemctl ufw fail2ban; do
    command -v "$dep" &>/dev/null || { missing_deps=$(( missing_deps+1 )); }
  done
  if (( missing_deps == 0 )); then
    _chk "Runtime dependencies" ok "all present"
  else
    _chk "Runtime dependencies" warn "${missing_deps} missing — run: $0 deps"
  fi

  # Disk space
  local avail_usr; avail_usr=$(df /usr --output=avail -m 2>/dev/null | tail -1 | tr -d ' ')
  if (( ${avail_usr:-0} >= 500 )); then
    _chk "Disk space (/usr)" ok "${avail_usr} MB free"
  elif (( ${avail_usr:-0} >= 200 )); then
    _chk "Disk space (/usr)" warn "${avail_usr} MB free — low"
  else
    _chk "Disk space (/usr)" fail "${avail_usr:-?} MB free — critical"
  fi

  # Network
  if curl -fsSL --max-time 8 https://api.github.com -o /dev/null 2>/dev/null; then
    _chk "Network (GitHub)" ok "reachable"
  else
    _chk "Network (GitHub)" fail "unreachable"
  fi

  # UFW
  if run_sudo ufw status 2>/dev/null | grep -q "Status: active"; then
    _chk "UFW firewall" ok "active"
  else
    _chk "UFW firewall" warn "inactive — run: sudo $0 harden"
  fi

  # fail2ban
  if systemctl is-active --quiet fail2ban 2>/dev/null; then
    _chk "fail2ban" ok "running"
  else
    _chk "fail2ban" warn "not running"
  fi

  # auditd
  if systemctl is-active --quiet auditd 2>/dev/null; then
    _chk "auditd" ok "running"
  else
    _chk "auditd" warn "not running"
  fi

  # systemd-resolved
  if systemctl is-active --quiet systemd-resolved 2>/dev/null; then
    _chk "systemd-resolved (DoT)" ok "running"
  else
    _chk "systemd-resolved (DoT)" warn "not running"
  fi

  # AppArmor
  if command -v aa-status &>/dev/null; then
    if run_sudo aa-status --enabled 2>/dev/null; then
      _chk "AppArmor" ok "enforcing"
    else
      _chk "AppArmor" warn "not enforcing"
    fi
  else
    _chk "AppArmor" warn "not installed"
  fi

  # unattended-upgrades
  if systemctl is-enabled --quiet unattended-upgrades 2>/dev/null; then
    _chk "Auto security updates" ok "enabled"
  else
    _chk "Auto security updates" warn "disabled"
  fi

  # resolv.conf symlink
  local STUB="/run/systemd/resolve/stub-resolv.conf"
  if [[ "$(readlink /etc/resolv.conf 2>/dev/null)" == "$STUB" ]]; then
    _chk "resolv.conf (DNS-over-TLS)" ok "stub linked"
  else
    _chk "resolv.conf (DNS-over-TLS)" warn "not linked — DoT may be bypassed"
  fi

  # Per-account checks
  echo ""
  echo -e "  ${BOLD}Account Status:${RESET}"
  local D N any_acct=false
  for D in "$ACCOUNTS_ROOT"/*/; do
    [[ -d "$D" ]] || continue
    N=$(basename "$D"); any_acct=true
    local bstate; bstate=$(systemctl is-active "teneo-beacon@${N}" 2>/dev/null || echo dead)
    local xstate; xstate=$(systemctl is-active "teneo-xvfb@${N}"   2>/dev/null || echo dead)
    local restarts; restarts=$(systemctl show "teneo-beacon@${N}" \
      --property=NRestarts 2>/dev/null | cut -d= -f2)

    local acct_status="ok"
    [[ "$bstate" != "active" ]] && acct_status="fail"
    [[ "$acct_status" == "ok" && "${restarts:-0}" -gt 10 ]] && acct_status="warn"

    _chk "  Account: ${N}" "$acct_status" \
      "beacon=${bstate} xvfb=${xstate} restarts=${restarts:-0}"

    # Proxy connectivity
    local PX; PX=$(grep "^PROXY_URL=" "${D}meta.env" 2>/dev/null | cut -d= -f2-)
    if [[ -n "$PX" ]]; then
      if curl -fsSL --proxy "$PX" --max-time 10 https://ifconfig.me -o /dev/null 2>/dev/null; then
        _chk "  Proxy: ${N}" ok "reachable"
      else
        _chk "  Proxy: ${N}" fail "unreachable"
      fi
    fi

    # Log size
    local LOG="${D}logs/beacon.log"
    if [[ -f "$LOG" ]]; then
      local lsize; lsize=$(stat -c%s "$LOG" 2>/dev/null || echo 0)
      if (( lsize > 104857600 )); then  # >100MB
        _chk "  Log: ${N}" warn "$(_fmt_bytes "$lsize") — consider: $0 clean-logs ${N}"
      fi
    fi
  done
  [[ "$any_acct" == false ]] && echo -e "  ${YELLOW}  No accounts yet.${RESET}"

  # Summary
  echo ""
  hr
  local total=$(( PASS + WARN + FAIL ))
  printf "  ${BOLD}Health: %d/%d checks passed${RESET}" "$PASS" "$total"
  (( WARN > 0 )) && printf "  ${YELLOW}%d warning(s)${RESET}" "$WARN"
  (( FAIL > 0 )) && printf "  ${RED}%d failure(s)${RESET}" "$FAIL"
  echo ""
  hr; echo ""

  if [[ "$JSON_OUT" == true ]]; then
    printf '{"pass":%d,"warn":%d,"fail":%d,"total":%d}\n' "$PASS" "$WARN" "$FAIL" "$total"
  fi
}

# ================================================================
#  SECURITY-STATUS — summary of all hardening layers
# ================================================================
cmd_security_status() {
  section "Security Status"

  # UFW
  echo -e "  ${BOLD}[1] UFW Firewall${RESET}"
  if run_sudo ufw status verbose 2>/dev/null | grep -q "Status: active"; then
    run_sudo ufw status numbered 2>/dev/null | head -20 | sed 's/^/    /'
  else
    echo -e "    ${RED}inactive${RESET}"
  fi
  echo ""

  # fail2ban
  echo -e "  ${BOLD}[2] fail2ban Jails${RESET}"
  if systemctl is-active --quiet fail2ban 2>/dev/null; then
    run_sudo fail2ban-client status 2>/dev/null | grep "Jail list" | sed 's/^/    /'
    run_sudo fail2ban-client status sshd 2>/dev/null \
      | grep -E 'Banned IP|Currently banned|Total banned' | sed 's/^/    /' || true
  else
    echo -e "    ${RED}fail2ban not running${RESET}"
  fi
  echo ""

  # SSH
  echo -e "  ${BOLD}[3] SSH Config${RESET}"
  local sshd_conf="/etc/ssh/sshd_config.d/99-teneo-harden.conf"
  if [[ -f "$sshd_conf" ]]; then
    grep -E 'PasswordAuth|PermitRoot|X11Forward|AllowAgent|KbdInter' "$sshd_conf" \
      2>/dev/null | sed 's/^/    /' || true
  else
    echo -e "    ${YELLOW}Teneo SSH hardening config not found${RESET}"
  fi
  echo ""

  # AppArmor
  echo -e "  ${BOLD}[9] AppArmor${RESET}"
  if command -v aa-status &>/dev/null; then
    run_sudo aa-status 2>/dev/null | grep -E 'profiles.*enforce|teneo' | sed 's/^/    /' || true
  else
    echo -e "    ${YELLOW}not installed${RESET}"
  fi
  echo ""

  # auditd
  echo -e "  ${BOLD}[12] auditd${RESET}"
  if systemctl is-active --quiet auditd 2>/dev/null; then
    echo -e "    ${GREEN}running${RESET}"
    run_sudo auditctl -l 2>/dev/null | grep -c "watch\|-a" \
      | xargs -I{} echo "    {} active rules" || true
  else
    echo -e "    ${RED}not running${RESET}"
  fi
  echo ""

  # Auto-updates
  echo -e "  ${BOLD}[11] Automatic Updates${RESET}"
  if systemctl is-enabled --quiet unattended-upgrades 2>/dev/null; then
    echo -e "    ${GREEN}enabled${RESET}"
  else
    echo -e "    ${YELLOW}disabled${RESET}"
  fi
  echo ""

  # DNS-over-TLS
  echo -e "  ${BOLD}[10] DNS-over-TLS${RESET}"
  if systemctl is-active --quiet systemd-resolved 2>/dev/null; then
    local dot_conf="/etc/systemd/resolved.conf.d/dot.conf"
    if [[ -f "$dot_conf" ]]; then
      grep -E 'DNSOverTLS|DNSSEC|DNS=' "$dot_conf" | sed 's/^/    /'
    else
      echo -e "    ${YELLOW}resolved running but DoT not configured${RESET}"
    fi
  else
    echo -e "    ${YELLOW}systemd-resolved not running${RESET}"
  fi
}

# ================================================================
#  AUDIT-REPORT — recent events from auditd + journalctl
# ================================================================
cmd_audit_report() {
  section "Audit Report (last 24h)"
  local SINCE
  SINCE="$(date -d '24 hours ago' '+%Y-%m-%d %H:%M:%S' 2>/dev/null || date '+%Y-%m-%d %H:%M:%S')"
  # ausearch uses MM/DD/YYYY HH:MM:SS format, not ISO — compute separately
  local AUSEARCH_SINCE
  AUSEARCH_SINCE="$(date -d '24 hours ago' '+%m/%d/%Y %H:%M:%S' 2>/dev/null || echo 'yesterday')"

  if ! command -v ausearch &>/dev/null; then
    warn "ausearch not found — install auditd for full audit reports"
    info "Falling back to journalctl SSH logins…"
    journalctl -u ssh -u sshd --since "$SINCE" --no-pager -n 50 2>/dev/null \
      | grep -E 'Accepted|Failed|Invalid' | sed 's/^/  /' || true
    return
  fi

  echo -e "  ${BOLD}Recent login attempts:${RESET}"
  journalctl -u ssh -u sshd --since "$SINCE" --no-pager 2>/dev/null \
    | grep -E 'Accepted|Failed|Invalid' | tail -20 | sed 's/^/    /' || true
  echo ""

  echo -e "  ${BOLD}Privilege escalations (euid→0):${RESET}"
  run_sudo ausearch -k priv_exec --start "$AUSEARCH_SINCE" 2>/dev/null \
    | grep 'comm=' | tail -20 | sed 's/^/    /' || echo "    none"
  echo ""

  echo -e "  ${BOLD}Identity file changes (/etc/passwd, /etc/shadow, /etc/group):${RESET}"
  run_sudo ausearch -k identity --start "$AUSEARCH_SINCE" 2>/dev/null \
    | grep 'name=' | tail -20 | sed 's/^/    /' || echo "    none"
  echo ""

  echo -e "  ${BOLD}Sudoers changes:${RESET}"
  run_sudo ausearch -k sudoers --start "$AUSEARCH_SINCE" 2>/dev/null \
    | grep 'name=' | tail -10 | sed 's/^/    /' || echo "    none"
  echo ""

  echo -e "  ${BOLD}SSH config changes:${RESET}"
  run_sudo ausearch -k sshd_config --start "$AUSEARCH_SINCE" 2>/dev/null \
    | grep 'name=' | tail -10 | sed 's/^/    /' || echo "    none"
  echo ""

  echo -e "  ${BOLD}Teneo data changes:${RESET}"
  run_sudo ausearch -k teneo_data --start "$AUSEARCH_SINCE" 2>/dev/null \
    | grep 'name=' | tail -10 | sed 's/^/    /' || echo "    none"
  echo ""

  echo -e "  ${BOLD}Kernel module loads:${RESET}"
  run_sudo ausearch -k kernel_modules --start "$AUSEARCH_SINCE" 2>/dev/null \
    | grep 'comm=' | tail -10 | sed 's/^/    /' || echo "    none"
}

# ================================================================
#  CHECK-UPDATE — check latest release without installing
# ================================================================
cmd_check_update() {
  require_jq; check_network
  detect_arch
  section "Update Check"
  local API; API=$(_curl -fsSL -H "Accept: application/vnd.github+json" "$GITHUB_API") \
    || die "GitHub API unreachable."
  local LATEST; LATEST=$(echo "$API" | jq -r '.tag_name')
  [[ -n "$LATEST" && "$LATEST" != "null" ]] || die "Could not read tag_name from GitHub API."
  local CURRENT="none"; [[ -f "$VERSION_FILE" ]] && CURRENT=$(<"$VERSION_FILE")

  if [[ "$JSON_OUT" == true ]]; then
    printf '{"current":"%s","latest":"%s","up_to_date":%s}\n' \
      "$CURRENT" "$LATEST" "$( [[ "$CURRENT" == "$LATEST" ]] && echo true || echo false )"
    return
  fi

  echo -e "  Installed: ${CYAN}${CURRENT}${RESET}"
  echo -e "  Latest:    ${CYAN}${LATEST}${RESET}"
  echo ""

  if [[ "$CURRENT" == "$LATEST" ]]; then
    success "Already on latest version."
  else
    warn "Update available: ${CURRENT} → ${LATEST}"
    echo -e "  Run: ${CYAN}sudo $0 update${RESET}"
    # Show release notes excerpt
    local body; body=$(echo "$API" | jq -r '.body // ""' | head -20)
    if [[ -n "$body" && "$body" != "null" ]]; then
      echo ""
      echo -e "  ${BOLD}Release notes (excerpt):${RESET}"
      echo "$body" | head -10 | sed 's/^/    /'
    fi
  fi
}

# ================================================================
#  VERIFY — re-verify installed binary via dpkg
# ================================================================
cmd_verify() {
  section "Binary Verification"
  if ! command -v teneo-beacon &>/dev/null; then
    die "teneo-beacon not installed."
  fi
  local BIN; BIN=$(command -v teneo-beacon)
  info "Verifying: ${BIN}"

  # dpkg verify checks file hashes against package database
  local PKG; PKG=$(dpkg -S "$BIN" 2>/dev/null | cut -d: -f1 || true)
  if [[ -n "$PKG" ]]; then
    if run_sudo dpkg --verify "$PKG" 2>/dev/null; then
      success "dpkg integrity check passed for package '${PKG}'"
    else
      warn "dpkg reports modified files in '${PKG}' — consider reinstalling"
    fi
  else
    warn "Binary not tracked by dpkg — cannot verify via package database"
    info "SHA256: $(sha256sum "$BIN" 2>/dev/null | awk '{print $1}')"
  fi
}

# ================================================================
#  OFFLINE-INSTALL — install from a local .deb file
# ================================================================
cmd_offline_install() {
  local DEB_PATH="${ARG2:-}"
  [[ -n "$DEB_PATH" ]] || die "Usage: sudo $0 offline-install <path/to/teneo-beacon.deb>"
  [[ -f "$DEB_PATH" ]] || die "File not found: ${DEB_PATH}"
  [[ "$DEB_PATH" == *.deb ]] || die "Expected a .deb file, got: ${DEB_PATH}"
  require_sudo; detect_ubuntu; _acquire_lock
  section "Offline Install"

  info "Installing from: ${DEB_PATH}"
  local DPKG_ERR; DPKG_ERR=$(mktemp /tmp/teneo-dpkg-XXXXXX.err)
  _TMP_FILES+=("$DPKG_ERR")
  _exec run_sudo dpkg -i "$DEB_PATH" 2>"$DPKG_ERR" || {
    _exec run_sudo apt-get install -f -y -qq
    _exec run_sudo dpkg -i "$DEB_PATH" 2>>"$DPKG_ERR" || { cat "$DPKG_ERR"; die "Installation failed."; }
  }
  # Extract version tag from filename if possible, else from binary
  local TAG; TAG=$(dpkg-deb -f "$DEB_PATH" Version 2>/dev/null || echo "local")
  mkdir -p "$META_DIR"
  [[ "$DRY_RUN" != true ]] && _write_atomic "$VERSION_FILE" "$TAG"
  resolve_binary
  success "Offline install complete: ${APP_BINARY} (${TAG})"
}

# ================================================================
#  BACKUP — archive all account configs and meta
# ================================================================
cmd_backup() {
  local OUT="${ARG2:-}"
  [[ -z "$OUT" ]] && OUT="$REAL_HOME/teneo-backup-$(date +%Y%m%d-%H%M%S).tar.gz"
  section "Backup"
  info "Creating backup: ${OUT}"

  if [[ "$DRY_RUN" == true ]]; then
    echo -e "  ${YELLOW}[DRY-RUN]${RESET} Would archive ${REAL_HOME}/.teneo → ${OUT}"
    return
  fi

  # Include account configs, meta, and service unit files
  local TMP_DIR; TMP_DIR=$(mktemp -d /tmp/teneo-backup-XXXXXX)
  _TMP_FILES+=("$TMP_DIR")

  cp -r "$REAL_HOME/.teneo" "$TMP_DIR/teneo-data" 2>/dev/null || true
  mkdir -p "$TMP_DIR/systemd-units"
  # Use nullglob so unmatched patterns produce an empty array, not a literal string.
  local _ng; _ng=$(shopt -p nullglob); shopt -s nullglob
  local _units=(/etc/systemd/system/teneo-*.service)
  local _rotates=(/etc/logrotate.d/teneo-beacon-*)
  eval "$_ng"   # restore original nullglob state
  mkdir -p "$TMP_DIR/systemd-units" "$TMP_DIR/logrotate"
  [[ ${#_units[@]}   -gt 0 ]] && cp "${_units[@]}"   "$TMP_DIR/systemd-units/" 2>/dev/null || true
  [[ ${#_rotates[@]} -gt 0 ]] && cp "${_rotates[@]}" "$TMP_DIR/logrotate/"    2>/dev/null || true

  tar czf "$OUT" -C "$TMP_DIR" . 2>/dev/null \
    || die "Failed to create backup archive."

  local size; size=$(_fmt_bytes "$(stat -c%s "$OUT" 2>/dev/null || echo 0)")
  success "Backup saved: ${OUT} (${size})"
  info "Restore with: sudo $0 restore ${OUT}"
}

# ================================================================
#  RESTORE — restore from a backup archive
# ================================================================
cmd_restore() {
  local ARCHIVE="${ARG2:-}"
  [[ -n "$ARCHIVE" ]] || die "Usage: sudo $0 restore <backup.tar.gz>"
  [[ -f "$ARCHIVE" ]] || die "Archive not found: ${ARCHIVE}"
  require_sudo; _acquire_lock
  section "Restore"

  # Verify archive integrity
  info "Verifying archive…"
  tar tzf "$ARCHIVE" &>/dev/null || die "Archive is corrupt or not a valid .tar.gz"
  success "Archive OK"

  warn "This will overwrite existing account configs."
  _confirm "Proceed with restore?" || { info "Aborted."; exit 0; }

  # Stop all accounts before restore
  info "Stopping all services…"
  local D N
  for D in "$ACCOUNTS_ROOT"/*/; do
    [[ -d "$D" ]] || continue
    N=$(basename "$D")
    run_sudo systemctl stop "teneo-beacon@${N}" 2>/dev/null || true
    run_sudo systemctl stop "teneo-xvfb@${N}"   2>/dev/null || true
  done

  local TMP_DIR; TMP_DIR=$(mktemp -d /tmp/teneo-restore-XXXXXX)
  _TMP_FILES+=("$TMP_DIR")

  info "Extracting archive…"
  tar xzf "$ARCHIVE" -C "$TMP_DIR" 2>/dev/null || die "Extraction failed."

  # Restore account data
  if [[ -d "$TMP_DIR/teneo-data" ]]; then
    _backup "$REAL_HOME/.teneo" 2>/dev/null || true
    cp -r "$TMP_DIR/teneo-data/." "$REAL_HOME/.teneo/" 2>/dev/null || true
    chown -R "$REAL_USER" "$REAL_HOME/.teneo" 2>/dev/null || true
  fi
  # Restore service units
  if [[ -d "$TMP_DIR/systemd-units" ]]; then
    cp "$TMP_DIR/systemd-units"/teneo-*.service /etc/systemd/system/ 2>/dev/null || true
    run_sudo systemctl daemon-reload
  fi
  # Restore logrotate
  if [[ -d "$TMP_DIR/logrotate" ]]; then
    cp "$TMP_DIR/logrotate"/teneo-beacon-* /etc/logrotate.d/ 2>/dev/null || true
  fi

  # Re-enable and start all restored accounts
  for D in "$ACCOUNTS_ROOT"/*/; do
    [[ -d "$D" ]] || continue
    N=$(basename "$D")
    run_sudo systemctl enable "teneo-xvfb@${N}"  --quiet 2>/dev/null || true
    run_sudo systemctl enable "teneo-beacon@${N}" --quiet 2>/dev/null || true
    run_sudo systemctl start  "teneo-xvfb@${N}"          2>/dev/null || true
    run_sudo systemctl start  "teneo-beacon@${N}"        2>/dev/null || true
  done

  success "Restore complete."
}

# ================================================================
#  COMPLETION — generate bash completion script
# ================================================================
cmd_completion() {
  local SCRIPT_NAME; SCRIPT_NAME=$(basename "$0")
  local OUT="${ARG2:-}"
  [[ -z "$OUT" ]] && OUT="$REAL_HOME/.bash_completion.d/teneo"

  _emit_completion() {
  cat << COMPLETION
#!/usr/bin/env bash
# Teneo Beacon — bash tab completion
# Generated by: $0 completion
# Install: mkdir -p ~/.bash_completion.d && $0 completion > ~/.bash_completion.d/teneo
#          echo 'source ~/.bash_completion.d/teneo' >> ~/.bashrc
_teneo_accounts() {
  local accts_root="\${REAL_HOME:-\$HOME}/.teneo/accounts"
  local dirs=("\$accts_root"/*/)
  local a
  for a in "\${dirs[@]}"; do [[ -d "\$a" ]] && echo "\$(basename "\$a")"; done
}
_teneo_complete() {
  local cur prev
  COMPREPLY=()
  cur="\${COMP_WORDS[COMP_CWORD]}"
  prev="\${COMP_WORDS[COMP_CWORD-1]}"
  local commands="quicksetup install add remove list logs status update harden
    pause resume restart start-all stop-all restart-all rename stats watch
    tail-all check-proxy set-proxy doctor security-status audit-report
    check-update verify offline-install backup restore completion deps
    clean-logs clean-cache notes config setup-alerts --help --version"
  local acct_cmds="remove logs status pause resume restart rename stats
    check-proxy set-proxy clean-logs clean-cache notes"
  if [[ \$COMP_CWORD -eq 1 ]]; then
    COMPREPLY=( \$(compgen -W "\$commands" -- "\$cur") )
  elif echo "\$acct_cmds" | grep -qw "\$prev"; then
    COMPREPLY=( \$(compgen -W "\$(_teneo_accounts)" -- "\$cur") )
  fi
  return 0
}
complete -F _teneo_complete ${SCRIPT_NAME}
COMPLETION
  }

  if [[ "${OUT}" == "-" ]]; then
    _emit_completion
  elif [[ -n "$OUT" ]]; then
    mkdir -p "$(dirname "$OUT")"
    _emit_completion > "$OUT" && chmod +x "$OUT" \
      && success "Completion script written: ${OUT}" \
      && info "Add to ~/.bashrc:  source ${OUT}" \
      || warn "Could not write to ${OUT}"
  else
    _emit_completion
  fi
}

# ================================================================
#  DEPS — check and report all dependencies
# ================================================================
cmd_deps() {
  section "Dependency Check"
  local OK="${GREEN}✓${RESET}" NG="${RED}✗${RESET}"
  local missing=0

  _dep() {
    local name="$1" cmd="${2:-$1}" pkg="${3:-$1}"
    if command -v "$cmd" &>/dev/null; then
      printf "  %b  %-20s %s\n" "$OK" "$name" "$(command -v "$cmd")"
    else
      printf "  %b  %-20s %s\n" "$NG" "$name" "missing — install: apt-get install $pkg"
      missing=$(( missing+1 ))
    fi
  }

  echo -e "  ${BOLD}Runtime:${RESET}"
  _dep "bash (4+)"   bash   bash
  _dep "curl"        curl   curl
  _dep "jq"          jq     jq
  _dep "Xvfb"        Xvfb   xvfb
  _dep "flock"       flock  util-linux
  _dep "systemctl"   systemctl systemd
  _dep "dpkg"        dpkg   dpkg
  _dep "sha256sum"   sha256sum coreutils
  _dep "awk"         awk    gawk
  _dep "sed"         sed    sed
  _dep "tar"         tar    tar
  echo ""

  echo -e "  ${BOLD}Security:${RESET}"
  _dep "ufw"              ufw          ufw
  _dep "fail2ban-client"  fail2ban-client fail2ban
  _dep "auditctl"         auditctl     auditd
  _dep "apparmor_parser"  apparmor_parser apparmor
  echo ""

  echo -e "  ${BOLD}Optional:${RESET}"
  _dep "bc"      bc      bc
  _dep "ausearch" ausearch auditd
  _dep "aa-status" aa-status apparmor-utils
  _dep "sendmail" sendmail sendmail
  echo ""

  if (( missing == 0 )); then
    success "All required dependencies present."
  else
    warn "${missing} missing dependency/ies — install with the commands above."
  fi
}

# ================================================================
#  CLEAN-LOGS — truncate or remove old log files
# ================================================================
cmd_clean_logs() {
  local NAME="${ARG2:-}"
  section "Clean Logs${NAME:+: ${NAME}}"

  local dirs=()
  if [[ -n "$NAME" ]]; then
    _require_account "$NAME"
    dirs+=("$ACCOUNTS_ROOT/$NAME")
  else
    for D in "$ACCOUNTS_ROOT"/*/; do [[ -d "$D" ]] && dirs+=("$D"); done
  fi

  local total_freed=0
  for D in "${dirs[@]}"; do
    local N; N=$(basename "$D")
    local LOG="${D}logs/beacon.log"
    [[ -f "$LOG" ]] || continue
    local before; before=$(stat -c%s "$LOG" 2>/dev/null || echo 0)
    if [[ "$DRY_RUN" == true ]]; then
      echo -e "  ${YELLOW}[DRY-RUN]${RESET} Would truncate ${LOG} ($(_fmt_bytes "$before"))"
    else
      # Preserve last 1000 lines; truncate the rest
      local tmp; tmp=$(mktemp "${LOG}.XXXXXX")
      tail -1000 "$LOG" > "$tmp" && mv "$tmp" "$LOG" || rm -f "$tmp"
      local after; after=$(stat -c%s "$LOG" 2>/dev/null || echo 0)
      local freed=$(( before - after ))
      total_freed=$(( total_freed + freed ))
      info "  ${N}: truncated to last 1000 lines (freed $(_fmt_bytes "$freed"))"
    fi
  done
  [[ "$DRY_RUN" != true ]] && success "Total freed: $(_fmt_bytes "$total_freed")"
}

# ================================================================
#  CLEAN-CACHE — wipe XDG cache dirs for account(s)
# ================================================================
cmd_clean_cache() {
  local NAME="${ARG2:-}"
  section "Clean Cache${NAME:+: ${NAME}}"

  local dirs=()
  if [[ -n "$NAME" ]]; then
    _require_account "$NAME"
    dirs+=("$ACCOUNTS_ROOT/$NAME")
  else
    for D in "$ACCOUNTS_ROOT"/*/; do [[ -d "$D" ]] && dirs+=("$D"); done
  fi

  for D in "${dirs[@]}"; do
    local N; N=$(basename "$D")
    local CACHE="${D}cache"
    [[ -d "$CACHE" ]] || continue
    local before; before=$(du -sb "$CACHE" 2>/dev/null | cut -f1 || echo 0)
    if [[ "$DRY_RUN" == true ]]; then
      echo -e "  ${YELLOW}[DRY-RUN]${RESET} Would clear ${CACHE} ($(_fmt_bytes "$before"))"
    else
      find "${CACHE:?}" -mindepth 1 -delete 2>/dev/null || true
      info "  ${N}: cache cleared (freed $(_fmt_bytes "$before"))"
    fi
  done
}

# ================================================================
#  NOTES — set or show a text note on an account
# ================================================================
cmd_notes() {
  local NAME="${ARG2:-}"; _require_account "$NAME"
  local META="$ACCOUNTS_ROOT/$NAME/meta.env"
  local TEXT="${ARG3:-}"
  if [[ -n "$TEXT" ]]; then
    _kv_set "$META" "NOTES" "$TEXT"
    success "Note set for '${NAME}'."
  else
    local note; note=$(grep "^NOTES=" "$META" 2>/dev/null | cut -d= -f2-)
    printf '  \033[1m%s:\033[0m %s\n' "$NAME" "${note:-no note set}"
    echo -e "  Set with: $0 notes ${NAME} \"your note here\""
  fi
}

# ================================================================
#  CONFIG — show or set global config values
# ================================================================
cmd_config() {
  local sub="${ARG2:-show}"
  local kv="${ARG3:-}"

  case "$sub" in
    show)
      section "Global Config: ${CONF_FILE}"
      if [[ -f "$CONF_FILE" ]]; then
        cat "$CONF_FILE" | sed 's/^/  /'
      else
        echo -e "  ${YELLOW}No config file yet.${RESET}"
        echo -e "  Config path: ${CONF_FILE}"
      fi
      echo ""
      echo -e "  ${BOLD}Available settings:${RESET}"
      echo -e "    WEBHOOK_URL    — POST alerts here (Discord/Slack/generic)"
      echo -e "    ALERT_EMAIL    — send email alerts (requires sendmail)"
      echo -e "    AUTO_BACKUP    — true/false: backup before updates"
      echo -e "    STAGED_UPDATE  — true/false: confirm per-account on restart-all"
      echo -e "    DEFAULT_PROXY  — pre-fill proxy prompt"
      echo -e "    TIMESTAMPS     — true/false: prefix log lines with time"
      echo -e "    WATCH_INTERVAL — seconds between watch refreshes (default: 5)"
      ;;
    set)
      [[ -n "$kv" ]] || die "Usage: $0 config set KEY=VALUE"
      mkdir -p "$(dirname "$CONF_FILE")"
      [[ -f "$CONF_FILE" ]] || touch "$CONF_FILE"
      _kv_set "$CONF_FILE" "${kv%%=*}" "${kv#*=}"
      success "Config updated."
      _load_config
      ;;
    edit)
      mkdir -p "$(dirname "$CONF_FILE")"
      [[ -f "$CONF_FILE" ]] || touch "$CONF_FILE"
      "${EDITOR:-nano}" "$CONF_FILE"
      ;;
    *)
      die "Usage: $0 config [show|set KEY=VALUE|edit]"
      ;;
  esac
}

# ================================================================
#  SETUP-ALERTS — configure crash notifications
# ================================================================
cmd_setup_alerts() {
  require_sudo
  _acquire_lock
  section "Alert Setup"
  echo -e "  Configure crash/health notifications for all beacon services."
  echo ""

  local WEBHOOK_IN="" EMAIL_IN=""
  read -rp "  Webhook URL (Discord/Slack/generic POST, blank to skip): " WEBHOOK_IN
  read -rp "  Alert email (requires sendmail/msmtp, blank to skip): " EMAIL_IN

  mkdir -p "$(dirname "$CONF_FILE")"

  if [[ -n "$WEBHOOK_IN" ]]; then
    [[ "$WEBHOOK_IN" =~ ^https?://[^[:space:]]+$ ]] \
      || warn "Webhook URL '${WEBHOOK_IN}' does not look like an https URL — proceeding anyway."
    ARG3="WEBHOOK_URL=${WEBHOOK_IN}"; ARG2="set"; cmd_config
  fi
  if [[ -n "$EMAIL_IN" ]]; then
    ARG3="ALERT_EMAIL=${EMAIL_IN}"; ARG2="set"; cmd_config
  fi

  # Create a reusable OnFailure alert handler script
  local HANDLER="/usr/local/bin/teneo-alert"
  info "Installing alert handler: ${HANDLER}"
  run_sudo tee "$HANDLER" > /dev/null << 'HANDLER_SCRIPT'
#!/usr/bin/env bash
# Called by systemd OnFailure= for teneo-beacon@* units
UNIT="${1:-unknown}"
HOST=$(hostname -f 2>/dev/null || hostname)
CONF="${SUDO_USER:-$USER}"
CONF_FILE="$(getent passwd "${SUDO_USER:-$USER}" | cut -d: -f6)/.teneo/teneo.conf"
WEBHOOK_URL=$(grep "^WEBHOOK_URL=" "$CONF_FILE" 2>/dev/null | cut -d= -f2-)
ALERT_EMAIL=$(grep "^ALERT_EMAIL=" "$CONF_FILE" 2>/dev/null | cut -d= -f2-)
MSG="[Teneo ${HOST}] Service ${UNIT} failed at $(date '+%Y-%m-%d %H:%M:%S')"
[[ -n "$WEBHOOK_URL" ]] && curl -fsSL -X POST -H "Content-Type: application/json" \
  -d "{\"text\":\"${MSG}\"}" "$WEBHOOK_URL" &>/dev/null || true
[[ -n "$ALERT_EMAIL" ]] && echo "$MSG" | mail -s "Teneo Alert: ${UNIT} failed" "$ALERT_EMAIL" &>/dev/null || true
HANDLER_SCRIPT
  run_sudo chmod +x "$HANDLER"

  # Add OnFailure= drop-in to each existing beacon service
  local D N
  for D in "$ACCOUNTS_ROOT"/*/; do
    [[ -d "$D" ]] || continue; N=$(basename "$D")
    local DROP="/etc/systemd/system/teneo-beacon@${N}.service.d"
    run_sudo mkdir -p "$DROP"
    run_sudo tee "${DROP}/alert.conf" > /dev/null << DROPIN
[Unit]
OnFailure=teneo-alert@${N}.service
DROPIN
    # Create the alert service
    run_sudo tee "/etc/systemd/system/teneo-alert@${N}.service" > /dev/null << ALERT_SVC
[Unit]
Description=Teneo alert handler for %i
[Service]
Type=oneshot
ExecStart=${HANDLER} teneo-beacon@${N}
ALERT_SVC
  done

  run_sudo systemctl daemon-reload
  success "Alert handler installed. Services will notify on crash."
  [[ -z "$WEBHOOK_IN" && -z "$EMAIL_IN" ]] && warn "No webhook or email configured — alerts will be silent."
}

# ================================================================
#  MAIN
# ================================================================
usage() {
  banner
  echo -e "  ${BOLD}★  New here? One command does everything:${RESET}"
  echo -e "  ${GREEN}sudo $0 quicksetup${RESET}   — install + harden + one account wizard"
  echo ""
  echo -e "  ${BOLD}Install & Maintain:${RESET}"
  echo -e "  ${CYAN}sudo $0 quicksetup${RESET}              — ★ full install + single account wizard"
  echo -e "  ${CYAN}sudo $0 install${RESET}                 — install binary + apply hardening"
  echo -e "  ${CYAN}sudo $0 install --local <path>${RESET}  — install from local .deb (offline)"
  echo -e "  ${CYAN}sudo $0 update${RESET}                  — upgrade binary + restart all"
  echo -e "  ${CYAN}sudo $0 update --staged${RESET}         — upgrade, confirm each account restart"
  echo -e "  ${CYAN}sudo $0 harden${RESET}                  — re-apply system hardening only"
  echo -e "  ${CYAN}     $0 check-update${RESET}            — check for new release (no install)"
  echo -e "  ${CYAN}     $0 verify${RESET}                  — verify installed binary integrity"
  echo -e "  ${CYAN}sudo $0 offline-install <deb>${RESET}   — install from a local .deb file"
  echo ""
  echo -e "  ${BOLD}Account Control:${RESET}"
  echo -e "  ${CYAN}sudo $0 add${RESET}                     — add another isolated account"
  echo -e "  ${CYAN}sudo $0 remove <name>${RESET}           — permanently remove an account"
  echo -e "  ${CYAN}sudo $0 rename <old> <new>${RESET}      — rename an account"
  echo -e "  ${CYAN}sudo $0 pause  <name>${RESET}           — stop (keep enabled for next boot)"
  echo -e "  ${CYAN}sudo $0 resume <name>${RESET}           — start a paused account"
  echo -e "  ${CYAN}sudo $0 restart <name>${RESET}          — restart one account"
  echo -e "  ${CYAN}sudo $0 start-all${RESET}               — start all accounts"
  echo -e "  ${CYAN}sudo $0 stop-all${RESET}                — stop all accounts"
  echo -e "  ${CYAN}sudo $0 restart-all${RESET}             — restart all accounts"
  echo ""
  echo -e "  ${BOLD}Monitoring:${RESET}"
  echo -e "  ${CYAN}     $0 list${RESET}                    — status of all accounts (memory/uptime/rst)"
  echo -e "  ${CYAN}     $0 list --json${RESET}             — machine-readable JSON output"
  echo -e "  ${CYAN}     $0 list --filter active${RESET}    — show only active/dead accounts"
  echo -e "  ${CYAN}     $0 watch${RESET}                   — live-refresh list (Ctrl-C to exit)"
  echo -e "  ${CYAN}     $0 stats <name>${RESET}            — detailed per-account resource stats"
  echo -e "  ${CYAN}     $0 status <name>${RESET}           — systemd unit status"
  echo -e "  ${CYAN}     $0 logs <name>${RESET}             — tail live logs"
  echo -e "  ${CYAN}     $0 tail-all${RESET}                — aggregate logs from all accounts"
  echo ""
  echo -e "  ${BOLD}Proxy:${RESET}"
  echo -e "  ${CYAN}     $0 check-proxy <name>${RESET}      — verify proxy and show outbound IP"
  echo -e "  ${CYAN}sudo $0 set-proxy <name> [url]${RESET}  — update proxy for an account"
  echo ""
  echo -e "  ${BOLD}Diagnostics:${RESET}"
  echo -e "  ${CYAN}     $0 doctor${RESET}                  — full system health check"
  echo -e "  ${CYAN}     $0 security-status${RESET}         — all hardening layers at a glance"
  echo -e "  ${CYAN}     $0 audit-report${RESET}            — recent security events"
  echo -e "  ${CYAN}     $0 deps${RESET}                    — check all dependencies"
  echo ""
  echo -e "  ${BOLD}Data:${RESET}"
  echo -e "  ${CYAN}     $0 backup [file]${RESET}           — archive all account data"
  echo -e "  ${CYAN}sudo $0 restore <file>${RESET}          — restore from backup"
  echo -e "  ${CYAN}     $0 clean-logs [name]${RESET}       — truncate old log files"
  echo -e "  ${CYAN}     $0 clean-cache [name]${RESET}      — clear XDG cache dirs"
  echo -e "  ${CYAN}     $0 notes <name> [text]${RESET}     — set or show account notes"
  echo ""
  echo -e "  ${BOLD}Configuration:${RESET}"
  echo -e "  ${CYAN}     $0 config show${RESET}             — show global config"
  echo -e "  ${CYAN}     $0 config set KEY=VALUE${RESET}    — set a config value"
  echo -e "  ${CYAN}     $0 config edit${RESET}             — open config in editor"
  echo -e "  ${CYAN}sudo $0 setup-alerts${RESET}            — configure crash notifications"
  echo -e "  ${CYAN}     $0 completion${RESET}              — generate bash completion script"
  echo ""
  echo -e "  ${BOLD}Global Flags (before command):${RESET}"
  echo -e "  ${CYAN}--dry-run${RESET}   show what would be done    ${CYAN}--force${RESET}      skip confirmations"
  echo -e "  ${CYAN}--quiet/-q${RESET}  suppress info output       ${CYAN}--json${RESET}       machine-readable output"
  echo -e "  ${CYAN}--verbose/-v${RESET} extra detail              ${CYAN}--timestamps${RESET} prefix log lines with time"
  echo -e "  ${CYAN}--debug${RESET}     enable bash xtrace         ${CYAN}--no-color${RESET}   plain text output"
  echo -e "  ${CYAN}--version/-V${RESET} print version (${SCRIPT_VERSION})"
  echo ""
}

# ================================================================
#  SIMPLE SETUP — install binary + one account, NO hardening
# ================================================================
cmd_simple_setup() {
  require_sudo
  detect_ubuntu
  detect_arch
  _acquire_lock
  _setup_tmpfiles
  banner

  echo -e "  ${BOLD}Normal Install — Single Account (No Hardening)${RESET}"
  echo -e "  This wizard will:"
  echo -e "   ${CYAN}1.${RESET} Install the Teneo Beacon binary"
  echo -e "   ${CYAN}2.${RESET} Create and start one account as a system service"
  echo -e "  ${DIM}(Security hardening is skipped — run 'sudo $0 harden' later if needed)${RESET}"
  echo ""
  echo -e "  ${YELLOW}Requirements:${RESET} Ubuntu 20.04+, amd64 or arm64, sudo access"
  echo ""
  read -rp "  Press ENTER to begin, or Ctrl-C to cancel… "
  echo ""

  # ── Step 1: install binary ─────────────────────────────────────
  section "Step 1 / 2 — Install Binary"
  check_disk_space

  info "Updating package lists…"
  run_sudo apt-get update -qq

  local WEBKIT_PKG
  dpkg --compare-versions "$OS_VER" ge "22.04" 2>/dev/null \
    && WEBKIT_PKG="libwebkit2gtk-4.1-0" \
    || WEBKIT_PKG="libwebkit2gtk-4.0-37"

  local LIBASOUND_PKG
  dpkg --compare-versions "$OS_VER" ge "24.04" 2>/dev/null \
    && LIBASOUND_PKG="libasound2t64" \
    || LIBASOUND_PKG="libasound2"

  local DEPS=(curl jq xvfb iproute2 iptables util-linux
              libgtk-3-0 "$WEBKIT_PKG"
              libayatana-appindicator3-1 librsvg2-2
              libssl3 libglib2.0-0 libnss3 libxss1 "$LIBASOUND_PKG")
  local MISSING=()
  for p in "${DEPS[@]}"; do dpkg -s "$p" &>/dev/null || MISSING+=("$p"); done
  [[ ${#MISSING[@]} -gt 0 ]] && run_sudo apt-get install -y -qq "${MISSING[@]}"

  if command -v teneo-beacon &>/dev/null; then
    local CURRENT_VER; CURRENT_VER=$(cat "$VERSION_FILE" 2>/dev/null || echo "unknown")
    warn "teneo-beacon already installed (version: ${CURRENT_VER}) — skipping download."
    resolve_binary
  else
    check_network
    require_jq

    info "Fetching latest release from GitHub…"
    local API; API=$(_curl -fsSL -H "Accept: application/vnd.github+json" "$GITHUB_API") \
      || die "GitHub API unreachable."
    local TAG DEB_URL DEB_NAME
    TAG=$(    echo "$API" | jq -r '.tag_name')
    DEB_URL=$(echo "$API" | jq -r --arg pat "$ARCH_PAT" \
      '.assets[] | select(.name | test($pat)) | .browser_download_url' | head -1)
    DEB_NAME=$(echo "$API" | jq -r --arg pat "$ARCH_PAT" \
      '.assets[] | select(.name | test($pat)) | .name' | head -1)
    [[ -n "$TAG"     && "$TAG"     != "null" ]] || die "GitHub API returned no tag_name."
    [[ -n "$DEB_URL" && "$DEB_URL" != "null" ]] || die "No ${ARCH_PAT} .deb found in release ${TAG}."

    download_and_verify_deb "$DEB_URL" "$DEB_NAME" "$API"

    info "Installing .deb package…"
    local DPKG_ERR="/tmp/teneo-dpkg-$$.err"
    run_sudo dpkg -i "$DEB_CACHE" 2>"$DPKG_ERR" || {
      run_sudo apt-get install -f -y -qq
      run_sudo dpkg -i "$DEB_CACHE" 2>>"$DPKG_ERR" || { cat "$DPKG_ERR"; die "Package installation failed."; }
    }

    mkdir -p "$META_DIR"
    chown "$REAL_USER" "$REAL_HOME/.teneo" "$META_DIR" 2>/dev/null || true
    _write_atomic "$VERSION_FILE" "$TAG"
    chown "$REAL_USER" "$VERSION_FILE" 2>/dev/null || true
    resolve_binary
    success "Teneo Beacon ${TAG} installed → ${APP_BINARY}"
  fi

  # ── Step 2: account setup ──────────────────────────────────────
  section "Step 2 / 2 — Account Setup"

  local ACCT_NAME="main"
  local RAW_NAME="" INPUT_NAME=""
  read -rp "  Account name [default: main]: " RAW_NAME
  INPUT_NAME="${RAW_NAME//[^a-zA-Z0-9_-]/}"
  if [[ -n "$RAW_NAME" && -z "$INPUT_NAME" ]]; then
    warn "Name '${RAW_NAME}' contains only invalid characters — falling back to: main"
  elif [[ -n "$INPUT_NAME" ]]; then
    ACCT_NAME="$INPUT_NAME"
    [[ "$INPUT_NAME" != "$RAW_NAME" ]] && warn "Name sanitised: '${RAW_NAME}' → '${INPUT_NAME}'"
  fi
  [[ ${#ACCT_NAME} -ge 2  ]] || die "Account name must be at least 2 characters."
  [[ ${#ACCT_NAME} -le 32 ]] || die "Account name must be 32 characters or fewer."
  info "Account name: ${ACCT_NAME}"

  if [[ -d "$ACCOUNTS_ROOT/$ACCT_NAME" ]]; then
    warn "Account '${ACCT_NAME}' already exists — skipping creation."
    warn "Use '$0 list' to see status, or '$0 remove ${ACCT_NAME}' to reset it."
  else
    echo ""
    echo -e "  Proxy formats: ${CYAN}http://host:port${RESET}  |  ${CYAN}http://user:pass@host:port${RESET}  |  ${CYAN}socks5://user:pass@host:port${RESET}"
    echo -e "  ${DIM}Leave blank to use the server's bare IP (fine for a single account).${RESET}"
    echo ""
    local PROXY_URL=""
    read -rp "  Proxy URL [leave blank to skip]: " PROXY_URL
    if [[ -n "$PROXY_URL" ]]; then
      validate_proxy_url "$PROXY_URL"
      check_proxy_unique "$PROXY_URL"
    else
      info "No proxy — using server's bare IP."
    fi

    local DISP_NUM; DISP_NUM=$(_next_display)
    local DISPLAY_ID=":${DISP_NUM}"
    local ACCT_DIR="$ACCOUNTS_ROOT/$ACCT_NAME"
    local JITTER=3

    mkdir -p "$ACCT_DIR"/{config,data,cache,logs,run}
    chmod 700 "$ACCT_DIR" "$ACCT_DIR"/{config,data,cache,logs,run}

    {
      printf 'ACCT_NAME=%s\n'  "$ACCT_NAME"
      printf 'DISPLAY_NUM=%s\n' "$DISP_NUM"
      printf 'PROXY_URL=%s\n'  "$PROXY_URL"
      printf 'JITTER_SEC=%s\n' "$JITTER"
      printf 'CREATED=%s\n'    "$(date '+%Y-%m-%d %H:%M:%S')"
    } | _write_atomic "$ACCT_DIR/meta.env"
    chmod 600 "$ACCT_DIR/meta.env"
    chown -R "$REAL_USER" "$ACCT_DIR"

    local PROXY_BLOCK=""
    if [[ -n "$PROXY_URL" ]]; then
      PROXY_BLOCK="Environment=http_proxy=${PROXY_URL}
Environment=https_proxy=${PROXY_URL}
Environment=HTTP_PROXY=${PROXY_URL}
Environment=HTTPS_PROXY=${PROXY_URL}
Environment=ALL_PROXY=${PROXY_URL}
Environment=no_proxy=localhost,127.0.0.1,::1"
    fi

    _write_service_units

    run_sudo systemctl daemon-reload
    run_sudo systemctl enable "teneo-xvfb@${ACCT_NAME}"  --quiet
    run_sudo systemctl enable "teneo-beacon@${ACCT_NAME}" --quiet
    run_sudo systemctl start  "teneo-xvfb@${ACCT_NAME}"
    _wait_for_service "teneo-xvfb@${ACCT_NAME}"  30 || warn "Xvfb may still be starting"
    run_sudo systemctl start  "teneo-beacon@${ACCT_NAME}"
    _wait_for_service "teneo-beacon@${ACCT_NAME}" 60 || warn "Beacon may still be starting"

    success "Account '${ACCT_NAME}' created and running"
  fi

  # ── Done ───────────────────────────────────────────────────────
  section "All Done!"
  local SERVER_IP; SERVER_IP=$(hostname -I 2>/dev/null | awk '{print $1}' || echo "your-server")
  local ACCT_DIR="$ACCOUNTS_ROOT/$ACCT_NAME"
  local DISP_NUM; DISP_NUM=$(grep "^DISPLAY_NUM=" "$ACCT_DIR/meta.env" 2>/dev/null | cut -d= -f2 || echo "100")

  echo -e "  ${GREEN}${BOLD}✓ Teneo Beacon installed and running (no hardening applied).${RESET}"
  echo -e "  ${YELLOW}Tip:${RESET} run ${CYAN}sudo $0 harden${RESET} any time to apply the 13 security layers."
  echo ""
  echo -e "  ${BOLD}Next — authenticate once (required):${RESET}"
  echo -e "  ${CYAN}ssh user@${SERVER_IP}${RESET}"
  echo -e "  ${CYAN}DISPLAY=:${DISP_NUM} XDG_CONFIG_HOME=${ACCT_DIR}/config XDG_DATA_HOME=${ACCT_DIR}/data ${APP_BINARY}${RESET}"
  echo ""
  echo -e "  ${BOLD}Then restart to run headlessly:${RESET}"
  echo -e "  ${CYAN}sudo systemctl restart teneo-beacon@${ACCT_NAME}${RESET}"
  echo ""
  hr
  echo -e "  ${CYAN}$0 list${RESET}          — running status"
  echo -e "  ${CYAN}$0 logs ${ACCT_NAME}${RESET}   — tail live logs"
  echo -e "  ${CYAN}sudo $0 add${RESET}      — add more accounts"
  echo -e "  ${CYAN}sudo $0 harden${RESET}   — apply security hardening"
  hr
  echo ""
}

_parse_flags "$@"

# ================================================================
#  INTERACTIVE MENU — shown when no command argument is given
# ================================================================
cmd_menu() {
  local choice acct

  # Helper: pick an account name interactively from existing accounts
  _pick_account() {
    local prompt="${1:-Account name}"
    local accts=()
    local D
    for D in "$ACCOUNTS_ROOT"/*/; do [[ -d "$D" ]] && accts+=("$(basename "$D")"); done

    if [[ ${#accts[@]} -eq 0 ]]; then
      read -rp "  ${prompt}: " acct
    else
      echo ""
      echo -e "  ${BOLD}Existing accounts:${RESET}"
      local i=1
      for a in "${accts[@]}"; do
        printf "    %2d) %s\n" "$i" "$a"
        (( i++ ))
      done
      echo ""
      read -rp "  Enter account name or number: " acct
      # If numeric, resolve to name
      if [[ "$acct" =~ ^[0-9]+$ ]] && (( acct >= 1 && acct <= ${#accts[@]} )); then
        acct="${accts[$(( acct - 1 ))]}"
      fi
    fi
    echo "$acct"
  }

  while true; do
    clear
    banner
    echo -e "  ${BOLD}Select an option:${RESET}"
    echo ""
    echo -e "  ${CYAN}── Install & Setup ──────────────────${RESET}"
    echo -e "   1) Quick Setup    (install + harden + first account)"
    echo -e "   2) Normal Install (binary + single account, no hardening)"
    echo -e "   3) Install        (binary + hardening only)"
    echo -e "   4) Harden         (re-apply security hardening)"
    echo -e "   5) Update         (upgrade binary + restart all)"
    echo ""
    echo -e "  ${CYAN}── Account Management ───────────────${RESET}"
    echo -e "   6) Add account"
    echo -e "   7) Remove account"
    echo -e "   8) Rename account"
    echo -e "   9) Pause account"
    echo -e "  10) Resume account"
    echo -e "  11) Restart account"
    echo -e "  12) Start all"
    echo -e "  13) Stop all"
    echo -e "  14) Restart all"
    echo ""
    echo -e "  ${CYAN}── Monitoring ───────────────────────${RESET}"
    echo -e "  15) List accounts"
    echo -e "  16) Watch (live refresh)"
    echo -e "  17) Logs"
    echo -e "  18) Status"
    echo -e "  19) Stats"
    echo -e "  20) Tail all logs"
    echo ""
    echo -e "  ${CYAN}── Proxy ────────────────────────────${RESET}"
    echo -e "  21) Check proxy"
    echo -e "  22) Set proxy"
    echo ""
    echo -e "  ${CYAN}── Diagnostics ──────────────────────${RESET}"
    echo -e "  23) Doctor (full health check)"
    echo -e "  24) Security status"
    echo -e "  25) Audit report"
    echo -e "  26) Check for update"
    echo -e "  27) Verify binary"
    echo -e "  28) Deps check"
    echo ""
    echo -e "  ${CYAN}── Data ─────────────────────────────${RESET}"
    echo -e "  29) Backup"
    echo -e "  30) Restore"
    echo -e "  31) Clean logs"
    echo -e "  32) Clean cache"
    echo -e "  33) Notes"
    echo ""
    echo -e "  ${CYAN}── Configuration ────────────────────${RESET}"
    echo -e "  34) Config"
    echo -e "  35) Setup alerts"
    echo -e "  36) Offline install"
    echo ""
    echo -e "   q) Quit"
    echo ""
    read -rp "  Choice: " choice
    echo ""

    case "$choice" in
      1)  cmd_quicksetup ;;
      2)  cmd_simple_setup ;;
      3)  cmd_install ;;
      4)  cmd_harden ;;
      5)
          read -rp "  Staged restart (confirm each account)? (y/N): " _s
          [[ "$_s" =~ ^[Yy]$ ]] && STAGED_UPDATE=true
          cmd_update ;;
      6)  cmd_add ;;
      7)  ARG2=$(_pick_account "Account to remove"); cmd_remove ;;
      8)
          read -rp "  Old name: " ARG2
          read -rp "  New name: " ARG3
          cmd_rename ;;
      9)  ARG2=$(_pick_account "Account to pause");   cmd_pause ;;
      10) ARG2=$(_pick_account "Account to resume");  cmd_resume ;;
      11) ARG2=$(_pick_account "Account to restart"); cmd_restart ;;
      12) cmd_start_all ;;
      13) cmd_stop_all ;;
      14) cmd_restart_all ;;
      15) cmd_list ;;
      16) cmd_watch ;;
      17) ARG2=$(_pick_account "Account"); cmd_logs ;;
      18) ARG2=$(_pick_account "Account"); cmd_status ;;
      19) ARG2=$(_pick_account "Account"); cmd_stats ;;
      20) cmd_tail_all ;;
      21) ARG2=$(_pick_account "Account"); cmd_check_proxy ;;
      22) ARG2=$(_pick_account "Account"); ARG3=""; cmd_set_proxy ;;
      23) cmd_doctor ;;
      24) cmd_security_status ;;
      25) cmd_audit_report ;;
      26) cmd_check_update ;;
      27) cmd_verify ;;
      28) cmd_deps ;;
      29) ARG2=""; cmd_backup ;;
      30)
          read -rp "  Backup file path: " ARG2
          cmd_restore ;;
      31) ARG2=$(_pick_account "Account (blank for all)") || true; cmd_clean_logs ;;
      32) ARG2=$(_pick_account "Account (blank for all)") || true; cmd_clean_cache ;;
      33)
          ARG2=$(_pick_account "Account")
          read -rp "  Note text (blank to view): " ARG3
          cmd_notes ;;
      34) ARG2="show"; ARG3=""; cmd_config ;;
      35) cmd_setup_alerts ;;
      36)
          read -rp "  Path to .deb file: " ARG2
          cmd_offline_install ;;
      q|Q|quit|exit) echo ""; exit 0 ;;
      *) warn "Invalid choice: '${choice}'" ;;
    esac

    echo ""
    read -rp "  Press ENTER to return to menu…" _dummy
  done
}

case "$CMD" in
  quicksetup)      cmd_quicksetup ;;
  simple-setup)    cmd_simple_setup ;;
  install)         cmd_install ;;
  add)             cmd_add ;;
  remove)          cmd_remove "$ARG2" ;;
  rename)          cmd_rename ;;
  list)            cmd_list ;;
  logs)            cmd_logs "$ARG2" ;;
  status)          cmd_status "$ARG2" ;;
  stats)           cmd_stats ;;
  watch)           cmd_watch ;;
  tail-all)        cmd_tail_all ;;
  pause)           cmd_pause ;;
  resume)          cmd_resume ;;
  restart)         cmd_restart ;;
  start-all)       cmd_start_all ;;
  stop-all)        cmd_stop_all ;;
  restart-all)     cmd_restart_all ;;
  check-proxy)     cmd_check_proxy ;;
  set-proxy)       cmd_set_proxy ;;
  doctor)          cmd_doctor ;;
  security-status) cmd_security_status ;;
  audit-report)    cmd_audit_report ;;
  check-update)    cmd_check_update ;;
  verify)          cmd_verify ;;
  offline-install) cmd_offline_install ;;
  backup)          cmd_backup ;;
  restore)         cmd_restore ;;
  completion)      cmd_completion ;;
  deps)            cmd_deps ;;
  clean-logs)      cmd_clean_logs ;;
  clean-cache)     cmd_clean_cache ;;
  notes)           cmd_notes ;;
  config)          cmd_config ;;
  setup-alerts)    cmd_setup_alerts ;;
  update)          cmd_update ;;
  harden)          cmd_harden ;;
  --version|-V)    echo "teneo-beacon-setup v${SCRIPT_VERSION}" ;;
  --help|-h)       usage ;;
  '')              cmd_menu ;;
  *)               echo -e "${RED}[ERROR]${RESET} Unknown command: '${CMD}'" >&2; usage; exit 1 ;;
esac
