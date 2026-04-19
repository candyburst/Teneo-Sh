# Teneo Beacon — Hardened Multi-Account Manager

A production-grade, multi-account manager for the [Teneo Protocol](https://github.com/TeneoProtocolAI/teneo-node-app-release-beta) beacon node. Automates installation, account isolation, system hardening, and lifecycle management for Ubuntu 20.04+ on amd64/arm64.

---

## Features

- **One-command setup** — installs the binary, hardens the system, and launches your first account
- **Multi-account isolation** — each account runs under its own systemd unit with dedicated display, XDG dirs, and proxy
- **13-layer security hardening** — UFW, fail2ban, SSH lockdown, AppArmor, auditd, DNS-over-TLS, and more
- **Full lifecycle management** — add, remove, rename, pause, resume, restart, update
- **Live monitoring** — real-time list with memory/uptime/restart counts, per-account stats, log tailing
- **Proxy support** — per-account HTTP/HTTPS/SOCKS5 proxy with duplicate detection
- **Backup & restore** — archive all account configs and service units
- **Interactive menu** — run with no arguments for a guided terminal UI

---

## Requirements

| Requirement | Detail |
|---|---|
| OS | Ubuntu 20.04 or newer |
| Architecture | amd64 or arm64 |
| Shell | bash 4+ |
| Privileges | sudo access |

---

## Quick Start

```bash
chmod +x setup.sh
sudo ./setup.sh quicksetup
```

This single command installs the Teneo Beacon binary, applies all 13 hardening layers, and walks you through creating your first account.

**Want to skip hardening?**
```bash
sudo ./setup.sh simple-setup
```

**Interactive menu (no arguments):**
```bash
sudo ./setup.sh
```

---

## Commands

### Install & Maintain

| Command | Description |
|---|---|
| `sudo ./setup.sh quicksetup` | ★ Full install + harden + first account wizard |
| `sudo ./setup.sh simple-setup` | Install + single account, no hardening |
| `sudo ./setup.sh install` | Install binary + apply hardening |
| `sudo ./setup.sh install --local <path>` | Install from a local `.deb` file (offline) |
| `sudo ./setup.sh update` | Upgrade binary + restart all accounts |
| `sudo ./setup.sh update --staged` | Upgrade, confirm each account restart |
| `sudo ./setup.sh harden` | Re-apply system hardening only |
| `./setup.sh check-update` | Check for a new release (no install) |
| `./setup.sh verify` | Verify installed binary integrity via dpkg |
| `sudo ./setup.sh offline-install <deb>` | Install from a local `.deb` file |

### Account Control

| Command | Description |
|---|---|
| `sudo ./setup.sh add` | Add a new isolated account |
| `sudo ./setup.sh remove <n>` | Permanently remove an account |
| `sudo ./setup.sh rename <old> <new>` | Rename an account |
| `sudo ./setup.sh pause <n>` | Stop an account (stays enabled for next boot) |
| `sudo ./setup.sh resume <n>` | Start a paused account |
| `sudo ./setup.sh restart <n>` | Restart one account |
| `sudo ./setup.sh start-all` | Start all accounts |
| `sudo ./setup.sh stop-all` | Stop all accounts |
| `sudo ./setup.sh restart-all` | Restart all accounts |

### Monitoring

| Command | Description |
|---|---|
| `./setup.sh list` | Status of all accounts (memory / uptime / restarts) |
| `./setup.sh list --json` | Machine-readable JSON output |
| `./setup.sh list --filter active` | Show only active (or `dead`) accounts |
| `./setup.sh watch` | Live-refresh list (Ctrl-C to exit) |
| `./setup.sh stats <n>` | Detailed per-account resource stats |
| `./setup.sh status <n>` | Full systemd unit status |
| `./setup.sh logs <n>` | Tail live logs for an account |
| `./setup.sh tail-all` | Aggregate live logs from all accounts |

### Proxy

| Command | Description |
|---|---|
| `./setup.sh check-proxy <n>` | Verify proxy and show outbound IP |
| `sudo ./setup.sh set-proxy <n> [url]` | Update proxy for an account |

### Diagnostics

| Command | Description |
|---|---|
| `./setup.sh doctor` | Full system health check |
| `./setup.sh security-status` | All 13 hardening layers at a glance |
| `./setup.sh audit-report` | Recent security events from auditd |
| `./setup.sh deps` | Check all runtime dependencies |

### Data

| Command | Description |
|---|---|
| `./setup.sh backup [file]` | Archive all account configs and service units |
| `sudo ./setup.sh restore <file>` | Restore from a backup archive |
| `./setup.sh clean-logs [name]` | Truncate old log files (keeps last 1000 lines) |
| `./setup.sh clean-cache [name]` | Clear XDG cache directories |
| `./setup.sh notes <n> [text]` | Set or display a note on an account |

### Configuration

| Command | Description |
|---|---|
| `./setup.sh config show` | Show global config |
| `./setup.sh config set KEY=VALUE` | Set a config value |
| `./setup.sh config edit` | Open config in `$EDITOR` |
| `sudo ./setup.sh setup-alerts` | Configure crash notifications (webhook / email) |
| `./setup.sh completion` | Generate bash tab-completion script |

---

## Security Hardening (13 Layers)

Applied automatically by `install` and `harden`. Each layer can be reviewed with `./setup.sh security-status`.

| # | Layer | What it does |
|---|---|---|
| 1 | **UFW** | Deny-all inbound + rate-limited SSH (6 connections / 30s) |
| 2 | **fail2ban** | SSH jail (2h ban) + recidive re-ban (1 week) for repeat offenders |
| 3 | **SSH** | Strong ciphers/MACs/KEX, no root login, no forwarding or tunneling |
| 4 | **Login banner** | Legal warning on `/etc/issue.net` |
| 5 | **Unused services** | Disables avahi, cups, bluetooth, ModemManager |
| 6 | **Kernel sysctl** | ASLR, kptr_restrict, eBPF lockdown, TCP hardening, FS protections |
| 7 | **Core dumps** | Disabled via PAM limits + systemd coredump config |
| 8 | **/tmp** | Remounted `nosuid`, `nodev`, `noexec` |
| 9 | **AppArmor** | Enforce profile for the `teneo-beacon` binary |
| 10 | **DNS-over-TLS** | Cloudflare primary, Google fallback, DNSSEC enabled |
| 11 | **Auto-updates** | `unattended-upgrades` for automatic security patches |
| 12 | **auditd** | Syscall rules covering identity, sudo, SSH, kernel modules, time |
| 13 | **Credential store** | `700` dirs, `600` secrets, correct ownership under `~/.teneo` |

---

## Global Flags

Place these before any command:

| Flag | Description |
|---|---|
| `--dry-run` | Print actions without executing anything |
| `--quiet` / `-q` | Suppress info and success output |
| `--verbose` / `-v` | Extra debug detail |
| `--force` | Skip all y/N confirmations |
| `--json` | Machine-readable output (where supported) |
| `--timestamps` | Prefix every log line with `HH:MM:SS` |
| `--debug` | Enable `set -x` bash tracing |
| `--no-color` | Plain text output (no ANSI colours) |
| `--version` / `-V` | Print script version |

**Example:**
```bash
sudo ./setup.sh --dry-run --force update
```

---

## Configuration File

Global settings live in `~/.teneo/teneo.conf` as `KEY=VALUE` pairs.

```bash
./setup.sh config set WEBHOOK_URL=https://hooks.slack.com/...
./setup.sh config set AUTO_BACKUP=true
./setup.sh config set TIMESTAMPS=true
```

| Key | Default | Description |
|---|---|---|
| `WEBHOOK_URL` | _(empty)_ | POST crash/health alerts here (Discord, Slack, generic) |
| `ALERT_EMAIL` | _(empty)_ | Send email alerts (requires `sendmail` or `msmtp`) |
| `AUTO_BACKUP` | `false` | Automatically back up before every update |
| `STAGED_UPDATE` | `false` | Confirm each account restart during `update` / `restart-all` |
| `DEFAULT_PROXY` | _(empty)_ | Pre-fill the proxy prompt when adding accounts |
| `TIMESTAMPS` | `false` | Prefix log lines with `HH:MM:SS` |
| `WATCH_INTERVAL` | `5` | Seconds between refreshes in `watch` mode |

---

## Multi-Account & Proxy Notes

- Each account needs a **unique outbound IP** — Teneo blocks multiple accounts sharing the same IP.
- Supported proxy formats: `http://host:port`, `http://user:pass@host:port`, `socks5://user:pass@host:port`
- Duplicate proxy detection warns you before adding an account that shares an IP with an existing one.
- Each account runs under its own systemd service (`teneo-beacon@<name>`) with isolated XDG directories under `~/.teneo/accounts/<name>/`.

---

## First Login (Required After Install)

The Teneo Beacon must be authenticated once in a visible window before it can run headlessly. After installation:

```bash
# 1. On the server, launch with the account's display:
DISPLAY=:100 \
  XDG_CONFIG_HOME=~/.teneo/accounts/main/config \
  XDG_DATA_HOME=~/.teneo/accounts/main/data \
  teneo-beacon

# 2. Log in through the UI window.

# 3. Then restart as a headless service:
sudo systemctl restart teneo-beacon@main
```

`quicksetup` and `simple-setup` print the exact commands for your account at the end of the wizard.

---

## Tab Completion

```bash
./setup.sh completion > ~/.bash_completion.d/teneo
echo 'source ~/.bash_completion.d/teneo' >> ~/.bashrc
source ~/.bashrc
```

---

## License

MIT — see [LICENSE](LICENSE)
