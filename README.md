# Teneo Protocol Beacon — Hardened Multi-Account Manager

A hardened, multi-account manager for the [Teneo Protocol](https://github.com/TeneoProtocolAI/teneo-node-app-release-beta) beacon node. Supports Ubuntu 20.04+ on amd64/arm64.

## Requirements

- Ubuntu 20.04+
- amd64 or arm64
- bash 4+
- sudo access

## Quick Start

```bash
chmod +x setup.sh
sudo ./setup.sh quicksetup
```

## Commands

| Command | Description |
|---|---|
| `sudo ./setup.sh quicksetup` | Full install + wizard |
| `sudo ./setup.sh install` | Install binary + harden |
| `sudo ./setup.sh add` | Add isolated account |
| `sudo ./setup.sh remove <name>` | Remove an account |
| `./setup.sh list` | Status of all accounts |
| `./setup.sh logs <name>` | Live logs for account |
| `./setup.sh status <name>` | Detailed systemd status |
| `sudo ./setup.sh update` | Upgrade binary + restart |
| `sudo ./setup.sh harden` | Re-apply hardening only |
| `./setup.sh --version` | Print version |
| `./setup.sh --help` | Print usage |

## Security Hardening (13 Layers)

| # | Layer | Details |
|---|---|---|
| 1 | UFW | Deny-all + rate-limited SSH (6 conn/30s) |
| 2 | fail2ban | SSH jail (2h) + recidive 1-week re-ban |
| 3 | SSH | Strong ciphers/MACs/KEX, no forwarding |
| 4 | Login banner | Legal warning on `/etc/issue.net` |
| 5 | Unused services | avahi, cups, bluetooth, ModemManager off |
| 6 | Kernel sysctl | ASLR, kptr_restrict, eBPF lockdown, TCP |
| 7 | Core dumps | Disabled via PAM limits + systemd |
| 8 | /tmp | Remounted nosuid, nodev, noexec |
| 9 | AppArmor | Enforce profile for teneo-beacon binary |
| 10 | DNS-over-TLS | Cloudflare primary, Google fallback, DNSSEC |
| 11 | Auto-updates | Unattended-upgrades for security patches |
| 12 | auditd | Syscall rules: identity/sudo/SSH/kernel/time |
| 13 | Credential store | 700 dirs, 600 secrets, correct ownership |

## Global Flags

```
--dry-run       Print actions without executing
--quiet / -q    Suppress info/success output
--verbose / -v  Extra detail
--force         Skip y/N confirmations
--json          Machine-readable output
--timestamps    Prefix log lines with HH:MM:SS
--debug         Enable set -x tracing
--no-color      Disable colour output
```

## License

MIT
