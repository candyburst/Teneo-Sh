# Changelog

All notable changes to this project will be documented in this file.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.0.0/) and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.0.0] — 2026-04-19

### Added
- Initial release
- 13-layer security hardening (UFW, fail2ban, SSH, AppArmor, auditd, DNS-over-TLS, and more)
- Multi-account management with full systemd isolation
- Interactive menu for all operations
- Global flags: `--dry-run`, `--quiet`, `--verbose`, `--force`, `--json`, `--timestamps`, `--debug`
- Proxy support per account
- Backup and restore
- Doctor / health check command
- Audit report and security status
- Shell completion support
- Webhook and email alerting
- Staged update mode
