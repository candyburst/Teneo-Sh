# Contributing

Thank you for taking the time to contribute!

## Getting Started

1. Fork the repository and clone it locally
2. Create a branch: `git checkout -b feat/your-feature`
3. Make your changes
4. Run ShellCheck: `shellcheck setup.sh`
5. Commit using [Conventional Commits](https://www.conventionalcommits.org/): `feat:`, `fix:`, `docs:`, `chore:`
6. Push and open a Pull Request

## Guidelines

- **Keep it POSIX-safe at entry** — the script re-execs under bash, but the guard block must stay POSIX sh-compatible
- **No new external dependencies** without discussion — the goal is to work on a stock Ubuntu 20.04+ install
- **Test on both amd64 and arm64** if your change touches binary download or architecture detection
- **Document new commands** in the header block, `usage()`, and `README.md`
- **Do not commit credentials**, proxy URLs, or account data

## Reporting Bugs

Please use the [Bug Report](.github/ISSUE_TEMPLATE/bug_report.md) issue template.

## Security Issues

See [SECURITY.md](SECURITY.md) — do not open a public issue for vulnerabilities.
