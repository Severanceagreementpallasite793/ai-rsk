# Contributing to ai-rsk

Thank you for your interest in contributing to ai-rsk!

## How to Contribute

### Reporting Bugs

Open an issue with:
- What you expected
- What happened instead
- Steps to reproduce
- Your environment (OS, Rust version, ai-rsk version)

### Suggesting Rules

ai-rsk detects security patterns that LLMs commonly generate. If you've found a recurring vulnerability pattern, open an issue with:
- The CWE (verified on cwe.mitre.org)
- A vulnerable code example
- A safe code example
- Why existing tools (Semgrep, Gitleaks) don't catch it

### Pull Requests

1. Fork the repository
2. Create a branch (`git checkout -b fix/my-fix`)
3. Make your changes
4. Run tests (`cargo test`)
5. Run clippy (`cargo clippy`)
6. Run formatter (`cargo fmt`)
7. Submit a PR

### Adding a New Rule

Every rule requires:
1. A YAML file in `rules/` with a verified CWE
2. A vulnerable fixture in `tests/fixtures/vulnerable/`
3. A safe fixture in `tests/fixtures/safe/`
4. Tests that prove the rule fires on vulnerable code and stays silent on safe code

**We do not accept rules without verified CWE sources.**

## Code of Conduct

Be respectful. We're here to protect people's data. That mission requires collaboration, not conflict.

## License

By contributing, you agree that your contributions will be licensed under the MIT License.
