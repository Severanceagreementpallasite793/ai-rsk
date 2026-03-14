# Architecture

ai-rsk is a single Rust binary that orchestrates three layers of security scanning.

## Scan Flow

```
ai-rsk scan [path]
  |
  +-- 1. DETECT    Identify ecosystems (JS/TS, Python, Go, Rust)
  |                by reading package.json, requirements.txt, go.mod, Cargo.toml
  |
  +-- 2. CHECK     Verify required tools are installed and up to date
  |                (Semgrep, Gitleaks, osv-scanner)
  |
  +-- 3. RUN       Execute external tools, capture output
  |                Threaded pipe reading to prevent deadlocks
  |
  +-- 4. SCAN      Apply 31 built-in YAML rules (Layer 1)
  |                Agnostic negation: project-wide, not per-file
  |
  +-- 5. ANALYZE   Project structure analysis (Layer 3)
  |                Tests, CI/CD, dead deps, documentation
  |
  +-- 6. REPORT    Unified output, markdown report
  |
  +-- 7. EXIT      0 = pass, 1 = blocked, 2 = internal error
```

## Three Layers

### Layer 1 - Built-in Rules (Regex, offline)
31 YAML rules embedded in the binary via `include_str!`. Each rule has:
- A regex pattern to detect
- Optional negation pattern (checked project-wide)
- CWE reference verified on cwe.mitre.org
- File type filters and path exclusions

These catch patterns that existing tools miss: tokens in localStorage, missing security headers, client-side auth, Bearer tokens in frontend code.

### Layer 2 - External Tools
Three universal tools, always required:
- **Semgrep** - SAST with 1000+ rules, taint analysis
- **Gitleaks** - Secrets in code and git history
- **osv-scanner** - CVE in dependencies

ai-rsk manages their installation, updates, and timeout.

### Layer 3 - Project Analysis
Reads project structure to detect:
- Missing tests, CI/CD, documentation
- Dead dependencies, deprecated packages
- Console.log without production stripping
- Duplicate HTTP clients

## Source Files

| File | Purpose |
|------|---------|
| `main.rs` | Entry point, CLI dispatch |
| `cli.rs` | Argument parsing, output formatting |
| `config.rs` | Config file loading (ai-rsk.config.yaml) |
| `detect.rs` | Ecosystem detection |
| `rules.rs` | Rule engine, agnostic negation, file scanning |
| `runner.rs` | External tool execution, pipe management |
| `tools.rs` | Tool definitions, version checking, auto-install |
| `types.rs` | Shared types (Finding, Severity, Ecosystem) |
| `analyze.rs` | Project structure analysis (Layer 3) |
| `init.rs` | Project setup (prebuild hooks, LLM config) |
| `embedded_rules.rs` | Compile-time rule embedding |

## Design Principles

- **Deterministic** - Same input = same output. No LLM, no inference, no randomness.
- **Imposition, not discipline** - LLMs don't follow advice. Exit code 1 forces action.
- **Zero runtime dependency** - Single binary. External tools are managed, not bundled.
- **Offline first** - Layer 1 works without network. Layer 2 needs network for rule updates.
