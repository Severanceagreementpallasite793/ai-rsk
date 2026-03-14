# Vision

## Why ai-rsk exists

AI-generated code works. It compiles, it runs, it does what you asked. But it's full of security holes.

Tokens in localStorage. No security headers. Client-side auth checks. Bearer tokens in frontend code. CORS wide open. No input validation. No rate limiting. Passwords logged to console. Dependencies with known CVEs that nobody checked.

These aren't edge cases. These are the **default patterns** that every major LLM produces, every day, in every language.

The people shipping this code aren't careless. Many of them aren't developers at all - they're entrepreneurs, designers, students, hobbyists who use AI to build things. They don't know what CSP headers are. They don't know that `localStorage.setItem('token', ...)` is a security disaster. They trust the AI, and the AI doesn't tell them.

Their users pay the price. Real people's emails, passwords, credit cards, personal data - exposed because nobody checked.

## What ai-rsk does about it

ai-rsk is a single command that stands between AI-generated code and production. It blocks the build until the code is secure.

Not with advice. Not with warnings the AI can ignore. With **exit code 1** - the build doesn't pass, the AI is forced to fix the code, and the developer's users are protected.

## Principles

**Imposition, not discipline.** An AI won't follow security advice voluntarily. It will always try to work around the problem to deliver what the user asked for. The only thing that forces action is a blocked build. Every security rule in ai-rsk is enforced by a technical mechanism, not a suggestion.

**Deterministic, not probabilistic.** ai-rsk uses regex patterns, not AI inference. Same input, same output, every time. No hallucinations, no varying results between runs. When ai-rsk says there's a problem, there is one. When it says it's clean, it is.

**One binary, zero friction.** `cargo install ai-rsk`, then `ai-rsk scan`. That's it. No config files required, no accounts, no subscriptions. The tool auto-installs what it needs (Semgrep, Gitleaks, osv-scanner) and runs everything in one pass.

**Open source, forever.** MIT license. No premium tier, no "pro" features behind a paywall. Security shouldn't be a luxury. If you're building with AI, you deserve the same protection as a Fortune 500 company.

## Who this is for

- **Non-developers building with AI** - You don't need to understand security. ai-rsk understands it for you. It tells your AI exactly what to fix and how.
- **Junior developers** - Learn security patterns by reading ai-rsk's output. Every finding explains why it's dangerous and shows the correct fix.
- **Senior developers** - Use ai-rsk as a safety net. Even experienced devs miss things when reviewing AI-generated code at speed.
- **Teams** - Put ai-rsk in your CI/CD pipeline. No insecure code gets merged, regardless of who (or what) wrote it.

## What ai-rsk is NOT

- Not a replacement for a security audit
- Not an AI tool (it scans AI-generated code, but it's deterministic software)
- Not a linter or code style enforcer
- Not commercial software with upsells

## Contributing

ai-rsk gets better when the community reports false positives, false negatives, and new vulnerability patterns. Every report makes every AI-built project safer.

See [CONTRIBUTING.md](CONTRIBUTING.md) for how to get involved.
