use crate::detect;
use crate::types::Ecosystem;
use anyhow::{Context, Result};
use colored::Colorize;
use std::path::{Path, PathBuf};

/// Result of the init command - tracks what was created/modified.
#[derive(Debug, Default)]
pub struct InitReport {
    pub created: Vec<PathBuf>,
    pub modified: Vec<PathBuf>,
    pub warnings: Vec<String>,
    pub ecosystems: Vec<Ecosystem>,
}

/// Run the full init pipeline for a project.
pub fn run_init(project_path: &Path) -> Result<InitReport> {
    let project_path = project_path
        .canonicalize()
        .unwrap_or_else(|_| project_path.to_path_buf());

    let mut report = InitReport::default();

    // Step 1: Detect ecosystems
    let ecosystems = detect::detect_ecosystems(&project_path);
    report.ecosystems = ecosystems.clone();

    println!("{}\n", "ai-rsk init - Setting up security gate".bold());
    println!(
        "{}",
        "===================================================".dimmed()
    );

    if ecosystems.is_empty() {
        println!(
            "  {}",
            "No known ecosystem detected. Generating universal config.".yellow()
        );
    } else {
        let names: Vec<String> = ecosystems.iter().map(|e| format!("{e}")).collect();
        println!("  Ecosystems: {}", names.join(", ").cyan());
    }

    // Step 2: Generate SECURITY_RULES.md
    let security_rules_path = project_path.join("SECURITY_RULES.md");
    if !security_rules_path.exists() {
        let content = generate_security_rules();
        std::fs::write(&security_rules_path, content)
            .context("Failed to write SECURITY_RULES.md")?;
        println!("  {} Created SECURITY_RULES.md", "+".green());
        report.created.push(security_rules_path);
    } else {
        println!(
            "  {} SECURITY_RULES.md already exists - skipping",
            "~".yellow()
        );
        report
            .warnings
            .push("SECURITY_RULES.md already exists".to_string());
    }

    // Step 3: Generate LLM discipline file
    let discipline_content = generate_discipline_file(&ecosystems);
    let discipline_targets = detect_llm_targets(&project_path);

    // Wrap discipline content in markers so we can update it in existing files
    let marked_content = format!(
        "{}\n{}\n{}",
        AI_RSK_MARKER_START,
        discipline_content.trim(),
        AI_RSK_MARKER_END
    );

    for (target_path, label) in &discipline_targets {
        let full_path = project_path.join(target_path);

        // Ensure parent directory exists
        if let Some(parent) = full_path.parent()
            && !parent.exists()
        {
            std::fs::create_dir_all(parent)
                .with_context(|| format!("Failed to create directory {}", parent.display()))?;
        }

        if !full_path.exists() {
            // New file - write discipline content directly
            std::fs::write(&full_path, &marked_content)
                .with_context(|| format!("Failed to write {}", full_path.display()))?;
            println!(
                "  {} Created {} ({})",
                "+".green(),
                target_path.display(),
                label
            );
            report.created.push(full_path);
        } else {
            // File exists - inject or update the ai-rsk block
            match inject_discipline_block(&full_path, &marked_content) {
                InjectResult::Injected => {
                    println!(
                        "  {} Injected ai-rsk discipline into {} ({})",
                        "+".green(),
                        target_path.display(),
                        label
                    );
                    report.modified.push(full_path);
                }
                InjectResult::Updated => {
                    println!(
                        "  {} Updated ai-rsk discipline in {} ({})",
                        "↻".cyan(),
                        target_path.display(),
                        label
                    );
                    report.modified.push(full_path);
                }
                InjectResult::AlreadyUpToDate => {
                    println!(
                        "  {} {} already up to date ({})",
                        "~".yellow(),
                        target_path.display(),
                        label
                    );
                }
                InjectResult::Error(e) => {
                    let msg = format!("Could not inject into {}: {}", target_path.display(), e);
                    println!("  {} {}", "!".red(), msg);
                    report.warnings.push(msg);
                }
            }
        }
    }

    // Step 4: Wire prebuild script (JS ecosystem)
    if ecosystems.contains(&Ecosystem::JavaScript) {
        match wire_prebuild_js(&project_path) {
            Ok(WireResult::Added) => {
                println!("  {} Injected prebuild script in package.json", "+".green());
                report.modified.push(project_path.join("package.json"));
            }
            Ok(WireResult::AlreadyPresent) => {
                println!(
                    "  {} prebuild script already present in package.json",
                    "~".yellow()
                );
            }
            Ok(WireResult::NoScriptsSection) => {
                println!(
                    "  {} Added scripts section with prebuild in package.json",
                    "+".green()
                );
                report.modified.push(project_path.join("package.json"));
            }
            Err(e) => {
                let msg = format!("Could not wire prebuild in package.json: {e}");
                println!("  {} {}", "!".red(), msg);
                report.warnings.push(msg);
            }
        }
    }

    // Step 5: Check devDependencies placement (JS ecosystem)
    if ecosystems.contains(&Ecosystem::JavaScript) {
        match check_dev_dependencies(&project_path) {
            DepPlacement::Correct => {
                // Nothing to report - ai-rsk isn't in dependencies, which is correct
            }
            DepPlacement::InDependencies => {
                let msg = "ai-rsk (or its wrapper) found in \"dependencies\" instead of \"devDependencies\". \
                           ai-rsk is DEV ONLY and must never be in the production bundle.";
                println!("  {} {}", "!".red().bold(), msg);
                report.warnings.push(msg.to_string());
            }
            DepPlacement::NotFound => {
                // Normal case for cargo-installed ai-rsk - no npm wrapper
            }
        }
    }

    // Step 6: Ensure .ai-rsk/ is in .gitignore (report is a build artifact)
    ensure_gitignore_entry(&project_path, &mut report);

    // Step 7: Install git hooks (if .git/ exists)
    let git_dir = project_path.join(".git");
    if git_dir.is_dir() {
        let hooks_dir = git_dir.join("hooks");
        if !hooks_dir.exists() {
            std::fs::create_dir_all(&hooks_dir).context("Failed to create .git/hooks directory")?;
        }

        // Pre-commit hook
        let pre_commit_path = hooks_dir.join("pre-commit");
        match install_hook(&pre_commit_path, generate_pre_commit_hook()) {
            HookResult::Created => {
                println!("  {} Installed pre-commit hook", "+".green());
                report.created.push(pre_commit_path);
            }
            HookResult::AlreadyHasAiRsk => {
                println!(
                    "  {} pre-commit hook already contains ai-rsk - skipping",
                    "~".yellow()
                );
            }
            HookResult::ExistsWithoutAiRsk => {
                let msg = "pre-commit hook exists but does not contain ai-rsk. \
                           Add `ai-rsk scan` manually or back up and re-run init.";
                println!("  {} {}", "!".yellow(), msg);
                report.warnings.push(msg.to_string());
            }
            HookResult::Error(e) => {
                let msg = format!("Could not install pre-commit hook: {e}");
                println!("  {} {}", "!".red(), msg);
                report.warnings.push(msg);
            }
        }

        // Pre-push hook
        let pre_push_path = hooks_dir.join("pre-push");
        match install_hook(&pre_push_path, generate_pre_push_hook()) {
            HookResult::Created => {
                println!("  {} Installed pre-push hook", "+".green());
                report.created.push(pre_push_path);
            }
            HookResult::AlreadyHasAiRsk => {
                println!(
                    "  {} pre-push hook already contains ai-rsk - skipping",
                    "~".yellow()
                );
            }
            HookResult::ExistsWithoutAiRsk => {
                let msg = "pre-push hook exists but does not contain ai-rsk. \
                           Add the force-push protection manually or back up and re-run init.";
                println!("  {} {}", "!".yellow(), msg);
                report.warnings.push(msg.to_string());
            }
            HookResult::Error(e) => {
                let msg = format!("Could not install pre-push hook: {e}");
                println!("  {} {}", "!".red(), msg);
                report.warnings.push(msg);
            }
        }
    } else {
        println!(
            "  {} No .git directory found - skipping git hooks installation",
            "~".yellow()
        );
        report
            .warnings
            .push("No .git directory - git hooks not installed".to_string());
    }

    // Step 7: Summary
    println!(
        "\n{}",
        "===================================================".dimmed()
    );
    println!(
        "  {} files created, {} files modified, {} warnings",
        report.created.len().to_string().green(),
        report.modified.len().to_string().cyan(),
        if report.warnings.is_empty() {
            "0".to_string().green().to_string()
        } else {
            report.warnings.len().to_string().yellow().to_string()
        }
    );
    println!(
        "{}",
        "===================================================".dimmed()
    );

    if !report.warnings.is_empty() {
        println!("\n  {}", "Warnings:".yellow().bold());
        for w in &report.warnings {
            println!("    - {}", w);
        }
    }

    println!("\n  {}", "Next steps:".bold());
    println!("    1. Run: ai-rsk scan");
    println!("    2. Fix all BLOCK findings");
    println!("    3. Commit the generated files");
    if ecosystems.contains(&Ecosystem::JavaScript) {
        println!("    4. The prebuild script will run ai-rsk before every build");
    }

    Ok(report)
}

/// Ensure `.ai-rsk/` is listed in the project's `.gitignore`.
/// The report (.ai-rsk/report.md) is a build artifact and should not be committed.
fn ensure_gitignore_entry(project_path: &Path, report: &mut InitReport) {
    let gitignore_path = project_path.join(".gitignore");
    let entry = ".ai-rsk/";

    if gitignore_path.exists() {
        let content = match std::fs::read_to_string(&gitignore_path) {
            Ok(c) => c,
            Err(e) => {
                report
                    .warnings
                    .push(format!("Could not read .gitignore: {}", e));
                return;
            }
        };
        // Check if already present
        if content.lines().any(|line| line.trim() == entry) {
            return;
        }
        // Append
        let separator = if content.ends_with('\n') { "" } else { "\n" };
        let new_content = format!("{}{}{}\n", content, separator, entry);
        match std::fs::write(&gitignore_path, new_content) {
            Ok(()) => {
                println!("  {} Added {} to .gitignore", "+".green(), entry);
                report.modified.push(gitignore_path);
            }
            Err(e) => {
                report
                    .warnings
                    .push(format!("Could not update .gitignore: {}", e));
            }
        }
    } else {
        // Create .gitignore with the entry
        match std::fs::write(&gitignore_path, format!("{}\n", entry)) {
            Ok(()) => {
                println!("  {} Created .gitignore with {}", "+".green(), entry);
                report.created.push(gitignore_path);
            }
            Err(e) => {
                report
                    .warnings
                    .push(format!("Could not create .gitignore: {}", e));
            }
        }
    }
}

// ─────────────────────────────────────────────────
// Content generators (pure functions, testable)
// ─────────────────────────────────────────────────

/// Generate the SECURITY_RULES.md content - the LLM-facing contract.
fn generate_security_rules() -> String {
    let mut s = String::new();
    s.push_str("# SECURITY_RULES.md - ai-rsk Security Contract\n\n");
    s.push_str(
        "This file is generated by `ai-rsk init`. It is the contract between ai-rsk and any LLM\n",
    );
    s.push_str("working on this project. The LLM MUST read and follow these rules.\n\n");

    s.push_str("## What is ai-rsk?\n\n");
    s.push_str(
        "ai-rsk is a security gate installed in this project. It blocks the build (exit code 1)\n",
    );
    s.push_str(
        "when security issues are detected. You cannot skip it, remove it, or work around it.\n\n",
    );

    s.push_str("## What you MUST do\n\n");
    s.push_str("1. **Install required tools** when ai-rsk reports them missing (Semgrep, Gitleaks, osv-scanner)\n");
    s.push_str("2. **Fix all BLOCK findings** before the build can pass\n");
    s.push_str("3. **Address WARN findings** - they become BLOCK in `--strict` mode\n");
    s.push_str("4. **Read ADVISE findings** and ask the developer about them - they become BLOCK in `--full` mode\n\n");

    s.push_str("## What you MUST NOT do\n\n");
    s.push_str(
        "1. **Never remove ai-rsk** from the prebuild script, devDependencies, or CI pipeline\n",
    );
    s.push_str("2. **Never add `|| true`** after `ai-rsk scan` - this defeats the security gate\n");
    s.push_str("3. **Never use `--no-verify`** on git commits to skip security hooks\n");
    s.push_str("4. **Never add `ai-rsk-ignore`** without a genuine justification after `--`\n");
    s.push_str("5. **Never disable rules** in config without a documented reason\n");
    s.push_str(
        "6. **Never put secrets, tokens, or API keys** in source code (Gitleaks will catch them)\n",
    );
    s.push_str("7. **Never store auth tokens in localStorage** - use HttpOnly cookies\n");
    s.push_str("8. **Never trust client-side auth alone** - always verify server-side\n");
    s.push_str(
        "9. **Never log sensitive data** (req.body, tokens, passwords) even in development\n",
    );
    s.push_str(
        "10. **Never put sensitive data in JWT payloads** - JWT is signed, not encrypted\n\n",
    );

    s.push_str("## Security checklist (non-negotiable)\n\n");
    s.push_str("Every LLM generating code in this project MUST ensure:\n\n");
    s.push_str("- [ ] Access tokens are short-lived (5-15 minutes)\n");
    s.push_str("- [ ] Refresh tokens use rotation and are stored in HttpOnly cookies\n");
    s.push_str("- [ ] All cookies have HttpOnly + Secure + SameSite flags\n");
    s.push_str("- [ ] Content-Security-Policy header is set (no unsafe-inline, no unsafe-eval)\n");
    s.push_str("- [ ] HSTS header is set with appropriate max-age\n");
    s.push_str("- [ ] X-Frame-Options header is set\n");
    s.push_str("- [ ] X-Content-Type-Options: nosniff is set\n");
    s.push_str("- [ ] x-powered-by header is removed\n");
    s.push_str("- [ ] No sensitive data in JWT payload\n");
    s.push_str("- [ ] Server-side session revocation is implemented\n");
    s.push_str("- [ ] Rate limiting is in place on auth endpoints\n");
    s.push_str("- [ ] All inputs are validated server-side\n");
    s.push_str("- [ ] CORS is configured with explicit origins (no wildcard with credentials)\n");
    s.push_str("- [ ] External scripts use Subresource Integrity (SRI)\n");
    s.push_str("- [ ] Links with target=\"_blank\" have rel=\"noopener noreferrer\"\n");
    s.push_str("- [ ] Business values (prices, quantities) are validated server-side\n");
    s.push_str("- [ ] console.log is stripped in production builds\n");
    s.push_str("- [ ] Tests exist and cover security-critical paths\n");
    s.push_str("- [ ] CI/CD pipeline runs ai-rsk scan\n\n");

    s.push_str("## Working method (imposed)\n\n");
    s.push_str("1. **OBSERVE** - Read existing code before modifying anything\n");
    s.push_str("2. **UNDERSTAND** - Trace dependencies, data flows, architecture\n");
    s.push_str("3. **PLAN** - Base your plan on observed facts, not assumptions\n");
    s.push_str("4. **EXECUTE** - Apply changes surgically without breaking what works\n");
    s.push_str("5. **VERIFY** - Test and confirm the change works correctly\n\n");

    s.push_str("## Exit codes\n\n");
    s.push_str("- `0` = PASS (no security issues)\n");
    s.push_str("- `1` = BLOCKED (security issues found - fix them)\n");
    s.push_str("- `2` = INTERNAL ERROR (ai-rsk itself failed)\n\n");
    s.push_str(
        "When the build fails with exit code 1, read the output, fix the issues, and rebuild.\n",
    );
    s.push_str("Do not try to work around the failure.\n\n");

    s.push_str("---\n");
    s.push_str("*Generated by ai-rsk v0.1.0 - https://github.com/Krigsexe/ai-rsk*\n");

    s
}

/// Generate the LLM discipline file content.
/// This content is the same regardless of which LLM tool reads it.
fn generate_discipline_file(ecosystems: &[Ecosystem]) -> String {
    let mut s = String::new();
    s.push_str("# ai-rsk - LLM Security Discipline\n\n");
    s.push_str("This project is protected by ai-rsk. The build WILL NOT pass if security rules are violated.\n");
    s.push_str("Read SECURITY_RULES.md for the full contract.\n\n");

    s.push_str("## Required external tools\n\n");
    s.push_str(
        "ai-rsk requires exactly 3 external tools. The build is BLOCKED if any is missing:\n\n",
    );
    s.push_str("| Tool | Purpose | Auto-installed by ai-rsk |\n");
    s.push_str("|---|---|---|\n");
    s.push_str("| **semgrep** | Static analysis (SAST) - covers all languages | Yes |\n");
    s.push_str("| **gitleaks** | Secret detection in code and git history | Yes |\n");
    s.push_str("| **osv-scanner** | Known vulnerability detection in dependencies | Yes |\n\n");
    s.push_str("These are the ONLY tools ai-rsk requires. No other tools (ESLint, bandit, gosec, etc.) are mandatory.\n");
    s.push_str("Semgrep covers multi-language SAST with 2000+ community rules.\n\n");

    s.push_str("## CRITICAL - FIRST ACTION EVERY SESSION\n\n");
    s.push_str("**Before doing ANYTHING in this project, read `.ai-rsk/report.md`.**\n");
    s.push_str(
        "This file contains the latest security scan results. If any BLOCK findings exist,\n",
    );
    s.push_str("you MUST fix them BEFORE working on any other task. No exceptions.\n\n");
    s.push_str("After fixing findings, run `ai-rsk scan` to regenerate the report and verify all issues are resolved.\n");
    s.push_str("The build will not pass until `.ai-rsk/report.md` shows Status: PASS.\n\n");

    s.push_str("## Mandatory working method\n\n");
    s.push_str("1. READ `.ai-rsk/report.md` - check for security findings\n");
    s.push_str("2. FIX all BLOCK findings - the build is blocked until they are resolved\n");
    s.push_str("3. RUN `ai-rsk scan` - regenerate the report to confirm fixes\n");
    s.push_str("4. OBSERVE - Read existing code before modifying anything\n");
    s.push_str("5. UNDERSTAND - Trace dependencies, data flows, architecture\n");
    s.push_str("6. PLAN - Base your plan on observed facts, not assumptions\n");
    s.push_str("7. EXECUTE - Apply changes surgically without breaking what works\n");
    s.push_str("8. VERIFY - Test and confirm the change works correctly\n\n");

    s.push_str("## Security rules (build will fail if violated)\n\n");

    s.push_str("### Authentication & tokens\n");
    s.push_str(
        "- NEVER store auth tokens in localStorage or sessionStorage - use HttpOnly cookies\n",
    );
    s.push_str("- NEVER expose Bearer tokens in client-side code\n");
    s.push_str("- NEVER put sensitive data (email, password, PII) in JWT payloads\n");
    s.push_str("- Access tokens MUST be short-lived (5-15 min) with rotating refresh tokens\n\n");

    s.push_str("### Headers & transport\n");
    s.push_str("- ALWAYS set Content-Security-Policy (no unsafe-inline, no unsafe-eval)\n");
    s.push_str("- ALWAYS set Strict-Transport-Security (HSTS)\n");
    s.push_str("- ALWAYS set X-Frame-Options\n");
    s.push_str("- ALWAYS set X-Content-Type-Options: nosniff\n");
    s.push_str("- ALWAYS remove x-powered-by header\n");
    s.push_str("- External scripts MUST use integrity (SRI) attributes\n");
    s.push_str("- Links with target=\"_blank\" MUST have rel=\"noopener noreferrer\"\n\n");

    s.push_str("### Server-side\n");
    s.push_str("- ALWAYS validate inputs server-side (client validation is not enough)\n");
    s.push_str("- ALWAYS implement rate limiting on auth endpoints\n");
    s.push_str("- NEVER trust client-side auth checks alone\n");
    s.push_str("- NEVER log sensitive data (req.body, tokens, passwords, headers)\n");
    s.push_str("- Business values (prices, quantities, amounts) MUST be validated server-side\n");
    s.push_str("- WebSocket connections MUST verify authentication\n\n");

    s.push_str("### Cookies\n");
    s.push_str("- ALL session cookies MUST have HttpOnly flag\n");
    s.push_str("- ALL cookies MUST have Secure flag in production\n");
    s.push_str("- ALL cookies MUST have SameSite attribute (Strict by default, Lax only if OAuth requires it)\n\n");

    s.push_str("### Build & deployment\n");
    s.push_str("- ai-rsk MUST remain in the prebuild script - do not remove it\n");
    s.push_str("- NEVER add `|| true` after ai-rsk scan commands\n");
    s.push_str("- NEVER use `--no-verify` on git operations\n");
    s.push_str("- console.log MUST be stripped in production builds\n\n");

    s.push_str("### Code quality\n");
    s.push_str("- Run `ai-rsk scan` before committing\n");
    s.push_str("- Fix all BLOCK findings before the build can pass\n");
    s.push_str("- WARN findings become BLOCK in --strict mode\n");
    s.push_str("- Every `ai-rsk-ignore` comment MUST have a justification after `--`\n");

    // Add ecosystem-specific rules
    if ecosystems.contains(&Ecosystem::JavaScript) {
        s.push_str("\n## JavaScript/TypeScript specific\n\n");
        s.push_str("- Use `express.json({ limit: '10kb' })` or equivalent - never unlimited body parsing\n");
        s.push_str("- Semgrep covers JS/TS security (eslint-plugin-security ruleset included)\n");
        s.push_str(
            "- Use a structured logger (pino, winston) instead of console.log in production\n",
        );
        s.push_str("- Request body size limits MUST be set on all body-parsing middleware\n");
    }

    if ecosystems.contains(&Ecosystem::Python) {
        s.push_str("\n## Python specific\n\n");
        s.push_str(
            "- Semgrep covers Python security analysis (bandit equivalent via p/python ruleset)\n",
        );
        s.push_str(
            "- Never use dynamic code evaluation or unsafe deserialization with untrusted input\n",
        );
        s.push_str("- Use parameterized queries - never string concatenation for SQL\n");
    }

    if ecosystems.contains(&Ecosystem::Go) {
        s.push_str("\n## Go specific\n\n");
        s.push_str(
            "- Semgrep covers Go security analysis (gosec equivalent via p/golang ruleset)\n",
        );
        s.push_str("- Never use fmt.Sprintf for SQL queries - use parameterized queries\n");
        s.push_str("- Validate all HTTP request inputs before processing\n");
    }

    if ecosystems.contains(&Ecosystem::Rust) {
        s.push_str("\n## Rust specific\n\n");
        s.push_str("- Zero `unsafe` blocks unless absolutely necessary and documented\n");
        s.push_str("- Use cargo-audit for dependency vulnerability scanning\n");
        s.push_str("- Never use `.unwrap()` on user input - use proper error handling\n");
    }

    s.push_str("\n---\n");
    s.push_str("*Generated by ai-rsk v0.1.0 - https://github.com/Krigsexe/ai-rsk*\n");

    s
}

/// Markers delimiting the ai-rsk discipline block in LLM config files.
/// Used to inject into existing files without destroying user content.
const AI_RSK_MARKER_START: &str = "<!-- ai-rsk:start -->";
const AI_RSK_MARKER_END: &str = "<!-- ai-rsk:end -->";

#[derive(Debug, PartialEq)]
enum InjectResult {
    Injected,
    Updated,
    AlreadyUpToDate,
    Error(String),
}

/// Inject or update the ai-rsk discipline block in an existing file.
/// - If the file has no ai-rsk markers, append the block at the end.
/// - If the file has ai-rsk markers, replace the block between them.
/// - If the block is identical, do nothing.
fn inject_discipline_block(file_path: &Path, marked_content: &str) -> InjectResult {
    let existing = match std::fs::read_to_string(file_path) {
        Ok(c) => c,
        Err(e) => return InjectResult::Error(format!("Failed to read: {}", e)),
    };

    if let (Some(start), Some(end)) = (
        existing.find(AI_RSK_MARKER_START),
        existing.find(AI_RSK_MARKER_END),
    ) {
        // Markers found - extract and compare
        let end_of_marker = end + AI_RSK_MARKER_END.len();
        let current_block = &existing[start..end_of_marker];

        if current_block == marked_content {
            return InjectResult::AlreadyUpToDate;
        }

        // Replace the block
        let new_content = format!(
            "{}{}{}",
            &existing[..start],
            marked_content,
            &existing[end_of_marker..]
        );
        match std::fs::write(file_path, new_content) {
            Ok(()) => InjectResult::Updated,
            Err(e) => InjectResult::Error(format!("Failed to write: {}", e)),
        }
    } else {
        // No markers - append at the end
        let separator = if existing.ends_with('\n') {
            "\n"
        } else {
            "\n\n"
        };
        let new_content = format!("{}{}{}\n", existing, separator, marked_content);
        match std::fs::write(file_path, new_content) {
            Ok(()) => InjectResult::Injected,
            Err(e) => InjectResult::Error(format!("Failed to write: {}", e)),
        }
    }
}

/// Known LLM tool configurations.
/// Each entry: (marker to detect, file to generate, description).
/// Sources verified on primary documentation 2026-03-12.
const LLM_CONFIGS: &[(&str, &str, &str)] = &[
    // marker_dir_or_file,   output_file,                          label
    // --- Single-file formats ---
    (".claude", "CLAUDE.md", "Claude Code"),
    (".cursor", ".cursorrules", "Cursor"),
    (".windsurf", ".windsurfrules", "Windsurf"),
    (".gemini", "GEMINI.md", "Gemini CLI"),
    (".codex", "AGENTS.md", "OpenAI Codex CLI"),
    (
        ".github",
        ".github/copilot-instructions.md",
        "GitHub Copilot",
    ),
    // Zed uses .rules file (also reads .cursorrules, AGENTS.md as fallback)
    (".rules", ".rules", "Zed"),
    // Aider reads CONVENTIONS.md via .aider.conf.yml
    (".aider.conf.yml", "CONVENTIONS.md", "Aider"),
    // --- Directory-based formats (ai-rsk writes a single .md inside) ---
    (".clinerules", ".clinerules/ai-rsk.md", "Cline"),
    (".roo", ".roo/rules/ai-rsk.md", "Roo Code"),
    (".kiro", ".kiro/steering/ai-rsk.md", "Kiro"),
    (".continue", ".continue/rules/ai-rsk.md", "Continue.dev"),
    (
        ".aiassistant",
        ".aiassistant/rules/ai-rsk.md",
        "JetBrains AI",
    ),
    (".amazonq", ".amazonq/rules/ai-rsk.md", "Amazon Q"),
    (".tabnine", ".tabnine/guidelines/ai-rsk.md", "Tabnine"),
    (".augment", ".augment/rules/ai-rsk.md", "Augment Code"),
];

/// Detect which LLM discipline files should be generated based on project markers.
/// Only generates files for LLM tools that are actually detected in the project.
/// If NO LLM tool is detected, generates CLAUDE.md as a sensible default
/// (most common LLM coding tool, and CLAUDE.md is the most standard format).
fn detect_llm_targets(project_path: &Path) -> Vec<(PathBuf, &'static str)> {
    let mut targets = Vec::new();

    for &(marker, output_file, label) in LLM_CONFIGS {
        let marker_path = project_path.join(marker);
        let output_path = project_path.join(output_file);
        // Detect if the LLM tool marker directory/file exists,
        // OR if the output file already exists (user may have created it manually)
        if marker_path.exists() || output_path.exists() {
            targets.push((PathBuf::from(output_file), label));
        }
    }

    // If no LLM tool detected at all, generate CLAUDE.md as a universal default.
    // CLAUDE.md is the most widely recognized format and works with multiple tools.
    if targets.is_empty() {
        targets.push((PathBuf::from("CLAUDE.md"), "Claude Code (default)"));
    }

    targets
}

// ─────────────────────────────────────────────────
// Package.json manipulation (JS ecosystem)
// ─────────────────────────────────────────────────

#[derive(Debug, PartialEq)]
enum WireResult {
    Added,
    AlreadyPresent,
    NoScriptsSection,
}

/// Inject `"prebuild": "ai-rsk scan --strict"` into package.json scripts.
/// Uses string manipulation to avoid pulling in serde_json as a dependency.
fn wire_prebuild_js(project_path: &Path) -> Result<WireResult> {
    let pkg_path = project_path.join("package.json");
    let content = std::fs::read_to_string(&pkg_path).context("Failed to read package.json")?;

    // Check if prebuild already references ai-rsk
    if content.contains("ai-rsk") && content.contains("prebuild") {
        return Ok(WireResult::AlreadyPresent);
    }

    // Find "scripts" section
    let Some(scripts_idx) = content.find("\"scripts\"") else {
        // No scripts section - add one
        let Some(first_brace) = content.find('{') else {
            anyhow::bail!("package.json is not valid JSON - no opening brace found");
        };

        let new_content = format!(
            "{}\n  \"scripts\": {{\n    \"prebuild\": \"ai-rsk scan --strict\"\n  }},{}",
            &content[..first_brace + 1],
            &content[first_brace + 1..]
        );
        std::fs::write(&pkg_path, new_content).context("Failed to write package.json")?;
        return Ok(WireResult::NoScriptsSection);
    };

    // Find the opening '{' of the scripts object
    let after_scripts = &content[scripts_idx..];
    let Some(scripts_brace_offset) = after_scripts.find('{') else {
        anyhow::bail!("Malformed package.json - \"scripts\" has no opening brace");
    };
    let scripts_brace_pos = scripts_idx + scripts_brace_offset;

    // Check if prebuild key already exists
    if content.contains("\"prebuild\"") {
        // prebuild exists but doesn't contain ai-rsk - warn, don't overwrite
        return Ok(WireResult::AlreadyPresent);
    }

    // Insert prebuild right after the scripts opening brace
    let new_content = format!(
        "{}\n    \"prebuild\": \"ai-rsk scan --strict\",{}",
        &content[..scripts_brace_pos + 1],
        &content[scripts_brace_pos + 1..]
    );
    std::fs::write(&pkg_path, new_content).context("Failed to write package.json")?;

    Ok(WireResult::Added)
}

#[derive(Debug, PartialEq)]
enum DepPlacement {
    Correct,
    InDependencies,
    NotFound,
}

/// Check if ai-rsk (or an npm wrapper) is correctly placed in devDependencies.
fn check_dev_dependencies(project_path: &Path) -> DepPlacement {
    let pkg_path = project_path.join("package.json");
    let Ok(content) = std::fs::read_to_string(&pkg_path) else {
        return DepPlacement::NotFound;
    };

    // Check if ai-rsk appears in "dependencies" (bad)
    // Simple heuristic: find "dependencies" section that contains "ai-rsk"
    // but exclude "devDependencies"
    let has_in_deps = content.find("\"dependencies\"").and_then(|idx| {
        // Make sure this isn't "devDependencies"
        let before = if idx > 0 {
            &content[idx.saturating_sub(3)..idx]
        } else {
            ""
        };
        if before.contains("dev") || before.contains("Dev") {
            None
        } else {
            // Find the matching closing brace
            let after = &content[idx..];
            let open = after.find('{')?;
            let close = after.find('}')?;
            let section = &after[open..close + 1];
            if section.contains("ai-rsk") {
                Some(())
            } else {
                None
            }
        }
    });

    if has_in_deps.is_some() {
        DepPlacement::InDependencies
    } else {
        let has_in_dev_deps = content.contains("devDependencies") && content.contains("ai-rsk");
        if has_in_dev_deps {
            DepPlacement::Correct
        } else {
            DepPlacement::NotFound
        }
    }
}

// ─────────────────────────────────────────────────
// Git hooks
// ─────────────────────────────────────────────────

#[derive(Debug)]
enum HookResult {
    Created,
    AlreadyHasAiRsk,
    ExistsWithoutAiRsk,
    Error(String),
}

/// Install a git hook file. If the file doesn't exist, create it.
/// If it exists and already contains ai-rsk, skip.
/// If it exists without ai-rsk, warn (don't overwrite user's hook).
fn install_hook(hook_path: &Path, content: String) -> HookResult {
    if hook_path.exists() {
        match std::fs::read_to_string(hook_path) {
            Ok(existing) => {
                if existing.contains("ai-rsk") {
                    HookResult::AlreadyHasAiRsk
                } else {
                    HookResult::ExistsWithoutAiRsk
                }
            }
            Err(e) => HookResult::Error(format!("Cannot read {}: {e}", hook_path.display())),
        }
    } else {
        match std::fs::write(hook_path, &content) {
            Ok(()) => {
                // Make executable on Unix
                #[cfg(unix)]
                {
                    use std::os::unix::fs::PermissionsExt;
                    let _ =
                        std::fs::set_permissions(hook_path, std::fs::Permissions::from_mode(0o755));
                }
                HookResult::Created
            }
            Err(e) => HookResult::Error(format!("Cannot write {}: {e}", hook_path.display())),
        }
    }
}

/// Generate the pre-commit hook content.
/// Runs `ai-rsk scan` and blocks the commit if it fails.
fn generate_pre_commit_hook() -> String {
    r#"#!/bin/sh
# ai-rsk pre-commit hook - blocks commits when security issues are found.
# Installed by `ai-rsk init`. Do not remove unless you have CI/CD as a safety net.

# Check if ai-rsk is installed
if ! command -v ai-rsk >/dev/null 2>&1; then
    echo "[ai-rsk] ai-rsk not found in PATH. Install: cargo install ai-rsk"
    echo "[ai-rsk] Skipping pre-commit security check."
    exit 0
fi

echo "[ai-rsk] Running security scan before commit..."
ai-rsk scan --strict
EXIT_CODE=$?

if [ $EXIT_CODE -ne 0 ]; then
    echo ""
    echo "[ai-rsk] Commit BLOCKED - fix the security issues above."
    echo "[ai-rsk] If you believe this is a false positive, use:"
    echo "[ai-rsk]   // ai-rsk-ignore RULE_ID -- your justification"
    echo ""
    exit 1
fi

exit 0
"#
    .to_string()
}

/// Generate the pre-push hook content.
/// Blocks force-push to protected branches (main, master, production, release/*).
fn generate_pre_push_hook() -> String {
    r#"#!/bin/sh
# ai-rsk pre-push hook - blocks force-push to protected branches.
# Installed by `ai-rsk init`. Do not remove unless you have CI/CD as a safety net.

# Protected branches - force-push is blocked on these
PROTECTED_BRANCHES="main master production develop"

# Read push info from stdin (git provides: local_ref local_sha remote_ref remote_sha)
while read local_ref local_sha remote_ref remote_sha; do
    # Extract branch name from remote_ref (refs/heads/branch-name)
    remote_branch=$(echo "$remote_ref" | sed 's|refs/heads/||')

    # Check for force-push (--force or --force-with-lease)
    # Git doesn't directly tell us if --force was used, but we can detect
    # if the push would overwrite remote history by checking if remote_sha
    # is an ancestor of local_sha
    for protected in $PROTECTED_BRANCHES; do
        if [ "$remote_branch" = "$protected" ]; then
            # Check if this is a force push by seeing if remote commit is ancestor of local
            if [ "$remote_sha" != "0000000000000000000000000000000000000000" ]; then
                if ! git merge-base --is-ancestor "$remote_sha" "$local_sha" 2>/dev/null; then
                    echo ""
                    echo "[ai-rsk] BLOCKED: force-push to protected branch '$protected'"
                    echo "[ai-rsk] Force-pushing rewrites history and can destroy team work."
                    echo "[ai-rsk] Use a regular push or create a new branch."
                    echo ""
                    exit 1
                fi
            fi
        fi
    done

    # Also check release/* branches
    case "$remote_branch" in
        release/*)
            if [ "$remote_sha" != "0000000000000000000000000000000000000000" ]; then
                if ! git merge-base --is-ancestor "$remote_sha" "$local_sha" 2>/dev/null; then
                    echo ""
                    echo "[ai-rsk] BLOCKED: force-push to protected branch '$remote_branch'"
                    echo "[ai-rsk] Release branches are protected. Use a regular push."
                    echo ""
                    exit 1
                fi
            fi
            ;;
    esac
done

exit 0
"#
    .to_string()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use tempfile::TempDir;

    // ─────────────────────────────────────────────────
    // Content generation tests
    // ─────────────────────────────────────────────────

    #[test]
    fn test_security_rules_contains_key_sections() {
        let content = generate_security_rules();
        assert!(content.contains("SECURITY_RULES.md"));
        assert!(content.contains("What you MUST do"));
        assert!(content.contains("What you MUST NOT do"));
        assert!(content.contains("Security checklist"));
        assert!(content.contains("Exit codes"));
        assert!(content.contains("ai-rsk v0.1.0"));
    }

    #[test]
    fn test_security_rules_forbids_localstorage() {
        let content = generate_security_rules();
        assert!(content.contains("localStorage"));
        assert!(content.contains("HttpOnly"));
    }

    #[test]
    fn test_security_rules_forbids_contournement() {
        let content = generate_security_rules();
        assert!(content.contains("|| true"));
        assert!(content.contains("--no-verify"));
        assert!(content.contains("ai-rsk-ignore"));
    }

    #[test]
    fn test_discipline_file_universal_content() {
        let content = generate_discipline_file(&[]);
        assert!(content.contains("OBSERVE"));
        assert!(content.contains("UNDERSTAND"));
        assert!(content.contains("PLAN"));
        assert!(content.contains("VERIFY"));
        assert!(content.contains("NEVER store auth tokens in localStorage"));
        assert!(content.contains("Content-Security-Policy"));
        assert!(content.contains("HSTS"));
    }

    #[test]
    fn test_discipline_file_js_specific() {
        let content = generate_discipline_file(&[Ecosystem::JavaScript]);
        assert!(content.contains("JavaScript/TypeScript specific"));
        assert!(content.contains("express.json"));
        assert!(content.contains("Semgrep covers JS/TS security"));
        assert!(!content.contains("Python specific"));
        assert!(!content.contains("Go specific"));
        assert!(!content.contains("Rust specific"));
    }

    #[test]
    fn test_discipline_file_python_specific() {
        let content = generate_discipline_file(&[Ecosystem::Python]);
        assert!(content.contains("Python specific"));
        assert!(content.contains("Semgrep covers Python security"));
        assert!(!content.contains("JavaScript/TypeScript specific"));
    }

    #[test]
    fn test_discipline_file_go_specific() {
        let content = generate_discipline_file(&[Ecosystem::Go]);
        assert!(content.contains("Go specific"));
        assert!(content.contains("Semgrep covers Go security"));
    }

    #[test]
    fn test_discipline_file_rust_specific() {
        let content = generate_discipline_file(&[Ecosystem::Rust]);
        assert!(content.contains("Rust specific"));
        assert!(content.contains("cargo-audit"));
        assert!(content.contains("unsafe"));
    }

    #[test]
    fn test_discipline_file_multi_ecosystem() {
        let content = generate_discipline_file(&[Ecosystem::JavaScript, Ecosystem::Python]);
        assert!(content.contains("JavaScript/TypeScript specific"));
        assert!(content.contains("Python specific"));
        assert!(!content.contains("Go specific"));
        assert!(!content.contains("Rust specific"));
    }

    // ─────────────────────────────────────────────────
    // LLM target detection tests
    // ─────────────────────────────────────────────────

    #[test]
    fn test_detect_llm_targets_no_markers_defaults_to_claude() {
        let dir = TempDir::new().expect("Failed to create temp dir");
        let targets = detect_llm_targets(dir.path());
        // No LLM markers → default to CLAUDE.md
        assert_eq!(targets.len(), 1);
        assert_eq!(targets[0].0, PathBuf::from("CLAUDE.md"));
        assert!(targets[0].1.contains("default"));
    }

    #[test]
    fn test_detect_llm_targets_claude_only() {
        let dir = TempDir::new().expect("Failed to create temp dir");
        fs::create_dir(dir.path().join(".claude")).expect("Failed to create .claude");
        let targets = detect_llm_targets(dir.path());
        assert_eq!(targets.len(), 1);
        assert_eq!(targets[0].0, PathBuf::from("CLAUDE.md"));
    }

    #[test]
    fn test_detect_llm_targets_cursor_only() {
        let dir = TempDir::new().expect("Failed to create temp dir");
        fs::create_dir(dir.path().join(".cursor")).expect("Failed to create .cursor");
        let targets = detect_llm_targets(dir.path());
        // Only Cursor detected - CLAUDE.md is NOT generated (no .claude/ dir)
        assert_eq!(targets.len(), 1);
        assert!(
            targets
                .iter()
                .any(|(p, _)| p == &PathBuf::from(".cursorrules"))
        );
        assert!(
            !targets
                .iter()
                .any(|(p, _)| p == &PathBuf::from("CLAUDE.md"))
        );
    }

    #[test]
    fn test_detect_llm_targets_github_only() {
        let dir = TempDir::new().expect("Failed to create temp dir");
        fs::create_dir(dir.path().join(".github")).expect("Failed to create .github");
        let targets = detect_llm_targets(dir.path());
        assert_eq!(targets.len(), 1);
        assert!(
            targets
                .iter()
                .any(|(p, _)| p == &PathBuf::from(".github/copilot-instructions.md"))
        );
    }

    #[test]
    fn test_detect_llm_targets_windsurf() {
        let dir = TempDir::new().expect("Failed to create temp dir");
        fs::create_dir(dir.path().join(".windsurf")).expect("Failed to create .windsurf");
        let targets = detect_llm_targets(dir.path());
        assert_eq!(targets.len(), 1);
        assert!(
            targets
                .iter()
                .any(|(p, _)| p == &PathBuf::from(".windsurfrules"))
        );
    }

    #[test]
    fn test_detect_llm_targets_cline() {
        let dir = TempDir::new().expect("Failed to create temp dir");
        // Cline marker is .clinerules/ directory
        fs::create_dir(dir.path().join(".clinerules")).expect("Failed to create .clinerules");
        let targets = detect_llm_targets(dir.path());
        assert_eq!(targets.len(), 1);
        assert!(
            targets
                .iter()
                .any(|(p, _)| p == &PathBuf::from(".clinerules/ai-rsk.md"))
        );
    }

    #[test]
    fn test_detect_llm_targets_multiple() {
        let dir = TempDir::new().expect("Failed to create temp dir");
        fs::create_dir(dir.path().join(".claude")).expect("Failed to create .claude");
        fs::create_dir(dir.path().join(".cursor")).expect("Failed to create .cursor");
        fs::create_dir(dir.path().join(".github")).expect("Failed to create .github");
        let targets = detect_llm_targets(dir.path());
        assert_eq!(targets.len(), 3); // CLAUDE.md + .cursorrules + copilot-instructions
        assert!(
            targets
                .iter()
                .any(|(p, _)| p == &PathBuf::from("CLAUDE.md"))
        );
        assert!(
            targets
                .iter()
                .any(|(p, _)| p == &PathBuf::from(".cursorrules"))
        );
        assert!(
            targets
                .iter()
                .any(|(p, _)| p == &PathBuf::from(".github/copilot-instructions.md"))
        );
    }

    #[test]
    fn test_detect_llm_targets_all() {
        let dir = TempDir::new().expect("Failed to create temp dir");
        // Create all 17 markers
        for marker in [
            ".claude",
            ".cursor",
            ".windsurf",
            ".gemini",
            ".codex",
            ".github",
            ".clinerules",
            ".roo",
            ".kiro",
            ".continue",
            ".aiassistant",
            ".amazonq",
            ".tabnine",
            ".augment",
        ] {
            fs::create_dir(dir.path().join(marker)).expect(&format!("create {marker}"));
        }
        // File-based markers
        fs::write(dir.path().join(".rules"), "# rules").expect("write .rules");
        fs::write(dir.path().join(".aider.conf.yml"), "# aider").expect("write .aider.conf.yml");
        let targets = detect_llm_targets(dir.path());
        // Should detect all 16 unique markers (14 dirs + 2 files)
        // Note: .codex creates AGENTS.md which is same file as what OpenCode would want
        assert_eq!(targets.len(), LLM_CONFIGS.len());
    }

    #[test]
    fn test_detect_llm_targets_existing_output_file() {
        // If .cursorrules exists (user created it manually) but no .cursor/ dir,
        // we still detect it as a Cursor project
        let dir = TempDir::new().expect("Failed to create temp dir");
        fs::write(dir.path().join(".cursorrules"), "# rules").expect("write .cursorrules");
        let targets = detect_llm_targets(dir.path());
        assert_eq!(targets.len(), 1);
        assert!(
            targets
                .iter()
                .any(|(p, _)| p == &PathBuf::from(".cursorrules"))
        );
    }

    // ─────────────────────────────────────────────────
    // Package.json prebuild wiring tests
    // ─────────────────────────────────────────────────

    #[test]
    fn test_wire_prebuild_adds_to_scripts() {
        let dir = TempDir::new().expect("Failed to create temp dir");
        fs::write(
            dir.path().join("package.json"),
            "{\n  \"name\": \"test-project\",\n  \"scripts\": {\n    \"build\": \"vite build\"\n  }\n}",
        )
        .expect("Failed to write");

        let result = wire_prebuild_js(dir.path()).expect("wire_prebuild failed");
        assert_eq!(result, WireResult::Added);

        let content = fs::read_to_string(dir.path().join("package.json")).expect("Failed to read");
        assert!(content.contains("\"prebuild\": \"ai-rsk scan --strict\""));
        assert!(content.contains("\"build\": \"vite build\""));
    }

    #[test]
    fn test_wire_prebuild_already_present() {
        let dir = TempDir::new().expect("Failed to create temp dir");
        fs::write(
            dir.path().join("package.json"),
            "{\n  \"name\": \"test\",\n  \"scripts\": {\n    \"prebuild\": \"ai-rsk scan --strict\",\n    \"build\": \"vite build\"\n  }\n}",
        )
        .expect("Failed to write");

        let result = wire_prebuild_js(dir.path()).expect("wire_prebuild failed");
        assert_eq!(result, WireResult::AlreadyPresent);
    }

    #[test]
    fn test_wire_prebuild_no_scripts_section() {
        let dir = TempDir::new().expect("Failed to create temp dir");
        fs::write(
            dir.path().join("package.json"),
            "{\n  \"name\": \"test-project\",\n  \"version\": \"1.0.0\"\n}",
        )
        .expect("Failed to write");

        let result = wire_prebuild_js(dir.path()).expect("wire_prebuild failed");
        assert_eq!(result, WireResult::NoScriptsSection);

        let content = fs::read_to_string(dir.path().join("package.json")).expect("Failed to read");
        assert!(content.contains("\"prebuild\": \"ai-rsk scan --strict\""));
        assert!(content.contains("\"scripts\""));
    }

    #[test]
    fn test_wire_prebuild_existing_prebuild_no_airsk() {
        let dir = TempDir::new().expect("Failed to create temp dir");
        fs::write(
            dir.path().join("package.json"),
            "{\n  \"name\": \"test\",\n  \"scripts\": {\n    \"prebuild\": \"echo hello\",\n    \"build\": \"vite build\"\n  }\n}",
        )
        .expect("Failed to write");

        let result = wire_prebuild_js(dir.path()).expect("wire_prebuild failed");
        assert_eq!(result, WireResult::AlreadyPresent);
    }

    // ─────────────────────────────────────────────────
    // devDependencies check tests
    // ─────────────────────────────────────────────────

    #[test]
    fn test_dep_placement_not_found() {
        let dir = TempDir::new().expect("Failed to create temp dir");
        fs::write(
            dir.path().join("package.json"),
            "{ \"name\": \"test\", \"dependencies\": { \"express\": \"4\" } }",
        )
        .expect("Failed to write");

        assert_eq!(check_dev_dependencies(dir.path()), DepPlacement::NotFound);
    }

    #[test]
    fn test_dep_placement_correct() {
        let dir = TempDir::new().expect("Failed to create temp dir");
        fs::write(
            dir.path().join("package.json"),
            "{ \"name\": \"test\", \"devDependencies\": { \"ai-rsk\": \"0.1.0\" } }",
        )
        .expect("Failed to write");

        assert_eq!(check_dev_dependencies(dir.path()), DepPlacement::Correct);
    }

    #[test]
    fn test_dep_placement_wrong() {
        let dir = TempDir::new().expect("Failed to create temp dir");
        fs::write(
            dir.path().join("package.json"),
            "{ \"name\": \"test\", \"dependencies\": { \"ai-rsk\": \"0.1.0\" } }",
        )
        .expect("Failed to write");

        assert_eq!(
            check_dev_dependencies(dir.path()),
            DepPlacement::InDependencies
        );
    }

    #[test]
    fn test_dep_placement_no_package_json() {
        let dir = TempDir::new().expect("Failed to create temp dir");
        assert_eq!(check_dev_dependencies(dir.path()), DepPlacement::NotFound);
    }

    // ─────────────────────────────────────────────────
    // Full init integration tests
    // ─────────────────────────────────────────────────

    #[test]
    fn test_init_empty_project() {
        let dir = TempDir::new().expect("Failed to create temp dir");
        let report = run_init(dir.path()).expect("init failed");

        assert!(report.ecosystems.is_empty());
        // SECURITY_RULES.md + CLAUDE.md + .gitignore
        assert_eq!(report.created.len(), 3);
        assert!(dir.path().join("SECURITY_RULES.md").exists());
        assert!(dir.path().join("CLAUDE.md").exists());
    }

    #[test]
    fn test_init_js_project() {
        let dir = TempDir::new().expect("Failed to create temp dir");
        fs::write(
            dir.path().join("package.json"),
            "{\n  \"name\": \"test-project\",\n  \"scripts\": {\n    \"build\": \"vite build\"\n  }\n}",
        )
        .expect("Failed to write");

        let report = run_init(dir.path()).expect("init failed");
        assert_eq!(report.ecosystems, vec![Ecosystem::JavaScript]);
        assert!(dir.path().join("SECURITY_RULES.md").exists());
        assert!(dir.path().join("CLAUDE.md").exists());

        let pkg = fs::read_to_string(dir.path().join("package.json")).expect("Failed to read");
        assert!(pkg.contains("ai-rsk scan --strict"));
    }

    #[test]
    fn test_init_idempotent() {
        let dir = TempDir::new().expect("Failed to create temp dir");
        fs::write(
            dir.path().join("package.json"),
            "{ \"name\": \"test\", \"scripts\": { \"build\": \"vite build\" } }",
        )
        .expect("Failed to write");

        let report1 = run_init(dir.path()).expect("init failed");
        assert_eq!(report1.created.len(), 3); // SECURITY_RULES.md + CLAUDE.md + .gitignore

        // Second run: SECURITY_RULES.md skipped (warning), CLAUDE.md already up to date (no warning)
        let report2 = run_init(dir.path()).expect("second init failed");
        assert_eq!(report2.created.len(), 0);

        // The CLAUDE.md content should still be valid
        let claude_md = fs::read_to_string(dir.path().join("CLAUDE.md")).expect("read CLAUDE.md");
        assert!(claude_md.contains("ai-rsk:start"));
        assert!(claude_md.contains("ai-rsk:end"));
        assert!(claude_md.contains("SECURITY_RULES.md"));
    }

    #[test]
    fn test_init_injects_into_existing_claude_md() {
        let dir = TempDir::new().expect("Failed to create temp dir");
        // Pre-existing CLAUDE.md with user content
        fs::write(
            dir.path().join("CLAUDE.md"),
            "# My Project Rules\n\nAlways use TypeScript.\n",
        )
        .expect("write CLAUDE.md");

        let report = run_init(dir.path()).expect("init failed");
        // CLAUDE.md should be modified (injected), not created
        assert!(report.modified.iter().any(|p| p.ends_with("CLAUDE.md")));

        let content = fs::read_to_string(dir.path().join("CLAUDE.md")).expect("read");
        // User content preserved
        assert!(content.contains("Always use TypeScript."));
        // ai-rsk block injected
        assert!(content.contains("ai-rsk:start"));
        assert!(content.contains("ai-rsk:end"));
        assert!(content.contains("SECURITY_RULES.md"));
    }

    #[test]
    fn test_init_updates_existing_airsk_block() {
        let dir = TempDir::new().expect("Failed to create temp dir");
        // CLAUDE.md with an old ai-rsk block
        fs::write(
            dir.path().join("CLAUDE.md"),
            "# My Project\n\n<!-- ai-rsk:start -->\nOLD CONTENT\n<!-- ai-rsk:end -->\n\n# Other stuff\n",
        )
        .expect("write CLAUDE.md");

        let report = run_init(dir.path()).expect("init failed");
        assert!(report.modified.iter().any(|p| p.ends_with("CLAUDE.md")));

        let content = fs::read_to_string(dir.path().join("CLAUDE.md")).expect("read");
        // Old content replaced
        assert!(!content.contains("OLD CONTENT"));
        // New content present
        assert!(content.contains("SECURITY_RULES.md"));
        // User content preserved
        assert!(content.contains("# My Project"));
        assert!(content.contains("# Other stuff"));
    }

    #[test]
    fn test_init_with_github_dir() {
        let dir = TempDir::new().expect("Failed to create temp dir");
        fs::create_dir(dir.path().join(".github")).expect("Failed to create .github");

        let report = run_init(dir.path()).expect("init failed");
        // SECURITY_RULES.md + copilot-instructions.md + .gitignore (no CLAUDE.md - .github detected, not .claude)
        assert_eq!(report.created.len(), 3);
        assert!(dir.path().join("SECURITY_RULES.md").exists());
        assert!(dir.path().join(".github/copilot-instructions.md").exists());
        assert!(!dir.path().join("CLAUDE.md").exists());
    }

    #[test]
    fn test_init_python_project() {
        let dir = TempDir::new().expect("Failed to create temp dir");
        fs::write(dir.path().join("requirements.txt"), "flask\n").expect("Failed to write");

        let report = run_init(dir.path()).expect("init failed");
        assert_eq!(report.ecosystems, vec![Ecosystem::Python]);

        let claude_md = fs::read_to_string(dir.path().join("CLAUDE.md")).expect("Failed to read");
        assert!(claude_md.contains("Python specific"));
        assert!(claude_md.contains("Semgrep covers Python security"));
    }

    // ─────────────────────────────────────────────────
    // Git hooks tests
    // ─────────────────────────────────────────────────

    #[test]
    fn test_pre_commit_hook_content() {
        let content = generate_pre_commit_hook();
        assert!(content.starts_with("#!/bin/sh"));
        assert!(content.contains("ai-rsk scan --strict"));
        assert!(content.contains("ai-rsk-ignore"));
        assert!(content.contains("EXIT_CODE"));
    }

    #[test]
    fn test_pre_push_hook_content() {
        let content = generate_pre_push_hook();
        assert!(content.starts_with("#!/bin/sh"));
        assert!(content.contains("main master production"));
        assert!(content.contains("force-push"));
        assert!(content.contains("merge-base --is-ancestor"));
        assert!(content.contains("release/*"));
    }

    #[test]
    fn test_install_hook_creates_new() {
        let dir = TempDir::new().expect("Failed to create temp dir");
        let hook_path = dir.path().join("pre-commit");
        let result = install_hook(&hook_path, "#!/bin/sh\nai-rsk scan".to_string());
        assert!(matches!(result, HookResult::Created));
        assert!(hook_path.exists());
        let content = fs::read_to_string(&hook_path).expect("read hook");
        assert!(content.contains("ai-rsk"));

        // Check executable on Unix
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let perms = fs::metadata(&hook_path).expect("metadata").permissions();
            assert_eq!(perms.mode() & 0o111, 0o111); // executable bits set
        }
    }

    #[test]
    fn test_install_hook_already_has_airsk() {
        let dir = TempDir::new().expect("Failed to create temp dir");
        let hook_path = dir.path().join("pre-commit");
        fs::write(&hook_path, "#!/bin/sh\nai-rsk scan --strict\n").expect("write");
        let result = install_hook(&hook_path, "new content".to_string());
        assert!(matches!(result, HookResult::AlreadyHasAiRsk));
    }

    #[test]
    fn test_install_hook_exists_without_airsk() {
        let dir = TempDir::new().expect("Failed to create temp dir");
        let hook_path = dir.path().join("pre-commit");
        fs::write(&hook_path, "#!/bin/sh\necho 'custom hook'\n").expect("write");
        let result = install_hook(&hook_path, "new content".to_string());
        assert!(matches!(result, HookResult::ExistsWithoutAiRsk));
        // Original content must NOT be overwritten
        let content = fs::read_to_string(&hook_path).expect("read");
        assert!(content.contains("custom hook"));
    }

    #[test]
    fn test_init_with_git_dir_installs_hooks() {
        let dir = TempDir::new().expect("Failed to create temp dir");
        // Create .git/hooks directory
        fs::create_dir_all(dir.path().join(".git/hooks")).expect("create .git/hooks");

        let report = run_init(dir.path()).expect("init failed");

        // Should have: SECURITY_RULES.md + CLAUDE.md + .gitignore + pre-commit + pre-push = 5
        assert_eq!(report.created.len(), 5);
        assert!(dir.path().join(".git/hooks/pre-commit").exists());
        assert!(dir.path().join(".git/hooks/pre-push").exists());

        let pre_commit =
            fs::read_to_string(dir.path().join(".git/hooks/pre-commit")).expect("read pre-commit");
        assert!(pre_commit.contains("ai-rsk scan"));

        let pre_push =
            fs::read_to_string(dir.path().join(".git/hooks/pre-push")).expect("read pre-push");
        assert!(pre_push.contains("force-push"));
    }

    #[test]
    fn test_init_without_git_dir_warns() {
        let dir = TempDir::new().expect("Failed to create temp dir");
        let report = run_init(dir.path()).expect("init failed");
        assert!(report.warnings.iter().any(|w| w.contains(".git")));
        assert!(!dir.path().join(".git/hooks/pre-commit").exists());
    }

    #[test]
    fn test_init_multi_ecosystem() {
        let dir = TempDir::new().expect("Failed to create temp dir");
        fs::write(
            dir.path().join("package.json"),
            "{ \"name\": \"test\", \"scripts\": { \"build\": \"vite build\" } }",
        )
        .expect("Failed to write");
        fs::write(dir.path().join("requirements.txt"), "flask\n").expect("Failed to write");

        let report = run_init(dir.path()).expect("init failed");
        assert_eq!(report.ecosystems.len(), 2);

        let claude_md = fs::read_to_string(dir.path().join("CLAUDE.md")).expect("Failed to read");
        assert!(claude_md.contains("JavaScript/TypeScript specific"));
        assert!(claude_md.contains("Python specific"));
    }
}
