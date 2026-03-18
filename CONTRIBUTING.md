# Contributing to AgentShield

Thank you for your interest in making AI agent ecosystems safer.

## Ways to Contribute

### 1. New Detection Rules

Detection rules are the core of AgentShield. Here's how to add one:

**Rust (scanner-core):**

1. Choose a rule ID following the convention:
   - `SC-xxx` — Supply chain attacks
   - `CE-xxx` — Code execution
   - `DE-xxx` — Data exfiltration
   - `PI-xxx` — Prompt injection
   - `SM-xxx` — Suspicious metadata
   - `BP-xxx` — Best practice violations
   - `SIG-xxx` — Known malware signatures
   - `BA-xxx` — Behavioral analysis

2. Add the rule in the appropriate analyzer file under `crates/scanner-core/src/analyzers/`:
   - `pattern.rs` — Regex-based rules (most common)
   - `metadata.rs` — Frontmatter analysis
   - `behavioral.rs` — Heuristic analysis
   - `signatures.rs` — Known campaign matching

3. Add a test in the same file:

```rust
#[test]
fn test_detects_my_new_rule() {
    let findings = scan(
        "---\nname: test\n---\n# Test\n\n<content that should trigger the rule>",
    );
    assert!(findings.iter().any(|f| f.rule_id == "XX-NNN"));
}
```

4. Add a matching test to the TypeScript analyzer in `cli/src/analyzers.ts`.

**Signature YAML:**

For known malware campaigns, add a YAML file in `signatures/`:

```yaml
---
campaign: Campaign Name
discovered_by: Your Name / Org
date: 2026-MM-DD
references:
  - https://link-to-report

indicators:
  publisher_accounts:
    - username1
  url_patterns:
    - "domain.com/path"
  name_patterns:
    - "prefix-*"
```

### 2. False Positive Reports

If AgentShield flags a legitimate skill:

1. Open an issue with:
   - The skill name / slug
   - The rule ID that triggered (e.g., `SC-002`)
   - Why you believe it's a false positive
2. We'll review and either:
   - Tune the rule to avoid the false positive
   - Add the skill to an allowlist

### 3. Test Fixtures

Add test cases to improve coverage:

- `tests/fixtures/malicious/` — Known bad skills (should trigger findings)
- `tests/fixtures/clean/` — Known good skills (should trigger zero findings)

Each fixture is a directory containing a `SKILL.md` file.

### 4. Bug Fixes and Features

1. Fork the repo
2. Create a branch (`git checkout -b fix/my-fix`)
3. Make changes
4. Run tests: `cargo test` and `cd cli && npm run build`
5. Submit a PR

## Development Setup

```bash
# Rust
cargo build
cargo test
cargo clippy

# TypeScript CLI
cd cli
npm install
npm run build
```

## Code Style

- **Rust**: `cargo fmt` and `cargo clippy` must pass with no warnings
- **TypeScript**: ESM modules, strict mode
- All public functions need doc comments
- All new rules need unit tests
- No `unwrap()` in library code — use `?` or proper error handling

## Suppressing Rules

Users can add ignore directives to their SKILL.md:

```markdown
<!-- agentshield:ignore SC-002 -->
<!-- agentshield:ignore DE-001, BP-001 -->
```

This suppresses the specified rules for that skill.

## Running Integration Tests

```bash
# Scan test fixtures
cargo run -- scan tests/fixtures/malicious/clawhavoc-sample/
cargo run -- scan tests/fixtures/clean/weather-skill/

# Full test suite
cargo test
```

## License

By contributing, you agree that your contributions will be licensed under MIT.
