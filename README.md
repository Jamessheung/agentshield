# AgentShield

Security scanner for AI agent ecosystems.

**20% of OpenClaw's skill marketplace is malware. We're fixing that.**

## The Problem

OpenClaw has 10,700+ skills on ClawHub. Security researchers have found 824+ malicious skills — roughly 20% of the entire registry. These skills steal passwords, browser cookies, crypto wallets, and API keys through a campaign called ClawHavoc.

Microsoft's advisory: *"OpenClaw should be treated as untrusted code execution with persistent credentials."*

There is no tool to scan skills before you install them. AgentShield changes that.

## What It Does

```
$ agentshield scan ./solana-wallet-tracker/

  AgentShield Scan Report
  ─────────────────────────────────────
  Skill:       solana-wallet-tracker
  Risk Score:  92/100 (CRITICAL)

  ⛔ CRITICAL  Fake prerequisite installer detected
  ⛔ CRITICAL  Pipe-to-interpreter pattern (curl | bash)
  ⚠  HIGH     Requests access to ~/.openclaw/.env
  ⚠  HIGH     External URL points to suspicious domain

  Verdict: DO NOT INSTALL
```

AgentShield scans OpenClaw skills for:

- **Supply chain attacks** — fake prerequisites that install malware (ClawHavoc's primary vector)
- **Code execution** — reverse shells, pipe-to-interpreter patterns
- **Data exfiltration** — credential theft, webhook exfil, env file access
- **Prompt injection** — hidden instructions that hijack agent behavior
- **Suspicious metadata** — typosquatting names, new accounts, mass publishing

## Quick Start

```bash
# Install
npm install -g agentshield

# Scan a local skill
agentshield scan ./my-skill/

# Check a skill from ClawHub by slug
agentshield check youtube-summarize-pro

# Output as JSON (for CI/CD)
agentshield scan ./my-skill/ --format json
```

## Detection Rules

| ID | Category | Severity | What It Catches |
|----|----------|----------|-----------------|
| SC-001 | Supply Chain | CRITICAL | Fake prerequisite installers |
| SC-002 | Supply Chain | HIGH | Typosquatting skill names |
| CE-001 | Code Execution | CRITICAL | `curl \| bash` patterns |
| CE-002 | Code Execution | CRITICAL | Reverse shell payloads |
| DE-001 | Data Exfil | HIGH | Sensitive file access (.env, .ssh, Keychain) |
| DE-002 | Data Exfil | HIGH | Webhook exfiltration endpoints |
| DE-003 | Data Exfil | HIGH | Base64 encoding before network send |
| PI-001 | Prompt Injection | HIGH | Hidden instruction override |
| SM-001 | Metadata | MEDIUM | Suspicious account age |
| SM-002 | Metadata | HIGH | Mass publisher pattern |
| BP-001 | Best Practice | MEDIUM | Unpinned dependencies |

Rules are defined in `signatures/` as YAML — PRs welcome.

## ClawHub Full Audit

We scanned all 10,700+ skills on ClawHub. Results: *The State of OpenClaw Security* (coming soon)

## How It Works

```
SKILL.md + skill files
        │
        ▼
   ┌─────────┐
   │ Ingester │  Parse YAML frontmatter + markdown + code blocks
   └────┬────┘
        │
        ▼
   ┌──────────────────────┐
   │  Analysis Pipeline    │
   │  • Pattern matching   │  Regex rules against known attack patterns
   │  • Metadata analysis  │  Account age, publish frequency, typosquats
   │  • Signature matching │  Known malware campaign indicators
   │  • Behavioral analysis│  Permission/access heuristics
   └────┬─────────────────┘
        │
        ▼
   ┌──────────┐
   │  Scorer   │  Aggregate findings → 0-100 risk score
   └────┬─────┘
        │
        ▼
   ┌──────────┐
   │ Reporter  │  Terminal (colored) / JSON / SARIF
   └──────────┘
```

## Contributing

We need help with:

- **New detection rules** — see `signatures/` for the YAML format
- **False positive reports** — open an issue with the skill slug and finding ID
- **ClawHub coverage** — testing against more skills from the registry

```bash
# Development
cargo build
cargo test

# Run locally
cargo run -- scan ./test-fixtures/malicious-skill/
```

## Roadmap

- [x] Core scanning engine (Rust)
- [x] CLI tool (TypeScript)
- [x] ClawHavoc / AMOS signature database
- [ ] ClawHub full registry audit
- [ ] Web scanner (agentshield.dev)
- [ ] GitHub Actions integration
- [ ] LLM-assisted behavioral analysis
- [ ] Multi-framework support (LangChain, CrewAI, Dify)

## Security

If you discover a vulnerability in AgentShield itself, please open a GitHub issue with the `security` label.

<!-- TODO: Update to security@agentshield.dev once domain email is configured -->

## License

MIT
