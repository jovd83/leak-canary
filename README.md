# leak-canary

[![version](https://img.shields.io/badge/version-1.2.0-blue)](CHANGELOG.md)
[![status](https://img.shields.io/badge/status-stable-3fb950)](SKILL.md)
[![category](https://img.shields.io/badge/category-security-e11d48)](SKILL.md)
[![CI](https://github.com/jovd83/leak-canary/actions/workflows/validate.yml/badge.svg)](.github/workflows/validate.yml)
[![license](https://img.shields.io/badge/license-MIT-green)](LICENSE)
[![Buy Me a Coffee](https://img.shields.io/badge/Buy%20Me%20a%20Coffee-ffdd00?style=flat&logo=buy-me-a-coffee&logoColor=black)](https://buymeacoffee.com/jovd83)

`leak-canary` scans a project directory for data leaks before they reach GitHub — hardcoded secrets, API keys, and GDPR/PII violations — then walks you through interactive remediation without touching a single file until you decide what to do.

Like the canary in the coal mine, it runs before you push and alerts you to danger early. It is intentionally conservative: it never modifies files automatically, obfuscates sensitive values in its report so they don't leak a second time into agent logs, and respects your existing ignore files (`.gitignore`, `.aiignore`, `.cursorignore`) and a permanent whitelist for known-safe test data.

## What This Skill Does

Use `leak-canary` to catch sensitive data before a `git push`, when auditing an existing workspace for GDPR compliance, or before sharing a CSV export with an external partner.

- Runs a fast, zero-dependency Node.js scanner (`detect.js`) that reads line-by-line and applies checksum-validated regex patterns.
- Detects **secrets and credentials**: generic passwords, Google/AWS/GitHub/Stripe/OpenAI/Azure keys, JWT tokens, Slack/Discord/Twilio/Mailgun/SendGrid tokens, private key blocks, database connection strings, and opaque Bearer tokens.
- Detects **GDPR/PII**: email addresses, phone numbers, credit cards (including spaced/dashed formats), IBAN bank accounts, MAC addresses, and 17 European national ID formats with checksum validation.
- Validates checksums (Luhn, modulo-97, modulo-11, EAN-13, mod-23, etc.) to suppress numeric false positives.
- Falls back to agent-native grep search when Node.js is unavailable.
- Presents findings in an obfuscated markdown table and offers four remediation options per finding: delete, extract to environment variable, add to `.gitignore`/`.aiignore`, or whitelist.
- Runs a post-remediation verification scan to confirm the workspace is clean.

## When To Use It

Use this skill when:

- You are about to `git push` or open a pull request and want a final safety check.
- A workspace may contain real customer data (CSVs, database exports, test fixtures) that should not be committed.
- You need to audit a project for GDPR compliance before a release or handoff.
- You are preparing a release ZIP, archiving logs, or sharing data with an external party.
- A team member or AI agent has been working in the repository and you want to verify nothing sensitive was accidentally hardcoded.

## What This Skill Does Not Do

- It does not commit, push, or modify any file automatically — all remediations require explicit user confirmation.
- It does not replace a dedicated secrets management solution (e.g. HashiCorp Vault, GitHub secret scanning).
- It does not scan binary files, compiled artifacts, or archives.
- It does not guarantee zero false negatives — patterns with no distinctive prefix (e.g. 9-digit national IDs) rely on checksums that occasionally pass for arbitrary numbers; see the precision note in `references/leak-patterns.md`.
- It does not scan files larger than ~1 000 characters per line (minified bundles are intentionally skipped).

## Install

```powershell
npx skills add jovd83/leak-canary
```

For local install:

```powershell
Copy-Item -Recurse . "$env:USERPROFILE\.agents\skills\leak-canary"
```

Requires **Node.js ≥ 12** for the fast programmatic scan path. If Node.js is unavailable the skill falls back to agent-native search tools automatically.

## Usage

Example prompts:

```text
Before I push, use leak-canary to check this project for any leaked API keys or customer data.
```

```text
Scan my workspace for GDPR violations and secrets. Don't change anything yet — just show me what you find.
```

```text
I just exported a customer CSV into the repo. Can you check it for PII before I commit?
```

The skill will:

1. Run `detect.js` against your workspace (or fall back to grep if Node.js is unavailable).
2. Present a deduplicated, obfuscated findings table grouped by file.
3. Offer numbered remediation choices for each finding.
4. Wait for your instructions before touching any file.
5. Re-run the scan after remediation to confirm the workspace is clean.

## Pattern Categories

| Category | Examples |
|---|---|
| Secrets / Credentials | Generic passwords, Google API keys, AWS access/secret keys, GitHub PATs, Stripe keys, OpenAI keys, JWT tokens, Azure Storage Account keys, Generic Bearer tokens, Slack/Discord webhooks, Twilio/Mailgun/SendGrid API keys, DB connection strings (MongoDB, PostgreSQL, MySQL, MSSQL), private key blocks |
| GDPR / PII | Email addresses, US phone numbers, credit cards (plain, spaced, dashed), IBAN accounts, MAC addresses, Belgian INSZ/Rijksregisternummer, Dutch BSN, French INSEE, German Steuer-ID, Spanish DNI/NIE, UK NINO, Italian Codice Fiscale, Austrian SV-Nummer, Swiss AHV, Polish PESEL, Swedish Personnummer, Finnish HETU, Romanian CNP, Irish PPS Number, Portuguese NIF |

## Remediation Options

| Option | What it does |
|---|---|
| **[1] Delete** | Removes the hardcoded value or the line |
| **[2] Extract to env var** | Replaces with `process.env.VAR_NAME` and appends the key to `.env` |
| **[3] Ignore file** | Adds the file path to `.gitignore` and/or `.aiignore` |
| **[4] Whitelist** | Marks as a known false positive — permanently appends the raw string to `.leakwhitelist` |
