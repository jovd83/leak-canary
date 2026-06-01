# Changelog

All notable changes to leak-canary are documented here.

## [Unreleased]

### Added
### Changed
### Fixed
### Removed

## [1.2.0] - 2026-06-01

### Added

- **JWT Token detection.** `eyJ…` three-part base64url tokens are now detected as `JWT Token`. These are extremely common in modern APIs and were previously uncaught unless the containing variable name matched the generic secret pattern.
- **Azure Storage Account Key detection.** Connection strings containing `AccountKey=<86 base64 chars>==` are now detected as `Azure Storage Account Key`.
- **Generic Bearer Token detection.** `Authorization: Bearer <40+ char token>` in source files and logs is now flagged. Named "Generic" so specific overlapping patterns (e.g. JWT Token) win dedup when the same token is matched by both.
- **Portuguese NIF (Tax ID).** 9-digit Portuguese national tax identifier, validated with mod-11 checksum. Includes mutual-exclusion filter: a number that already passes the Dutch BSN check is reported as BSN only.
- **Irish PPS Number.** 7-digit + check-letter Irish personal identifier, validated with mod-23 checksum.
- **Romanian CNP.** 13-digit Romanian personal numeric code, validated with weighted mod-11 checksum.
- **MAC Address.** Colon- and hyphen-separated hardware addresses (e.g. `00:1A:2B:3C:4D:5E`) are now flagged as GDPR/PII because they can identify specific individuals in network logs. Broadcast (`FF:FF:FF:FF:FF:FF`) and all-zero addresses are excluded.

### Fixed

- **Passwords with `!` and other special characters not detected.** The generic secret regex character class `[a-zA-Z0-9_\-.@#$%^&*()+]` excluded `!`, `|`, `/`, and other common password characters. Replaced with `[^'"\`\s]{6,}` — matches any 6+ chars that are neither whitespace nor the enclosing quote character. `adminPassword: "MyP@ss2024!"` is now correctly flagged.
- **US phone in `(NXX) NXX-XXXX` format after comma in CSV not detected.** The leading `\b` word-boundary assertion failed before `(` when preceded by `,` (both non-word characters). Replaced `\b` with a negative lookbehind `(?<![0-9A-Za-z_])` that blocks mid-word matches without requiring a word boundary before `(`.
- **OpenAI API key (`sk-proj-…`) reported as "Generic Secret/Password" instead of "OpenAI API Key".** When a key is assigned via `openaiApiKey = "sk-proj-…"`, the generic `apikey` pattern matched the full assignment string (longer span) and suppressed the specific OpenAI pattern. Fixed the overlap-dedup rank function: non-generic leakTypes now receive a 100 000-point priority bonus, so specific patterns always beat a longer generic match covering the same region.

## [1.1.0] - 2026-05-29

### Fixed

- **CSV files were silently skipped.** `.csv` (and `.dsv`) were listed in the binary-file ignore set, meaning customer data files — the most common real-world PII leak vector — were never scanned. Removed both extensions from the exclusion list.
- **Scanner always scanned the wrong directory.** `detect.js` used `process.cwd()` unconditionally, so when an agent ran it from outside the target project (the normal case for a skill installed in `~/.agents/skills/`), it scanned the shell's working directory instead of the user's project. Added an optional positional argument: `node detect.js [target-dir]`.
- **Google API key regex missed real keys.** Pattern required `AIzaSy` (6 chars) + 35 more = 41 total, but real Google API keys are `AIza` (4 chars) + 35 = 39 total. Updated to `AIza[0-9A-Za-z\-_]{35}`.
- **Credit cards with spaces or dashes were not detected.** Regex only matched 16 contiguous digits, missing the grouped format (`4111 1111 1111 1111`) common in CSV exports and database dumps. Widened the candidate regex to accept single space/hyphen separators between digit groups; Luhn + brand-prefix validation in the filter preserves precision.
- **Duplicate findings on the same line.** A DB connection string's embedded password fragment was re-reported as a separate "Email Address" finding. Added overlap suppression: when two findings on the same line share characters, the higher-priority one (Secrets/Credentials outranks GDPR/PII; longer span wins ties) suppresses the other.
- **Placeholder email domains flagged as leaks.** `yourdomain.com` and `domain.com` were not in the email filter allowlist alongside `example.com` and `test.com`, producing false positives in documentation-heavy repositories.

### Documentation

- Updated `SKILL.md` Step 2A to show the correct invocation with an explicit target-directory argument, replacing the broken relative-path example.
- Added two new rows to the troubleshooting table for the wrong-directory and path-resolution failure modes.
- Updated `references/leak-patterns.md` with the corrected Google key format, expanded credit card detection note, and a new precision note on bare-digit national ID patterns (BSN, PESEL, SV-Nummer, etc.) explaining the checksum false-positive rate.

## [1.0.0] - initial release

- Initial skill with programmatic Node.js scanner (`detect.js`) and agent fallback using `references/leak-patterns.md`.
- Detects secrets/credentials (generic passwords, Google, AWS, GitHub, Stripe, OpenAI, Slack, Discord, Twilio, Mailgun, SendGrid, private keys, DB URIs) and GDPR/PII (emails, phones, credit cards, IBAN, 14 European national ID formats).
- Respects `.gitignore`, `.aiignore`, `.cursorignore`, `.npmignore`, and `.leakwhitelist`.
- Interactive remediation menu: delete, extract to env var, add to `.gitignore`/`.aiignore`, or whitelist.
