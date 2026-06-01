# Data Leak & GDPR Pattern Reference Catalog

This reference file lists the standard patterns, risk categories, and remediation methods used by the **Leak Shield** skill. It provides agents and developers with the technical context needed to classify and handle vulnerabilities.

---

## 1. Secrets & Credentials (High Severity)

Hardcoded secrets in source files represent immediate, high-severity vulnerabilities. If pushed, these secrets are easily mined by automated bots.

### Generic Secret/Password Definitions
*   **Target Indicators:** Variable names containing `password`, `passwd`, `pass`, `pwd`, `secret`, `auth_token`, `client_secret`, `api_key`, `apikey`, `private_key` assigned to string values.
*   **Regex Pattern:** `/(password|passwd|pass|pwd|secret|auth_token|client_secret|api_key|apikey|private_key)\s*[:=]\s*['"`]([a-zA-Z0-9_\-\.\@\#\$\%\^\&\*\(\)\+]{6,})['"`]/gi`
*   **Remediation:** Replace with `process.env.VARIABLE_NAME` (Node.js) or `os.environ.get('VARIABLE_NAME')` (Python) and put the real value in `.env`.

### Platform-Specific Keys

| Threat Name | Format Signature / Regex | Threat Context |
| :--- | :--- | :--- |
| **Google API Key** | `AIza[0-9A-Za-z\-_]{35}` (39 chars total) | Gives unauthorized access to Google Cloud, Maps, Firebase, etc. |
| **AWS API Key** | `AKIA[0-9A-Z]{16}` | Direct entry point into Amazon Web Services API interfaces. |
| **AWS Secret Key** | `aws_secret_access_key\s*[:=]\s*['"`]([0-9a-zA-Z\/+]{40})['"`]` | Paired with AWS API key, allows full control over target AWS infrastructure. |
| **Slack Token** | `xox[bapr]-[0-9a-zA-Z]{10,12}-[0-9a-zA-Z]{24}` | Allows full bot or workspace reading/writing permissions on Slack. |
| **Private Keys** | `-----BEGIN [A-Z ]+ PRIVATE KEY-----` | Exposes cryptographic SSH/SSL identity assets. |
| **Database URI** | `[a-z]+:\/\/([^:]+):([^@]+)@` | Exposes live databases (MongoDB, PostgreSQL, MySQL) to direct intrusion. |

---

## 2. Personally Identifiable Information (PII) & GDPR Compliance

Under GDPR (General Data Protection Regulation) and similar global privacy frameworks (CCPA, HIPAA), storing raw personal data in a project repository without appropriate encryption and consent mechanisms is a significant compliance breach.

### Monitored PII Classes

1.  **Email Addresses**
    *   **Risk:** Direct contact information. Allows spear-phishing and profile mapping.
    *   **Regex:** `\b[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}\b`
    *   **Remediation:** Remove mock email lists from production directories. Always use dummy domains (e.g., `user@example.com`) for testing.

2.  **US Phone Numbers**
    *   **Risk:** Secondary biometric/contact token used for 2FA intercept or social engineering.
    *   **Regex:** `\b(?:\+?1[-. ]?)?\(?([0-9]{3})\)?[-. ]?([0-9]{3})[-. ]?([0-9]{4})\b`
    *   **Remediation:** Mask phone numbers in sample data or replace with environmental mocks.

3.  **Credit Card Numbers**
    *   **Risk:** Direct financial fraud capability.
    *   **Regex:** Candidate match is a 13–19 digit run allowing single space/hyphen separators (cards leak grouped, e.g. `4111 1111 1111 1111`). Precision comes from the filter, not the regex.
    *   **Validation:** Strip separators, require a recognized brand prefix (Visa, Mastercard, AMEX, Discover, Diners, JCB) **and** a passing Luhn checksum before flagging.
    *   **Remediation:** Remove test card lists. All testing credit cards must utilize recognized test tokens and must pass a valid Luhn checksum filter before flag status.

4.  **IBAN Bank Account Numbers**
    *   **Risk:** Direct financial tracking and transaction initiation routing. Extremely sensitive PII under GDPR.
    *   **Regex:** `\b[A-Z]{2}\d{2}(?:[ ]?[A-Z0-9]){11,30}\b`
    *   **Validation:** Mathematical modulo-97 validation check on the rearranged character array.
    *   **Remediation:** Replace with dummy testing accounts or load dynamically from secure settings.

5.  **Belgian INSZ / Rijksregisternummer**
    *   **Risk:** Highly sensitive personal biometric identifier. Serves as key for government and health services. High exposure penalty under Belgian GDPR rules.
    *   **Regex:** `\b(?:\d{2}\.\d{2}\.\d{2}-\d{3}\.\d{2}|\d{6}-\d{5}|\d{11})\b`
    *   **Validation:** Dual modulo-97 calculation (supporting pre-2000 and post-2000 birthday registers).
    *   **Remediation:** Mask or delete all real registers; use dummy tokens for local development.

6.  **US Social Security Numbers (SSN)**
    *   **Risk:** Identity theft, credit rating subversion, tax/loan fraud. High regulatory compliance liability.
    *   **Regex:** `\b\d{3}-\d{2}-\d{4}\b`
    *   **Validation:** Exclude standard invalid ranges (area code 000, 666, or 900+).
    *   **Remediation:** Remove and replace with synthetic numbers in testing data suites.

7.  **French INSEE / Social Security Number**
    *   **Risk:** Sensitive demographic identifier linking sex, birthday, place of birth, and birth order. High GDPR exposure threat.
    *   **Regex:** `\b[12]\d{2}(?:0[1-9]|1[0-2])\d{10}\b`
    *   **Validation:** Modulo-97 checksum validation logic (`checksum = 97 - (first 13 digits % 97)`).
    *   **Remediation:** Delete or replace with synthetically validated dummy entries.

8.  **German Steuer-ID (Tax ID)**
    *   **Risk:** Universal German personal tax identifier. Strictly protected under German BDSG/GDPR guidelines.
    *   **Regex:** `\b[1-9]\d{10}\b`
    *   **Validation:** Modulo-11 checksum + unique digit frequency constraints (exactly one digit appears twice or three times, all others at most once).
    *   **Remediation:** Replace with mock Steuer-IDs passing modulo-11 checks.

9.  **Dutch BSN (Burgerservicenummer)**
    *   **Risk:** Unified personal citizen service identifier in the Netherlands. Highly critical PII.
    *   **Regex:** `\b\d{9}\b`
    *   **Validation:** Mathematical Dutch 9-test (11-test check using custom decreasing digit multipliers).
    *   **Remediation:** Use synthetic 9-test-compliant mock numbers for local testing.

10. **Spanish DNI / NIE**
    *   **Risk:** National Identity Card (DNI) and Foreign Resident Identifier (NIE). Direct personal identifier.
    *   **Regex:** `\b(?:[XYZ]\d{7}|\d{8})[A-Z]\b`
    *   **Validation:** Modulo-23 letter index check.
    *   **Remediation:** Remove or replace with synthetic DNI/NIE tokens.

11. **UK National Insurance Number (NINO)**
    *   **Risk:** National insurance security identifier in the United Kingdom. Critical biometric mapping key.
    *   **Regex:** `\b[A-CEGHJ-PR-TW-Z][A-CEGHJ-NPR-TW-Z]\s*\d{2}\s*\d{2}\s*\d{2}\s*[A-D]\b`
    *   **Remediation:** Strip or mask NINO records before storage.

12. **European Vehicle License Plates**
    *   **Risk:** Vehicle registration PII, which links physical vehicle ownership records directly to individuals under GDPR.
    *   **Regex:** Common standard patterns for France, Spain, Italy, the UK, Germany, and Belgium.
    *   **Remediation:** Blur or replace mock registration sequences in development datasets.

13. **Italian Codice Fiscale (Fiscal Code)**
    *   **Risk:** Universal taxpayer code in Italy. Distinctive, highly unique personal PII.
    *   **Regex:** `\b[A-Z]{6}\d{2}[A-EHLMPR-T]\d{2}[A-Z]\d{3}[A-Z]\b`
    *   **Remediation:** Replace with mock Italian fiscal codes for testing.

14. **Austrian SV-Nummer (Social Security)**
    *   **Risk:** Austrian national social security identifier. Highly protected citizen data under Austrian law.
    *   **Regex:** `\b\d{10}\b`
    *   **Validation:** Mathematical weight product modulo-11 check.
    *   **Remediation:** Use synthetic 10-digit codes that pass SV-Nummer modulo checks.

15. **Swiss AHV / OASI Number**
    *   **Risk:** Swiss old-age and survivors' insurance identifier. Universal citizen identity number in Switzerland.
    *   **Regex:** `\b756\.\d{4}\.\d{4}\.\d{2}\b`
    *   **Validation:** EAN-13 check digit logic.
    *   **Remediation:** Use synthetic 756-prefix numbers with correct EAN checksums.

16. **Polish PESEL Number**
    *   **Risk:** Universal Electronic System for Registration of the Population in Poland. Direct personal identifier.
    *   **Regex:** `\b\d{11}\b`
    *   **Validation:** Weighted sum modulo-10 check digit verification.
    *   **Remediation:** Use synthetic PESEL mock values in database tests.

17. **Swedish Personnummer**
    *   **Risk:** Swedish national personal identity number. Widely used across all social sectors.
    *   **Regex:** `\b(?:\d{6}|\d{8})[-+]\d{4}\b`
    *   **Validation:** Decenturying and standard Luhn algorithm check.
    *   **Remediation:** Use fake coordination/personnummer values for testing.

18. **Finnish Personal Identity Code (HETU)**
    *   **Risk:** Finnish national personal identity code. Highly critical PII.
    *   **Regex:** `\b\d{6}[-+A]\d{3}[0-9A-Y]\b`
    *   **Validation:** Modulo-31 check character matching.
    *   **Remediation:** Replace with mock codes passing modulo-31 checksum division.

19. **GitHub / Stripe / OpenAI Platform Tokens**
    *   **Risk:** High-severity access tokens that give direct control over Git repositories, payments processing, and billing assets.
    *   **Regex:** Platform-specific token formats (e.g. `github_pat_`, `sk_live_`, `sk-proj-`).
    *   **Remediation:** Extract immediately to local `.env` and load dynamically.

20. **JWT Token**
    *   **Risk:** Signed/encrypted session or API tokens. A leaked JWT grants access until expiry and may encode sensitive claims.
    *   **Regex:** `eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+` (`eyJ` is base64url of `{"` — the start of every JWT header).
    *   **Remediation:** Revoke the signing key; never store JWTs in source files or logs.

21. **Azure Storage Account Key**
    *   **Risk:** Grants full read/write/delete access to all blobs, tables, queues, and files in a storage account.
    *   **Regex:** `AccountKey=[A-Za-z0-9+\/]{86}==` (512-bit key, always 88 base64 chars).
    *   **Remediation:** Rotate the key in the Azure Portal; use Managed Identity or SAS tokens with limited scope instead.

22. **Generic Bearer Token**
    *   **Risk:** Long opaque tokens in `Authorization: Bearer …` headers or hardcoded in source. Can be API keys, OAuth tokens, or session tokens.
    *   **Regex:** `[Bb]earer\s+[A-Za-z0-9._\-]{40,}` (40+ char token after the `Bearer` keyword).
    *   **Remediation:** Extract to environment variable; consider short-lived tokens with refresh rotation.

23. **Portuguese NIF (Tax ID)**
    *   **Risk:** Portuguese national tax identifier. Directly links to tax records and financial data.
    *   **Regex:** `\b[1-9]\d{8}\b` (9 digits, first digit 1–3 for individuals, 5/6/8/9 for entities).
    *   **Validation:** Mod-11 checksum. Numbers that also pass the Dutch BSN test are reported as BSN only (mutual exclusion).
    *   **Remediation:** Replace with synthetic test NIFs passing the mod-11 check.

24. **Irish PPS Number**
    *   **Risk:** Irish Personal Public Service Number. Mandatory identifier for tax, social welfare, and healthcare.
    *   **Regex:** `\b\d{7}[A-W]{1,2}\b` (7 digits + check letter, optionally a second type letter).
    *   **Validation:** Weights 8–2 on first 7 digits, mod-23 → letter index in `WABCDEFGHIJKLMNOPQRSTUV`.
    *   **Remediation:** Remove and replace with synthetic values.

25. **Romanian CNP**
    *   **Risk:** Romanian Personal Numeric Code. Encodes sex, birth date, and birthplace — high-sensitivity PII under GDPR.
    *   **Regex:** `\b[1-8]\d{12}\b` (13 digits, first digit 1–8).
    *   **Validation:** Weights `2,7,9,1,4,6,3,5,8,2,7,9`, sum mod 11 (remainder 10 → check digit 1).
    *   **Remediation:** Replace with synthetic CNPs passing the checksum.

26. **MAC Address**
    *   **Risk:** Hardware address that uniquely identifies a device. In network logs and audit trails, MAC addresses can be directly linked to specific individuals under GDPR Article 4(1).
    *   **Regex:** `\b[0-9A-Fa-f]{2}(?:[-:][0-9A-Fa-f]{2}){5}\b` (colon or hyphen separated).
    *   **Exclusions:** Broadcast (`FF:FF:FF:FF:FF:FF`) and all-zero (`00:00:00:00:00:00`) addresses are not flagged.
    *   **Remediation:** Pseudonymise MAC addresses in log exports before sharing or archiving.

### Precision note on bare-digit national identifiers

Several national IDs (Dutch BSN `\d{9}`, Austrian SV `\d{10}`, German Steuer-ID / Polish PESEL / Belgian INSZ `\d{11}`) have no distinctive prefix — only a checksum distinguishes them from ordinary numbers. The scanner runs each checksum to filter the bulk of noise, but a checksum is only a few bits of entropy, so a fraction of arbitrary numbers (e.g. ~1 in 11 random 9-digit values for the BSN test) will coincidentally pass. In data-heavy repositories (order IDs, timestamps, sequence columns) expect some false positives in these categories. When reviewing findings, weigh surrounding context (column headers, variable names, neighboring real PII) before treating a lone numeric match as a confirmed leak — and use `.leakwhitelist` for known-safe synthetic values.

---

## 3. Shielding Files From AI Agents (`.aiignore` & `.cursorignore`)

Modern LLM-powered editors and AI coding assistants recursively index local workspaces to construct vector search databases or inject context. To prevent AI agents from accidentally reading or indexing sensitive logs, backups, or raw database files, use `.aiignore` or `.cursorignore`.

### How `.aiignore` Works
*   The `.aiignore` file resides at the root of the workspace.
*   Like `.gitignore`, it follows standard glob syntax rules.
*   AI agents complying with standard practices (including this skill) will skip any directory or file matching these patterns.

### Recommended `.aiignore` Setup
To shield logs, temporary databases, and API trace mocks, create an `.aiignore` file and add:
```ignore
# Exclude raw application log files
*.log
logs/
npm-debug.log*

# Exclude local database backups and dumps
*.db
*.sqlite
*.sqlite3
dumps/
data/backup/

# Exclude local credentials
.env
.env.*
!.env.example
secrets/
```

---

## 4. Permanent Whitelisting of Synthetic Data (`.leakwhitelist`)

When developing locally or writing unit tests, projects often include synthetic testing data (such as mock API keys or mathematically valid test bank accounts). 

To prevent the scanner from alerting on these known safe mocks during every scan, you can record them in a `.leakwhitelist` file at the root of the workspace.

### How `.leakwhitelist` Works
*   The `.leakwhitelist` file contains exact strings (one per line) that should be whitelisted.
*   Comments starting with `#` and empty lines are skipped.
*   If the scanner finds a match that exactly matches a whitelisted string, it is automatically bypassed.

### Example `.leakwhitelist` Setup
```ignore
# permanent whitelist for synthetic test accounts
BE68 5390 0754 7034
74.06.25-123.44
555-44-3333
AIzaSyAz1234567890abcdefghijklmnopqrstuv
```
