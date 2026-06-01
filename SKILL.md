---
name: leak-canary
description: "Scan, audit, or check a project, directory, file, CSV export, log, or workspace for data leaks — credentials, API keys, secrets, PII, or GDPR violations — before pushing to GitHub, committing, sharing with external partners, archiving, or releasing. Invoke whenever the user asks to scan for secrets, check for leaks, audit for PII, review for credentials, or wants to verify GDPR compliance of exported data or test fixtures. Detects hardcoded passwords, AWS/Google/GitHub/Stripe/OpenAI/Azure keys, JWT tokens, database connection strings, email addresses, credit card numbers, IBANs, and 20+ European national IDs (Belgian INSZ, Dutch BSN, French INSEE, Polish PESEL, Swedish Personnummer, UK NINO, Spanish DNI, German Steuer-ID, Italian Codice Fiscale, Romanian CNP, Irish PPS, Portuguese NIF, and more). Use this skill proactively when the user mentions leaks, secrets, credentials, PII, GDPR, personal data, sensitive data, pre-commit checks, release security gates, or data export reviews."
license: MIT
compatibility: Node.js >= 12.0.0
---

# Leak Shield: Data Leak & PII Protection Skill

This skill guides you through checking a workspace or directory for credentials, secrets, PII (Personally Identifiable Information), and GDPR vulnerabilities, and interactive remediation.

## Step-by-Step Execution Guide

### 1. Verification of Runtime Environment
1. Check if Node.js is installed in the environment by executing:
   ```bash
   node --version
   ```
2. If Node.js is available, proceed to **Step 2A (Fast Programmatic Scan)**.
3. If Node.js is NOT available, proceed to **Step 2B (Agent Fallback Search)**.

---

### 2A. Fast Programmatic Scan (Recommended)
1. Run the scanning script, pointing it at the workspace you want to scan. The script
   lives inside this skill's own directory (e.g. `~/.agents/skills/leak-shield/`), which
   is usually **not** the project being scanned, so pass the target directory explicitly:
   ```bash
   node "<path-to-this-skill>/scripts/detect.js" "<path-to-workspace>"
   ```
   `<path-to-this-skill>` is the directory containing this SKILL.md. If you have already
   `cd`'d into the workspace, you can omit the second argument and it defaults to the
   current directory:
   ```bash
   node "<path-to-this-skill>/scripts/detect.js"
   ```
2. Parse the JSON output from the command. The output will contain a structured array of findings:
   ```json
   [
     {
       "file": "path/to/file.js",
       "line": 42,
       "category": "Secrets/Credentials",
       "leakType": "Generic API Key",
       "matchedText": "const apiKey = 'AIzaSyExampleKey123';",
       "obfuscated": "const apiKey = 'AIzaSy...xxxx';"
     }
   ]
   ```
3. Skip to **Step 3 (Analysis & De-duplication)**.

---

### 2B. Agent Fallback Search (Manual Regex)
1. If the scanner script cannot run, read the reference pattern library to load the search patterns:
   ```markdown
   Read references/leak-patterns.md
   ```
2. Execute a search using your search tools (e.g., `grep_search` or system `ripgrep`) across the workspace using the regexes from `references/leak-patterns.md`.
3. Filter out directories to avoid performance hangs:
   * Exclude `node_modules/`, `.git/`, `build/`, `dist/`, `.next/`, `.nuxt/`.
   * Honor exclusions in `.gitignore`, `.npmignore`, `.aiignore`, and `.cursorignore` files if present.

---

### 3. Analysis & De-duplication
1. Analyze the matched lines. Filter out:
   * Obvious standard system port numbers (e.g., `3000`, `8080`).
   * Explicitly documented testing placeholders (e.g., `placeholder@example.com`, `your-api-key-here`).
   * Read-only test files (e.g., mock data in `__tests__/` or `*.test.js`), unless they contain actual live credentials.
2. Group the remaining findings by file and line number.

---

### 4. Interactive Remediation Prompt
1. Present the filtered findings to the user as a clean markdown table.
2. **CRITICAL:** Do NOT show full API keys or private credentials in the chat. Use the obfuscated string (e.g., show `AIzaSy...xxxx` instead of the full key) to prevent secondary leaks in agent logs.
3. For each finding, prompt the user with a numbered list of choices:
   * **[1] Delete/Remove Line/Value:** Safely delete the hardcoded value or remove the line if it is obsolete.
   * **[2] Extract to Environment Variable:** Replace the hardcoded string with a dynamic reference (e.g., `process.env.MY_SECRET`) and append the key-value pair to a local `.env` file.
   * **[3] Hide from Future Scanning / Git:**
     * Option A: Add the file path to `.gitignore` (ignores from Git commits).
     * Option B: Add the file path to `.aiignore` (specifically shields it from future AI agent indexing and scans).
   * **[4] Whitelist/Keep:** Ignore the finding as a false positive or acceptable mock data (either just for this run, or permanently append the matched raw string to `.leakwhitelist` in the workspace root to skip it in all future scans).
4. **DO NOT** modify any files automatically. Wait for the user to specify their choices (e.g., "Do Option 2 for finding 1, Option 4 (permanent) for finding 2").

---

### 5. Executing Remediations
1. Based on the user's choices, modify files carefully:
   * To replace a secret, use exact line edits (`replace_file_content`).
   * To append to `.gitignore`, `.aiignore`, or `.leakwhitelist`, use a file edit/write tool, ensuring each entry is on a new line. When adding a permanent whitelist value, append the exact matched raw string (e.g., `BE68 5390 0754 7034`) to `.leakwhitelist`.
2. Ensure you do not introduce syntax errors during line deletions or variable replacements.

---

### 6. Post-Remediation Verification
1. Re-run the scan script (same invocation as Step 2A) or native regex search to verify that the active leaks have been fully addressed:
   ```bash
   node "<path-to-this-skill>/scripts/detect.js" "<path-to-workspace>"
   ```
2. Confirm to the user that the project is now safe from accidental leaks before they execute git commits or pushes.

---

## Pattern-Matching Examples

### Example 1: Credential Leak in Configuration File
**Scan Input:**
```
File: src/config/database.js
Line: 12
Matched Text: const dbUri = "mongodb+srv://admin:P@ssw0rd123!@cluster0.mongodb.net/prod";
```

**Agent Output to User:**
```markdown
### ⚠️ 1 Potential Leak Found in your Workspace!

| File | Line | Category | Description | Matched String (Obfuscated) |
| :--- | :--- | :--- | :--- | :--- |
| `src/config/database.js` | 12 | Secrets/Credentials | MongoDB Connection String | `const dbUri = "mongodb+srv://admin:******@cluster0.mongodb.net/prod";` |

How would you like to handle this finding?
* **[1]** Delete/Remove the connection string.
* **[2]** Extract to Environment Variable (`process.env.DB_URI`) and append to `.env`.
* **[3]** Add `src/config/database.js` to `.gitignore` / `.aiignore`.
* **[4]** Ignore (false positive).
```

---

## Troubleshooting

| Error / Failure | Root Cause | Fix |
| :--- | :--- | :--- |
| `SyntaxError: Unexpected token` | Running scanner on a file with unsupported syntax. | The scanner script handles file parsing safely with regex; if a custom tool errors, exclude the directory or file extension. |
| Node command fails with `MODULE_NOT_FOUND` or `Cannot find module` | The script path is wrong — the skill is installed outside the project, so a relative `leak-shield/scripts/detect.js` won't resolve. | Use the absolute path to this skill's `scripts/detect.js` and pass the workspace as the argument (see Step 2A). |
| Scanner reports zero findings on a project you expect to have leaks | Likely scanning the wrong directory (default is the current working directory). | Pass the target workspace explicitly as the second argument: `node "<skill>/scripts/detect.js" "<workspace>"`. |
| Scan returns hundreds of mock credentials | Scanning third-party dependencies or build files. | Exclude folders like `node_modules/` or build folders using `.aiignore` or `.gitignore`. |
| Script execution permission denied | Shell sandbox blocking node process. | Ask the user to run the script or execute it using the agent's explicit shell command run tool. |
