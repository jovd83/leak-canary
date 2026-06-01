#!/usr/bin/env node

/**
 * Leak Shield Scanner
 * A zero-dependency project scanner to detect PII, secrets, credentials, and GDPR issues.
 * Respects .gitignore, .npmignore, .aiignore, and .cursorignore.
 */

const fs = require('fs');
const path = require('path');
const readline = require('readline');

// Standard binary file extensions to completely ignore
const BINARY_EXTENSIONS = new Set([
  '.png', '.jpg', '.jpeg', '.gif', '.ico', '.svg', '.webp',
  '.pdf', '.zip', '.tar', '.gz', '.rar', '.7z',
  '.exe', '.dll', '.so', '.dylib', '.bin', '.dat',
  '.woff', '.woff2', '.ttf', '.eot',
  '.mp3', '.wav', '.mp4', '.avi', '.mkv', '.mov',
  '.db', '.sqlite', '.sqlite3'
  // NOTE: .csv / .dsv are intentionally NOT ignored. They are plain text and are the
  // single most common place real PII (emails, card numbers, national IDs) leaks into
  // a repo, which is exactly what this skill exists to catch.
]);

// Hardcoded system directories to always ignore
const SYSTEM_IGNORES = new Set([
  '.git',
  'node_modules',
  '.next',
  '.nuxt',
  'dist',
  'build',
  'out',
  '.docusaurus',
  '.cache',
  'package-lock.json',
  'yarn.lock',
  'pnpm-lock.yaml'
]);

// Patterns definitions
const PATTERNS = [
  // Secrets & Credentials
  {
    category: 'Secrets/Credentials',
    leakType: 'Generic Secret/Password',
    // Gap fix: original char class excluded !, |, /, etc. — common in real passwords.
    // [^'"`\s]{6,} matches any 6+ chars that aren't whitespace or the enclosing quote.
    regex: /(password|passwd|pass|pwd|secret|auth_token|client_secret|api_key|apikey|private_key)\s*[:=]\s*(['"`])([^'"`\s]{6,})\2/gi,
    obfuscate: (match, p1, _quote, p2) => `${p1} = "${p2.substring(0, Math.min(3, p2.length))}******"`,
    filter: (text) => {
      // Ignore false positives like "const port = 3000" or mock config
      const lower = text.toLowerCase();
      return !lower.includes('placeholder') && !lower.includes('example') && !lower.includes('your-');
    }
  },
  {
    category: 'Secrets/Credentials',
    leakType: 'Google API Key',
    // Real Google API keys are "AIza" + 35 chars = 39 total. Requiring the full
    // "AIzaSy" prefix plus 35 more would demand 41 chars and miss genuine keys.
    regex: /\bAIza[0-9A-Za-z\-_]{35}\b/g,
    obfuscate: (match) => `${match.substring(0, 8)}...xxxx`
  },
  {
    category: 'Secrets/Credentials',
    leakType: 'Slack Token',
    regex: /\bxox[bapr]-[0-9a-zA-Z]{10,12}-[0-9a-zA-Z]{24}\b/g,
    obfuscate: (match) => `${match.substring(0, 8)}...xxxx`
  },
  {
    category: 'Secrets/Credentials',
    leakType: 'AWS API Key',
    regex: /\bAKIA[0-9A-Z]{16}\b/g,
    obfuscate: (match) => `${match.substring(0, 6)}...xxxx`
  },
  {
    category: 'Secrets/Credentials',
    leakType: 'AWS Secret Access Key',
    regex: /aws_secret_access_key\s*[:=]\s*['"`]([0-9a-zA-Z\/+]{40})['"`]/gi,
    obfuscate: (match, p1) => `aws_secret_access_key = "${p1.substring(0, 4)}...xxxx"`
  },
  {
    category: 'Secrets/Credentials',
    leakType: 'Private Key block',
    regex: /-----BEGIN [A-Z ]+ PRIVATE KEY-----/g,
    obfuscate: () => '-----BEGIN PRIVATE KEY...xxxx'
  },
  {
    category: 'Secrets/Credentials',
    leakType: 'Generic DB Connection String',
    // Negative lookahead excludes localhost / 127.0.0.1 — documentation examples with those
    // hosts pose no real credential risk and generate noise in README-heavy repos.
    regex: /\b(mongodb(?:\+srv)?|postgres|postgresql|mysql|mssql):\/\/([^:]+):([^@]+)@(?!localhost\b|127\.0\.0\.1\b|::1\b)/gi,
    obfuscate: (match, proto, user) => `${proto}://${user}:******@`
  },
  {
    category: 'Secrets/Credentials',
    leakType: 'GitHub Personal Access Token',
    regex: /\b(?:ghp_[a-zA-Z0-9]{36}|github_pat_[a-zA-Z0-9_]{82})\b/g,
    obfuscate: (match) => `${match.substring(0, 8)}...xxxx`
  },
  {
    category: 'Secrets/Credentials',
    leakType: 'Stripe API Key',
    regex: /\b(?:sk|rk)_live_[a-zA-Z0-9]{24}\b/g,
    obfuscate: (match) => `${match.substring(0, 8)}...xxxx`
  },
  {
    category: 'Secrets/Credentials',
    leakType: 'OpenAI API Key',
    regex: /\bsk-(?:proj-)?[a-zA-Z0-9_\-]{40,100}\b/g,
    obfuscate: (match) => `${match.substring(0, 8)}...xxxx`
  },
  {
    category: 'Secrets/Credentials',
    leakType: 'Slack Webhook URL',
    regex: /\bhttps:\/\/hooks\.slack\.com\/services\/T[A-Z0-9]{8}\/B[A-Z0-9]{8}\/[A-Za-z0-9]{24}\b/g,
    obfuscate: (match) => `${match.substring(0, 32)}...xxxx`
  },
  {
    category: 'Secrets/Credentials',
    leakType: 'Discord Webhook or Bot Token',
    regex: /\b(?:https:\/\/discord\.com\/api\/webhooks\/\d{17,20}\/[A-Za-z0-9\-]{68}|[A-Za-z0-9\-]{24}\.[A-Za-z0-9\-]{6}\.[A-Za-z0-9\-]{27})\b/g,
    obfuscate: (match) => `${match.substring(0, 24)}...xxxx`
  },
  {
    category: 'Secrets/Credentials',
    leakType: 'Twilio Account SID',
    regex: /\bAC[0-9a-fA-F]{32}\b/g,
    obfuscate: (match) => `${match.substring(0, 6)}...xxxx`
  },
  {
    category: 'Secrets/Credentials',
    leakType: 'Mailgun API Key',
    regex: /\bkey-[0-9a-zA-Z]{32}\b/g,
    obfuscate: (match) => `${match.substring(0, 8)}...xxxx`
  },
  {
    category: 'Secrets/Credentials',
    leakType: 'SendGrid API Key',
    regex: /\bSG\.[a-zA-Z0-9\-_]{22}\.[a-zA-Z0-9\-_]{43}\b/g,
    obfuscate: (match) => `${match.substring(0, 8)}...xxxx`
  },
  
  // PII / GDPR Vulnerabilities
  {
    category: 'GDPR/PII',
    leakType: 'Email Address',
    regex: /\b[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}\b/g,
    obfuscate: (match) => {
      const parts = match.split('@');
      const name = parts[0];
      return `${name[0]}***@${parts[1]}`;
    },
    filter: (text) => {
      // Exclude standard documentation/testing domains
      const lower = text.toLowerCase();
      return !lower.includes('example.com') && !lower.includes('test.com') && !lower.includes('localhost') && !lower.includes('user@domain') && !lower.includes('yourdomain.com') && !lower.includes('domain.com') && !lower.includes('@domain');
    }
  },
  {
    category: 'GDPR/PII',
    leakType: 'US Phone Number',
    // Gap fix: \b before ( fails after comma in CSV — (415) 867-5309 was not detected.
    // Negative lookbehind (?<![0-9A-Za-z_]) blocks mid-word matches without that problem.
    regex: /(?<![0-9A-Za-z_])(?:\+?1[-. ]?)?(?:\(([0-9]{3})\)[-. ]*|([0-9]{3})[-. ]+)([0-9]{3})[-. ]+([0-9]{4})\b/g,
    obfuscate: (match, p1, p2, p3, p4) => {
      const area = p1 || p2;
      return `(${area}) ***-**${p4.substring(2)}`;
    },
    filter: (text) => {
      return !text.toLowerCase().includes('555-');
    }
  },
  {
    category: 'GDPR/PII',
    leakType: 'Credit Card Number',
    // Match 13-19 digit candidates allowing single space/hyphen separators between
    // groups, because real card leaks (CSVs, dumps) are almost always grouped like
    // "4111 1111 1111 1111". Brand-prefix + Luhn validation in the filter keeps precision.
    regex: /\b\d(?:[ -]?\d){11,18}\b/g,
    obfuscate: (match) => `****-****-****-${match.replace(/[-\s]/g, '').slice(-4)}`,
    filter: (text) => {
      const clean = text.replace(/[-\s]/g, '');
      if (!/^\d{13,19}$/.test(clean)) return false;
      // Require a recognized card brand prefix to avoid flagging arbitrary numbers.
      const brand = /^(?:4\d{12}(?:\d{3})?(?:\d{3})?|5[1-5]\d{14}|2(?:2[2-9]|[3-6]\d|7[01])\d{12}|3[47]\d{13}|6(?:011|5\d{2})\d{12}|3(?:0[0-5]|[68]\d)\d{11}|(?:2131|1800|35\d{3})\d{11})$/.test(clean);
      if (!brand) return false;
      // Luhn checksum to prevent massive false positives.
      let sum = 0;
      let shouldDouble = false;
      for (let i = clean.length - 1; i >= 0; i--) {
        let digit = parseInt(clean.charAt(i), 10);
        if (shouldDouble) {
          digit *= 2;
          if (digit > 9) digit -= 9;
        }
        sum += digit;
        shouldDouble = !shouldDouble;
      }
      return (sum % 10) === 0;
    }
  },
  {
    category: 'GDPR/PII',
    leakType: 'IBAN Bank Account',
    regex: /\b[A-Z]{2}\d{2}(?:[ ]?[A-Z0-9]){11,30}\b/g,
    obfuscate: (match) => {
      const clean = match.replace(/\s+/g, '');
      return `${clean.substring(0, 4)}******${clean.slice(-4)}`;
    },
    filter: (text) => {
      const clean = text.replace(/[\s-]/g, '').toUpperCase();
      if (clean.length < 15 || clean.length > 34) return false;
      const rearranged = clean.substring(4) + clean.substring(0, 4);
      let digits = '';
      for (let i = 0; i < rearranged.length; i++) {
        const char = rearranged[i];
        const code = char.charCodeAt(0);
        if (code >= 65 && code <= 90) {
          digits += String(code - 55);
        } else {
          digits += char;
        }
      }
      let remainder = 0;
      for (let i = 0; i < digits.length; i += 7) {
        const chunk = String(remainder) + digits.substring(i, i + 7);
        remainder = parseInt(chunk, 10) % 97;
      }
      return remainder === 1;
    }
  },
  {
    category: 'GDPR/PII',
    leakType: 'Belgian INSZ / Rijksregisternummer',
    regex: /\b(?:\d{2}\.\d{2}\.\d{2}-\d{3}\.\d{2}|\d{6}-\d{5}|\d{11})\b/g,
    obfuscate: (match) => {
      const clean = match.replace(/[\.-]/g, '');
      return `${clean.substring(0, 6)}-***.**`;
    },
    filter: (text) => {
      const clean = text.replace(/[\.-]/g, '');
      if (clean.length !== 11) return false;
      const baseNumStr = clean.substring(0, 9);
      const checksum = parseInt(clean.substring(9), 10);
      const baseNum1 = parseInt(baseNumStr, 10);
      const remainder1 = baseNum1 % 97;
      if ((97 - remainder1) === checksum) return true;
      const baseNum2 = parseInt('2' + baseNumStr, 10);
      const remainder2 = baseNum2 % 97;
      return (97 - remainder2) === checksum;
    }
  },
  {
    category: 'GDPR/PII',
    leakType: 'US Social Security Number (SSN)',
    regex: /\b\d{3}-\d{2}-\d{4}\b/g,
    obfuscate: (match) => `***-**-${match.slice(-4)}`,
    filter: (text) => {
      const parts = text.split('-');
      const area = parseInt(parts[0], 10);
      const group = parseInt(parts[1], 10);
      const serial = parseInt(parts[2], 10);
      if (area === 0 || area === 666 || area >= 900) return false;
      if (group === 0) return false;
      if (serial === 0) return false;
      return true;
    }
  },
  {
    category: 'GDPR/PII',
    leakType: 'French INSEE / Social Security Number',
    regex: /\b[12]\d{2}(?:0[1-9]|1[0-2])\d{10}\b/g,
    obfuscate: (match) => `${match.substring(0, 5)}******${match.slice(-2)}`,
    filter: (text) => {
      if (text.length !== 15) return false;
      const baseNumStr = text.substring(0, 13);
      const controlKey = parseInt(text.substring(13), 10);
      const baseNum = parseInt(baseNumStr, 10);
      const remainder = baseNum % 97;
      return (97 - remainder) === controlKey;
    }
  },
  {
    category: 'GDPR/PII',
    leakType: 'German Steuer-ID (Tax ID)',
    regex: /\b[1-9]\d{10}\b/g,
    obfuscate: (match) => `${match.substring(0, 3)}*****${match.slice(-3)}`,
    filter: (text) => {
      if (text.length !== 11 || text[0] === '0') return false;
      const first10 = text.substring(0, 10);
      const counts = {};
      for (let i = 0; i < 10; i++) {
        const digit = first10[i];
        counts[digit] = (counts[digit] || 0) + 1;
      }
      let doubleCount = 0;
      let tripleCount = 0;
      let otherOverOne = false;
      for (const digit in counts) {
        if (counts[digit] === 2) doubleCount++;
        else if (counts[digit] === 3) tripleCount++;
        else if (counts[digit] > 1) otherOverOne = true;
      }
      if (otherOverOne || (doubleCount !== 1 && tripleCount !== 1)) return false;
      const checksum = parseInt(text[10], 10);
      let product = 10;
      for (let i = 0; i < 10; i++) {
        const digit = parseInt(first10[i], 10);
        let sum = (digit + product) % 10;
        if (sum === 0) sum = 10;
        product = (sum * 2) % 11;
      }
      let calcChecksum = 11 - product;
      if (calcChecksum === 11) calcChecksum = 0;
      else if (calcChecksum === 10) calcChecksum = 9;
      return calcChecksum === checksum || (calcChecksum === 10 && checksum === 9);
    }
  },
  {
    category: 'GDPR/PII',
    leakType: 'Dutch BSN (Burgerservicenummer)',
    regex: /\b\d{9}\b/g,
    obfuscate: (match) => `${match.substring(0, 3)}***${match.slice(-3)}`,
    filter: (text) => {
      if (text.length !== 9) return false;
      let sum = 0;
      for (let i = 0; i < 8; i++) {
        sum += parseInt(text[i], 10) * (9 - i);
      }
      sum -= parseInt(text[8], 10);
      return sum % 11 === 0;
    }
  },
  {
    category: 'GDPR/PII',
    leakType: 'Spanish DNI/NIE Identity Number',
    regex: /\b(?:[XYZ]\d{7}|\d{8})[A-Z]\b/gi,
    obfuscate: (match) => `${match.substring(0, 4)}***${match.slice(-1)}`,
    filter: (text) => {
      const clean = text.toUpperCase();
      let numStr = clean.slice(0, -1);
      const letter = clean.slice(-1);
      if (numStr[0] === 'X') numStr = '0' + numStr.substring(1);
      else if (numStr[0] === 'Y') numStr = '1' + numStr.substring(1);
      else if (numStr[0] === 'Z') numStr = '2' + numStr.substring(1);
      const num = parseInt(numStr, 10);
      if (isNaN(num)) return false;
      const letters = "TRWAGMYFPDXBNJZSQVHLCKE";
      const index = num % 23;
      return letters[index] === letter;
    }
  },
  {
    category: 'GDPR/PII',
    leakType: 'UK National Insurance Number (NINO)',
    regex: /\b[A-CEGHJ-PR-TW-Z][A-CEGHJ-NPR-TW-Z]\s*\d{2}\s*\d{2}\s*\d{2}\s*[A-D]\b/gi,
    obfuscate: (match) => {
      const clean = match.replace(/\s+/g, '');
      return `${clean.substring(0, 2)} ${clean.substring(2, 4)} ${clean.substring(4, 6)} *** ${clean.slice(-1)}`;
    }
  },
  {
    category: 'GDPR/PII',
    leakType: 'European Vehicle License Plate',
    regex: /\b(?:[A-Z]{2}-\d{3}-[A-Z]{2}|[A-Z]{2}\d{2}\s*[A-Z]{3}|\d{4}[ -]?[BCDFGHJKLMNPQRSTVWXYZ]{3}|[A-Z]{2}\s*\d{3}[A-Z]{2}|[A-Z]{1,3}-[A-Z]{1,2}\s+\d{1,4}|[12]-[A-Z]{3}-\d{3}|[MOTQY]-[A-Z]{3}-\d{3}|[A-Z]{3}-\d{3}|\d{3}-[A-Z]{3})\b/gi,
    obfuscate: (match) => `${match.substring(0, 2)}***${match.slice(-2)}`,
    filter: (text) => {
      // Avoid false positive matches on regex character classes or programming brackets in files
      return !text.includes('[') && !text.includes(']') && !text.includes('\\') && !text.includes('{') && !text.includes('}');
    }
  },
  {
    category: 'GDPR/PII',
    leakType: 'Italian Codice Fiscale',
    regex: /\b[A-Z]{6}\d{2}[A-EHLMPR-T]\d{2}[A-Z]\d{3}[A-Z]\b/gi,
    obfuscate: (match) => `${match.substring(0, 6)}******${match.slice(-3)}`
  },
  {
    category: 'GDPR/PII',
    leakType: 'Austrian SV-Nummer (Social Security)',
    regex: /\b\d{10}\b/g,
    obfuscate: (match) => `${match.substring(0, 4)}***${match.slice(-3)}`,
    filter: (text) => {
      if (text.length !== 10) return false;
      const digits = text.split('').map(Number);
      const weights = [3, 7, 9, 0, 5, 8, 4, 2, 1, 6];
      let sum = 0;
      for (let i = 0; i < 10; i++) {
        sum += digits[i] * weights[i];
      }
      const remainder = sum % 11;
      if (remainder === 10) return false;
      return remainder === digits[3];
    }
  },
  {
    category: 'GDPR/PII',
    leakType: 'Swiss AHV / OASI Number',
    regex: /\b756\.\d{4}\.\d{4}\.\d{2}\b/g,
    obfuscate: (match) => `756.****.****.${match.slice(-2)}`,
    filter: (text) => {
      // Validates Swiss AHV number using EAN-13 check digit logic
      const clean = text.replace(/\./g, '');
      if (clean.length !== 13) return false;
      let sum = 0;
      for (let i = 0; i < 12; i++) {
        const digit = parseInt(clean[i], 10);
        sum += (i % 2 === 0) ? digit * 1 : digit * 3;
      }
      const checkDigit = parseInt(clean[12], 10);
      const calcDigit = (10 - (sum % 10)) % 10;
      return calcDigit === checkDigit;
    }
  },
  {
    category: 'GDPR/PII',
    leakType: 'Polish PESEL Number',
    regex: /\b\d{11}\b/g,
    obfuscate: (match) => `${match.substring(0, 4)}*****${match.slice(-2)}`,
    filter: (text) => {
      if (text.length !== 11) return false;
      const weights = [1, 3, 7, 9, 1, 3, 7, 9, 1, 3, 1];
      let sum = 0;
      for (let i = 0; i < 11; i++) {
        sum += parseInt(text[i], 10) * weights[i];
      }
      return sum % 10 === 0;
    }
  },
  {
    category: 'GDPR/PII',
    leakType: 'Swedish Personnummer',
    regex: /\b(?:\d{6}|\d{8})[-+]\d{4}\b/g,
    obfuscate: (match) => `${match.substring(0, 6)}-***${match.slice(-1)}`,
    filter: (text) => {
      const clean = text.replace(/[-+]/g, '');
      let tenDigits = clean;
      if (clean.length === 12) {
        tenDigits = clean.substring(2);
      }
      if (tenDigits.length !== 10) return false;
      let sum = 0;
      let shouldDouble = true;
      for (let i = 0; i < 10; i++) {
        let digit = parseInt(tenDigits[i], 10);
        if (shouldDouble) {
          digit *= 2;
          if (digit > 9) digit -= 9;
        }
        sum += digit;
        shouldDouble = !shouldDouble;
      }
      return sum % 10 === 0;
    }
  },
  {
    category: 'GDPR/PII',
    leakType: 'Finnish Personal Identity Code (HETU)',
    regex: /\b\d{6}[-+A]\d{3}[0-9A-Y]\b/gi,
    obfuscate: (match) => `${match.substring(0, 6)}-***${match.slice(-1)}`,
    filter: (text) => {
      const clean = text.toUpperCase();
      const dob = clean.substring(0, 6);
      const individual = clean.substring(7, 10);
      const checksumChar = clean.slice(-1);
      const num = parseInt(dob + individual, 10);
      if (isNaN(num)) return false;
      const checkMap = "0123456789ABCDEFHJKLMNPRSTUVWXY";
      const index = num % 31;
      return checkMap[index] === checksumChar;
    }
  },

  // ── New detectors added in v1.2.0 ────────────────────────────────────

  {
    category: 'Secrets/Credentials',
    leakType: 'JWT Token',
    // eyJ is base64url of '{"' — the start of every JWT header. Three-part structure
    // with dots is extremely specific; false positives are negligible in practice.
    regex: /eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+/g,
    obfuscate: (match) => `${match.substring(0, 12)}...xxxx`
  },
  {
    category: 'Secrets/Credentials',
    leakType: 'Azure Storage Account Key',
    // Azure storage keys are exactly 512-bit = 86 base64 chars + '==' padding.
    regex: /AccountKey=[A-Za-z0-9+\/]{86}==/g,
    obfuscate: (match) => `AccountKey=${match.substring(11, 19)}...xxxx`
  },
  {
    category: 'Secrets/Credentials',
    leakType: 'Generic Bearer Token',
    // Catches opaque long-lived tokens in Authorization headers and source files.
    // Named 'Generic' so the rank function prefers a more specific overlapping match
    // (e.g. JWT Token) over this one.
    regex: /[Bb]earer\s+([A-Za-z0-9._\-]{40,})\b/g,
    obfuscate: (match, p1) => `Bearer ${p1.substring(0, 8)}...xxxx`,
    filter: (text) => !text.includes('{') && !text.includes('}')
  },
  {
    category: 'GDPR/PII',
    leakType: 'Portuguese NIF (Tax ID)',
    // 9-digit Portuguese tax number. First-digit constraint and mod-11 checksum.
    // Excludes numbers that also pass Dutch BSN checksum to avoid dual-reporting.
    regex: /\b[1-9]\d{8}\b/g,
    obfuscate: (match) => `${match.substring(0, 3)}***${match.slice(-3)}`,
    filter: (text) => {
      if (text.length !== 9) return false;
      const first = parseInt(text[0]);
      if (![1, 2, 3, 5, 6, 8, 9].includes(first)) return false;
      const weights = [9, 8, 7, 6, 5, 4, 3, 2];
      let sum = 0;
      for (let i = 0; i < 8; i++) sum += parseInt(text[i]) * weights[i];
      const rem = sum % 11;
      const check = rem < 2 ? 0 : 11 - rem;
      if (check !== parseInt(text[8])) return false;
      // Skip if it also passes Dutch BSN (BSN pattern already handles it)
      let bsnSum = 0;
      for (let i = 0; i < 8; i++) bsnSum += parseInt(text[i]) * (9 - i);
      bsnSum -= parseInt(text[8]);
      return bsnSum % 11 !== 0;
    }
  },
  {
    category: 'GDPR/PII',
    leakType: 'Irish PPS Number',
    // Irish Personal Public Service Number: 7 digits + check letter [+ type letter].
    regex: /\b\d{7}[A-W]{1,2}\b/gi,
    obfuscate: (match) => `${match.substring(0, 4)}***${match.slice(-1)}`,
    filter: (text) => {
      const upper = text.toUpperCase();
      if (!/^\d{7}[A-W]{1,2}$/.test(upper)) return false;
      const weights = [8, 7, 6, 5, 4, 3, 2];
      let sum = 0;
      for (let i = 0; i < 7; i++) sum += parseInt(upper[i]) * weights[i];
      const checkMap = 'WABCDEFGHIJKLMNOPQRSTUV';
      return checkMap[sum % 23] === upper[7];
    }
  },
  {
    category: 'GDPR/PII',
    leakType: 'Romanian CNP',
    // Romanian Personal Numeric Code: 13 digits, first digit 1-8, weighted mod-11 check.
    regex: /\b[1-8]\d{12}\b/g,
    obfuscate: (match) => `${match.substring(0, 4)}*****${match.slice(-4)}`,
    filter: (text) => {
      if (text.length !== 13) return false;
      const weights = [2, 7, 9, 1, 4, 6, 3, 5, 8, 2, 7, 9];
      let sum = 0;
      for (let i = 0; i < 12; i++) sum += parseInt(text[i]) * weights[i];
      let check = sum % 11;
      if (check === 10) check = 1;
      return check === parseInt(text[12]);
    }
  },
  {
    category: 'GDPR/PII',
    leakType: 'MAC Address',
    // MAC addresses in network logs can directly identify individual devices and users.
    regex: /\b[0-9A-Fa-f]{2}(?:[-:][0-9A-Fa-f]{2}){5}\b/g,
    obfuscate: (match) => `${match.substring(0, 8)}:XX:XX`,
    filter: (text) => {
      const clean = text.replace(/[-:]/g, '').toUpperCase();
      return clean !== 'FFFFFFFFFFFF' && clean !== '000000000000';
    }
  }
];

// Read user ignore files and convert to array of patterns
function loadIgnorePatterns(workspaceDir) {
  const ignoreFiles = ['.gitignore', '.npmignore', '.aiignore', '.cursorignore'];
  const patterns = [];
  
  for (const filename of ignoreFiles) {
    const filePath = path.join(workspaceDir, filename);
    if (fs.existsSync(filePath)) {
      try {
        const content = fs.readFileSync(filePath, 'utf8');
        const lines = content.split(/\r?\n/);
        for (let line of lines) {
          line = line.trim();
          // Skip empty lines and comments
          if (line && !line.startsWith('#')) {
            patterns.push({
              source: filename,
              raw: line,
              // Convert glob-like pattern to basic regex
              regex: globToRegex(line)
            });
          }
        }
      } catch (err) {
        // Ignore file read errors silently
      }
    }
  }
  return patterns;
}

// Read user whitelist file containing values to always skip
function loadWhitelist(workspaceDir) {
  const filePath = path.join(workspaceDir, '.leakwhitelist');
  const whitelist = new Set();
  
  if (fs.existsSync(filePath)) {
    try {
      const content = fs.readFileSync(filePath, 'utf8');
      const lines = content.split(/\r?\n/);
      for (let line of lines) {
        line = line.trim();
        // Skip empty lines and comments
        if (line && !line.startsWith('#')) {
          whitelist.add(line);
        }
      }
    } catch (err) {
      // Ignore file read errors silently
    }
  }
  return whitelist;
}

// Convert gitignore glob pattern to RegExp
function globToRegex(glob) {
  let p = glob;
  // Handle folder-only rules (trailing slash)
  let isDirectoryOnly = false;
  if (p.endsWith('/')) {
    p = p.slice(0, -1);
    isDirectoryOnly = true;
  }
  
  // Escape regex special chars
  let regexStr = p.replace(/[.+^${}()|[\]\\]/g, '\\$&');
  // Match * as anything except /
  regexStr = regexStr.replace(/\*/g, '[^/]*');
  // Match ? as any single char except /
  regexStr = regexStr.replace(/\?/g, '[^/]');
  
  // If rule has no slashes, match it anywhere (file/dir name)
  if (!p.includes('/')) {
    regexStr = `(^|/)${regexStr}(/|$)`;
  } else {
    // If it starts with a slash, anchor it to start
    if (p.startsWith('/')) {
      regexStr = `^${regexStr.slice(1)}`;
    } else {
      regexStr = `(^|/)${regexStr}`;
    }
  }
  
  if (isDirectoryOnly) {
    regexStr += '(/.*)?$';
  } else {
    regexStr += '(/.*)?$';
  }
  
  try {
    return new RegExp(regexStr);
  } catch (e) {
    // Fallback simple search
    return new RegExp(p.replace(/[-[\]{}()*+?.,\\^$|#\s]/g, '\\$&'));
  }
}

// Check if a path should be ignored
function isIgnored(relativePath, ignorePatterns) {
  const normPath = relativePath.replace(/\\/g, '/');
  
  // Check hardcoded defaults
  const parts = normPath.split('/');
  for (const part of parts) {
    if (SYSTEM_IGNORES.has(part)) {
      return true;
    }
  }
  
  // Check loaded patterns
  for (const item of ignorePatterns) {
    if (item.regex.test(normPath) || item.regex.test('/' + normPath)) {
      return true;
    }
  }
  
  return false;
}

// Recursively walk a directory and gather text files
function getFilesToScan(dir, workspaceDir, ignorePatterns, fileList = []) {
  let files;
  try {
    files = fs.readdirSync(dir);
  } catch (err) {
    return fileList;
  }
  
  for (const file of files) {
    const absolutePath = path.join(dir, file);
    const relativePath = path.relative(workspaceDir, absolutePath);
    
    if (isIgnored(relativePath, ignorePatterns)) {
      continue;
    }
    
    let stats;
    try {
      stats = fs.statSync(absolutePath);
    } catch (err) {
      continue;
    }
    
    if (stats.isDirectory()) {
      getFilesToScan(absolutePath, workspaceDir, ignorePatterns, fileList);
    } else if (stats.isFile()) {
      const ext = path.extname(file).toLowerCase();
      if (!BINARY_EXTENSIONS.has(ext)) {
        fileList.push(absolutePath);
      }
    }
  }
  
  return fileList;
}

// Scan a single file line-by-line
async function scanFile(filePath, workspaceDir, whitelist = new Set()) {
  const findings = [];
  const relativePath = path.relative(workspaceDir, filePath);
  
  return new Promise((resolve) => {
    let lineNum = 0;
    const fileStream = fs.createReadStream(filePath);
    
    const rl = readline.createInterface({
      input: fileStream,
      crlfDelay: Infinity
    });
    
    rl.on('line', (line) => {
      lineNum++;

      // Keep line search efficient: skip extremely long lines (minified files)
      if (line.length > 1000) return;

      const lineFindings = [];
      for (const rule of PATTERNS) {
        rule.regex.lastIndex = 0; // Reset state
        let match;

        while ((match = rule.regex.exec(line)) !== null) {
          const matchedString = match[0];
          const start = match.index;
          const end = start + matchedString.length;

          // Guard against zero-width matches causing an infinite loop
          if (matchedString.length === 0) {
            rule.regex.lastIndex++;
            continue;
          }

          // Skip if whitelisted
          const cleanMatched = matchedString.trim();
          if (whitelist.has(cleanMatched) || whitelist.has(matchedString)) {
            continue;
          }

          // Apply custom filter if defined
          if (rule.filter && !rule.filter(matchedString)) {
            continue;
          }

          let obfuscated = matchedString;
          if (rule.obfuscate) {
            obfuscated = rule.obfuscate(...match);
          }

          lineFindings.push({
            file: relativePath.replace(/\\/g, '/'),
            line: lineNum,
            category: rule.category,
            leakType: rule.leakType,
            matchedText: matchedString,
            obfuscated: obfuscated,
            start: start,
            end: end
          });
        }
      }

      // Suppress a finding when another, higher-priority finding overlaps the same
      // characters. This removes noise like a connection string's password being
      // re-reported as an "email": the credential finding already covers that region,
      // so the overlapping PII match is redundant. Credentials outrank PII; ties break
      // on span length so the more specific (longer) match wins.
      // Gap fix: specific leakTypes (OpenAI, Google, etc.) were being overshadowed by longer
      // Generic Secret/Password spans. Non-generic patterns now get a 100 000-point bonus
      // so they always beat a generic match that covers the same region.
      const rank = (f) => (f.category === 'Secrets/Credentials' ? 1e6 : 0) + (f.leakType.startsWith('Generic') ? 0 : 100000) + (f.end - f.start);
      for (const f of lineFindings) {
        const overshadowed = lineFindings.some((other) =>
          other !== f &&
          other.start < f.end && other.end > f.start && // spans overlap
          rank(other) > rank(f)
        );
        if (overshadowed) continue;
        const { start, end, ...clean } = f;
        findings.push(clean);
      }
    });
    
    rl.on('close', () => {
      resolve(findings);
    });
    
    fileStream.on('error', () => {
      resolve([]); // Resolve empty list on read errors
    });
  });
}

// Main function
async function main() {
  // Scan target defaults to the current working directory, but accepts an explicit
  // path argument. This matters because the skill is normally installed OUTSIDE the
  // project being scanned (e.g. ~/.agents/skills/leak-shield), so the agent can run
  // `node <skill>/scripts/detect.js <workspace>` without having to cd first.
  const workspaceDir = process.argv[2] ? path.resolve(process.argv[2]) : process.cwd();
  
  // Load ignore definitions (.gitignore, .aiignore, etc.)
  const ignorePatterns = loadIgnorePatterns(workspaceDir);
  
  // Load whitelist of test credentials
  const whitelist = loadWhitelist(workspaceDir);
  
  // Recursively collect all scan targets
  const filesToScan = getFilesToScan(workspaceDir, workspaceDir, ignorePatterns);
  
  const allFindings = [];
  for (const file of filesToScan) {
    const fileFindings = await scanFile(file, workspaceDir, whitelist);
    allFindings.push(...fileFindings);
  }
  
  // Output findings in clean JSON format
  console.log(JSON.stringify(allFindings, null, 2));
}

main().catch(err => {
  console.error(err);
  process.exit(1);
});
