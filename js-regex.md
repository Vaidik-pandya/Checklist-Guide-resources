# Regex for Bug Bounty Hunters (Web): An In-Depth Guide

## What is Regex?
Regular expressions (**regex**) are strings of characters used to define **search patterns**. In web hacking and bug bounty, regex is invaluable for automating the parsing, searching, and extraction of data from large blocks of text or code, such as HTTP responses, source code, or logs. Regex patterns range from simple to advanced[1].

---

## Why Use Regex in Web Bug Bounty?

### Key Uses:
- **Automating Recon:** Extract URLs, parameters, or domains from responses.
- **Payload Crafting/Filtering:** Validate or bypass WAFs and input filters.
- **Finding Vulnerable Patterns:** Identify common vulnerabilities (e.g., XSS, SQLi).
- **Log/Response Analysis:** Filter indicators from large logs for anomalies.

**Example – Extracting all URLs:**
(http://|https://).*?(?="|'| )

Matches anything starting with `http://` or `https://` until a quote or space[1].

---

## Fundamental Regex Concepts

| Symbol   | Function                          | Example         |
|----------|-----------------------------------|-----------------|
| .        | Any single character              | `.bc` → abc, bbc |
| *        | Zero/more repetitions             | `a*` → "", "a", "aa" |
| +        | One/more repetitions              | `a+` → "a", "aa" |
| ?        | Zero/one repetition               | `a?` → "", "a" |
| ^        | Start of line                     | `^abc` at start |
| $        | End of line                       | `abc$` at end   |
| []       | Character set                     | `[a-zA-Z]`      |
| \|       | OR                                | `abc|def`       |
| ()       | Grouping                          | `(ab)+` → "ab", "abab" |
| {n,m}    | n to m repetitions                | `a{1,3}` → "a", "aa", "aaa" |

---

## Practical Bug Bounty Regex Examples

### 1. Extracting Domains and Parameters
https?://([^/?#]+)

Finds HTML tags with event-handler attributes.

*Advanced – Match newlines too:*
<[\s\S]on[\s\S]=[\s\S]*>


Ensures newline coverage[5].

### 3. Bypassing Weak Regex-Based Filters
Developers may whitelist/block URLs with:

^https?://example.com/[\w]*

Attackers can bypass:
https://plantuml.com@evil.com

Understand such bypasses for regex-based filters[6].

---

## Regex Catastrophes: ReDoS (Regex Denial of Service)

Regex such as `^(a+)+$` can be exploited to create server slowdowns (ReDoS).

**Hunt for:**
- Filters with nested quantifiers
- User-controlled regex in APIs/search
- High-amplification vectors[4][1]

---

## Advanced Techniques

### Regex Fuzzing
Automate fuzz testing for regex-based filters:

- Use diverse input patterns and encoding
- Prefer `[\s\S]*` over `.*` for full coverage
- Explore tools like Regaxor for fuzz-based testing[7]

### Word Boundaries
Filters with `\bword\b` can be bypassed using payload variations[2].

### Escaping and Encoding Traps
Watch out for inconsistent wildcards and escaping:

- Double-check escape sequences
- Use encoding/unicode variations to exploit weak filters[7]

---

## Common Regex Pitfalls

- Incorrect anchors (`^`/`$`)
- Poor character class/range choices
- Multiline and dotall issues (`.` vs. `[\s\S]`)
- Over-acceptance (ReDoS)
- Bad grouping/order
- Improper escaping[7]

---

## Essential Bug Bounty Regex Tools

- Regex101: Test/debug regex
- pcregrep, grep -P: CLI regex parsing
- Burp Suite: Regex for match/filter rules
- Custom Scripts: Python/JS/bash automation[1]

---

## Cheat Sheet

- **XSS**: `<.*on.*=.*>`
- **SQLi Param**: `[\?&]([^=]+)=([^&]+)`
- **Email**: `[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+`
- **URL Extraction**: `https?:\/\/[^\s"'<>]+`

---

## Final Tips

- Test regexes on real-world payloads.
- Beware: regex can be slow or crash apps.
- Learn differences between language/framework regex support.
- Document bypasses for reporting and automation.

> Regex is powerful for parsing but dangerous to production if misused. As a bug bounty hunter, understanding developer regex mistakes is key to great findings[1][3][1][2].


# Playing with Regex to Find Bugs in JavaScript Files for Bug Bounty

When hunting on a web app and finding many JavaScript files, you can use regex to extract secrets, endpoints, parameters, and more.

---

## 1. Searching for Secrets and Credentials

- Search for keywords like:
  - `api_key`
  - `accessToken`
  - `secret`
  - `password`
  - `token`
  - `bearer`

- Regex patterns:
(accessToken|secret|api[_-]?key|token|password)\s*[:=]\s*['"][^'"]+['"]


- CLI Example:
grep -Ero "(accessToken|secret|_key)\s*[:=]\s*['"][^'"\s]+" /path/to/js/files


Helps spot hardcoded credentials and secrets.

- Use resources like [secrets-patterns-db](https://github.com/mazen160/secrets-patterns-db) for curated regex for AWS, Stripe, Twilio keys, etc.

---

## 2. Finding API Endpoints, Sensitive Routes, and Variables

- Extract endpoints or URLs:
(https?:\/\/[^\s'"]+)|(fetch\s*\(|xhr\.open\s*\(|\$.ajax\s*\(\s*{[^}]*data\s*:\s*['"][^'"]+['"])


- Find internal APIs or hidden routes:
grep -Eo "(api|endpoint|url|route|path)\s*[:=]\s*['"][^'"\s]+" ./



---

## 3. Enumerating Parameters and Input Names

- Regex for GET/POST parameters:
?&=


---

## 4. Detecting Potentially Vulnerable Functions

- Find dangerous JS functions:
(eval|document.write|innerHTML|setTimeout|setInterval|Function)\s*$$


---

## 5. Analyzing Minified or Obfuscated Files

- Use code formatting tools (`prettier`, browser DevTools) to unminify code.
- Run regex patterns on prettified code and look for source maps (`.js.map`) for richer source.

---

## 6. Bypassing Regex-Based WAF or Filters

- Identify input validation or filtering regexes in JS source.
- Look for weak, overly simple patterns (e.g. `<.*on.*=.*>`).
- Try exotic payloads and alternative encodings to bypass validation.

---

## 7. Automating with Tools

- Use JSFScan.sh, LinkFinder, GfPatterns, etc. for regex-based JS bug hunting.
- Write custom scripts in Python or bash (with `grep`, `sed`, `awk`) for bulk automation.

---

## 8. Targeting Common Regex Pitfalls

- Seek out:
- Incorrect escaping or quantifiers
- Missing case-insensitivity
- Overly broad or generic patterns
- ReDoS (catastrophic backtracking)
- Function assignment pattern:

[a-zA-Z0-9_]+\s*=\sfunction\s$$


---

**Tip:** Combine regex scanning with manual code review; secrets and bugs can hide in comments, disguised variable names, or unusual logic.


# 100 Regex Patterns for Bug Bounty Hunting Web Applications

## 1-20: Keys, Tokens, Secrets  
- `(api|api[_-]?key|secret|token|authorization|auth|access_token|bearer)[\s:=]+['"]?[a-zA-Z0-9_\-\.]{16,}['"]?`  
- `aws[_-]?(access|secret)[-_]?key[\s:=]+['"]?[a-zA-Z0-9\/+=]{16,}['"]?`  
- `ghp_[a-zA-Z0-9]{36}` (GitHub tokens)  
- `eyJ[A-Za-z0-9-_]+?\.[A-Za-z0-9-_]+?\.[A-Za-z0-9-_]+?` (JWT tokens)  
- `ssh-rsa AAAA[0-9A-Za-z+/]{100,}`  
- `-----BEGIN PRIVATE KEY-----`  
- `private[_-]?key[\s:=]+['"][^'"]+['"]`  
- `firebase[_-]?api[_-]?key[\s:=]+['"][^'"]+['"]`  
- `paypal[_-]?client[_-]?id[\s:=]+['"][^'"]+['"]`  
- `stripe[_-]?secret[_-]?key[\s:=]+['"][^'"]+['"]`  
- `sq0atp-[a-zA-Z0-9\-_]{22,}` (Square tokens)  
- `access[_-]?token[\s:=]+['"][^'"]+['"]`  
- `session[_-]?token[\s:=]+['"][^'"]+['"]`  
- `oauth[_-]?token[\s:=]+['"][^'"]+['"]`  
- `secret[_-]?key[\s:=]+['"][^'"]+['"]`  
- `api[_-]?secret[\s:=]+['"][^'"]+['"]`  
- `xox[baprs]-[a-zA-Z0-9]{10,48}` (Slack tokens)  
- `datadog[_-]?api[_-]?key[\s:=]+['"][^'"]+['"]`  
- `pagerduty[_-]?api[_-]?key[\s:=]+['"][^'"]+['"]`  
- `sendgrid[_-]?api[_-]?key[\s:=]+['"][^'"]+['"]`  

## 21-40: URL, Endpoints, Parameters
- `https?:\/\/[^\s'"]+` (URLs)  
- `\/api\/v[0-9]+\/[a-zA-Z0-9\-\/]+`  
- `(api|endpoint|url|route|path)[\s:=]+['"][^'"]+['"]`  
- `[?&][a-zA-Z0-9_\-]+=` (GET/POST params)  
- `fetch\(['"][^'"]+['"]` (JS fetch calls)  
- `xhr\.open\(['"][A-Z]+['"],\s*['"][^'"]+['"]`  
- `window\.location\.href\s*=\s*['"][^'"]+['"]`  
- `document\.location\s*=\s*['"][^'"]+['"]`  
- `axios\.\w+\(['"][^'"]+['"]\)`  
- `\$.ajax\(\s*{\s*url:\s*['"][^'"]+['"]`  

## 41-60: Vulnerable Functions & XSS Vectors
- `(eval|Function|setTimeout|setInterval)\s*\(`  
- `document\.write\s*\(`  
- `innerHTML\s*=`  
- `<.*on\w+\s*=`  
- `<script[^>]*>`  
- `alert\s*\(`  
- `prompt\s*\(`  
- `confirm\s*\(`  
- `javascript:`  
- `location\.href`  

## 61-80: Emails, IPs, IP Ranges, CVEs
- `[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}`  
- `\b((25[0-5]|2[0-4][0-9]|1?\d\d?)\.){3}(25[0-5]|2[0-4][0-9]|1?\d\d?)\b` (IPv4)  
- `\b([0-9a-f]{1,4}:){7}[0-9a-f]{1,4}\b` (IPv6)  
- `(CVE-\d{4}-\d{4,7})`  
- `docker\.[a-z]+`  
- `aws-[a-z0-9\-]+`  

## 81-100: Misc Patterns & Advanced
- `password\s*[:=]\s*['"][^'"]+['"]`  
- `client[_-]?secret[\s:=]+['"][^'"]+['"]`  
- `apikey\s*=\s*['"]\w{32,}['"]`  
- `token\s*=\s*['"]\w{32,}['"]`  
- `[a-zA-Z0-9]{40,}` (Long keys)  
- `basic\s+[A-Za-z0-9=_-]+` (Basic auth)  
- `Bearer\s+[A-Za-z0-9\-._~+/]+=*`  
- `password\s*=\s*getpass\(\)`  
- `crypt\s*\(`  
- `openssl[\s\S]+`  
- `/\*\*[\s\S]*?\*/` (Multiline comments)  
- `\/\/.*` (Single line comments)  
- `apikey\s*=\s*['"][a-zA-Z0-9]{32,}['"]`  

---


