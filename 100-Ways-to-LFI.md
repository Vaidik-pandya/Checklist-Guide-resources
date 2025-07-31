# 100 Ways to Achieve Local File Inclusion (LFI) — Exploits, CVEs & Techniques with Discovery Tips (2025)

---

## How to Use  
This cheat sheet lists 100 common and impactful Local File Inclusion (LFI) attack vectors, vulnerable components, recent CVEs, and exploitation methods to focus on during black-box testing and bug bounty hunting. It includes practical hints to detect, confirm, and exploit LFI vulnerabilities.

---

## 1–10: Classic LFI Attack Vectors & Basic Discovery  
1. **Directory Traversal via URL parameters**  
   - *Discovery:* Fuzz parameters like `page=`, `file=`, `template=` with `../../../../etc/passwd`.  
2. **LFI in PHP include/require functions without sanitization**  
   - *Tip:* Target PHP apps using dynamic includes without whitelist filtering.  
3. **LFI combined with null-byte injection to bypass file extension restrictions**  
   - *Exploitation:* Use `%00` or double encoding to bypass suffix filters.  
4. **LFI via encoded (URL/Unicode) directory traversal sequences**  
   - *Tip:* Test URL encoding variations like `%2e%2e/` or double URL encoding.  
5. **LFI in cookie values or HTTP headers processed internally as file paths**  
6. **LFI via file parameter in download or viewer scripts**  
   - *Example:* `download.php?file=../../../../etc/passwd`  
7. **LFI in multi-language or theme selection parameters**  
   - *Tip:* Change language or theme param to `../../../` paths to read config files.  
8. **LFI used to access system log files (`/var/log/apache/access.log`)**  
   - *Use:* Log poison web shell code then include logs to execute.  
9. **LFI in CMS components (e.g., Joomla, Drupal, WordPress plugins)**  
   - *Discovery:* Enumerate plugin paths and test vulnerable entry points.  
10. **LFI in image or document preview handlers abusing file path input**  

---

## 11–20: Advanced LFI Exploitation Techniques  
11. **Log Poisoning & LFI for Remote Code Execution (RCE)**  
    - *Method:* Inject PHP code into logs (user-agent, referrer) then include logs via LFI.  
12. **Session file inclusion leading to code execution**  
    - *Tip:* Target LFI to `../sessions/sess_<id>` after session poisoning.  
13. **LFI exploiting PHP wrappers (`php://filter`, `php://input`)**  
    - *Discovery:* Use wrappers to read or execute payloads indirectly.  
14. **LFI with filter chain to read source code (`php://filter/convert.base64-encode/resource=index.php`)**  
15. **LFI combined with SQL injection to upload code or write files on server**  
16. **LFI in JSP/ASP.NET apps exploiting similar dynamic includes**  
17. **LFI coupled with upload functionality to include attacker-controllable files**  
18. **LFI via misconfigured cron log or temp files inclusion**  
19. **LFI bypassing directory restrictions with symbolic link abuse or chroot escape**  
20. **LFI through encoded Unicode, UTF-8 or wide char encoding bypasses**

---

## 21–40: Real-World Examples & CVEs  
21. **CVE-2025-27610 — Local File Inclusion in Ruby Rack::Static (Rack web apps)**  
22. **CVE-2024-46513 — LFI in WordPress WP GDPR Compliance plugin via AJAX uploads**  
23. **LFI in Joomla com_users allowing file disclosure**  
24. **CVE-2023-22527 — Jira OGNL Injection chained with LFI for info disclosure**  
25. **PHP-CGI query string LFI via crafted requests (CVE-2012-1823 legacy)**  
26. **CVE-2019-6339 — Drupal 8 LFI vulnerability in REST resource endpoints**  
27. **LFI in Magento through theme/template main file includes**  
28. **CVE-2020-14179 — Jira sensitive file read via LFI in QueryComponent servlet**  
29. **LFI in Apache Tomcat webapps via poorly configured web.xml includes**  
30. **LFI in WordPress plugin debug or log viewer features**

---

## 41–60: Discovery Techniques & Tools  
41. **Static and dynamic source code analysis for suspicious include() or require() calls**  
42. **Automated fuzzing tools (ffuf, dirsearch) to brute forced LFI parameters**  
43. **Use Burp Intruder or extension plugins to inject directory traversal payloads**  
44. **Look for parameters containing `.php`, `.inc`, `.html`, `.txt`, or arbitrary file extensions**  
45. **Check error messages for file inclusion paths or disclosure clues**  
46. **Fingerprint application/framework to focus on known LFI entry points**  
47. **Check upload directories & attempt to include known temporary uploaded files**  
48. **Observe response time or content length differences during fuzzing to confirm LFI**  
49. **Leverage public scanners like JoomScan, WPScan, or general web vulnerability scanners**  
50. **Use GitHub dorks for exposed code revealing inclusion logic or vulnerable endpoints**

---

## 61–80: Bypasses & Encoding Tricks for LFI  
51. **Double URL encoding to bypass filters**  
52. **UTF-8 or Unicode encoded directory traversal sequences**  
53. **Use of PHP stream wrappers (`expect://`, `data://`) for complex LFI to RCE chains**  
54. **Appending null byte or other special bytes to bypass extension filtering**  
55. **Bypassing allowlists with case sensitivity abuse or mixed slashes (`..\\` vs `../`)**  
56. **Traversal using absolute paths or Windows drive letters on Windows hosts**  
57. **Passing URL wrappers to read .htaccess or server configuration files**  
58. **Using variable truncation/excessive length input to confuse parsers**  
59. **Multipart/form-data encoding bypasses to evade WAFs**  
60. **Chain LFI with PHP input stream wrappers to execute PHP code in POST body**

---

## 81–100: LFI Combined Attacks & Mitigations  
61. **LFI combined with PHP session poisoning for RCE**  
62. **Chain LFI with file upload flaws to execute attacker-controlled code**  
63. **Use LFI to access credentials files (`wp-config.php`, `.env`, `config.php`) for deeper compromise**  
64. **LFI to include SSH private keys or config files for lateral movement**  
65. **Exploit LFI to read server logs with injected PHP snippets for command execution**  
66. **Use LFI to leak source code revealing further vulnerabilities**  
67. **Bypass input sanitization using regex flaws or patch level bypasses**  
68. **Detect LFI using out-of-band interactions (JavaScript callbacks or DNS exfil)**  
69. **Chain LFI with SSRF or XXE for more advanced attacks**  
70. **Mitigation: Parameterize includes, whitelist file names/directories, disable NULL byte injection**  
71. **Mitigation: Use allowlist validation and block directory traversal patterns**  
72. **Mitigation: Disable dangerous PHP wrappers if not needed (expect://, data://)**  
73. **Mitigation: Sanitize all user input used in file processing and includes**  
74. **Mitigation: Implement proper access controls on sensitive files**  
75. **Mitigation: Employ Web Application Firewalls (WAFs) configured with LFI patterns**  
76. **Mitigation: Monitor server logs for suspicious LFI access patterns**  
77. **Mitigation: Keep frameworks and libraries updated with security patches**  
78. **Mitigation: Use least privilege principle on web server file permissions**  
79. **Mitigation: Conduct regular code reviews focusing on dynamic file includes**  
80. **Mitigation: Educate developers about inclusion vulnerabilities and secure coding**  
81. **Use LFI to access backup config files (.bak, .old, ~ files for sensitive data)**  
82. **LFI exploiting symlink race conditions to access protected resources**  
83. **Bypass simplistic blacklists with crafted UTF-7 or UTF-16 encodings**  
84. **LFI targeting proprietary CMS and frameworks with custom include logic**  
85. **LFI via misconfigured URL rewriting rules causing unexpected file loads**  
86. **Using LFI to read `.htpasswd` or `.user.ini` files exposing credentials**  
87. **Exploit LFI in multi-tenant environments to break tenant isolation**  
88. **Include PHP sessions of other users to hijack sessions or escalate privileges**  
89. **Confuse logging mechanisms with crafted inputs to evade LFI detection**  
90. **Bypass allowlists by injecting null bytes in encodings other than URL encoding**  
91. **LFI with exploitation on Windows/DOS special paths (e.g., `CON`, `PRN`)**  
92. **LFI to read PHP error logs with injected code for chained RCE**  
93. **Exploit LFI via file wrappers like `zip://`, `glob://` for archive traversal**  
94. **Detect LFI by sending unique file names and searching for their contents**  
95. **Bypass input sanitization using magic bytes or alternate character sets**  
96. **Combine LFI with CSRF attacks to exploit application user privileges**  
97. **Detect LFI using time-based or blind response techniques**  
98. **Exploit backup API keys or tokens found through LFI-disclosed files**  
99. **Chain LFI with cron jobs or other scheduled tasks for persistent control**  
100. **LFI combined with insecure deserialization leading to full server compromise**

---

## Helpful Resources & Tools for LFI Discovery & Exploitation  
- [Indusface File Inclusion Attacks Guide](https://www.indusface.com/learning/file-inclusion-attacks-lfi-rfi/)  
- [OWASP Web Security Testing Guide - Testing for LFI](https://owasp.org/www-project-web-security-testing-guide/v42/4-Web_Application_Security_Testing/07-Input_Validation_Testing/11.1-Testing_for_Local_File_Inclusion)  
- [VirtualCyberLabs Practical LFI Guide](https://virtualcyberlabs.com/local-file-inclusion-lfi/)  
- [Nuclei Templates for LFI Scanning](https://github.com/projectdiscovery/nuclei-templates) (search for `lfi`)  
- Burp Suite extensions such as Active Scanner and Intruder for LFI fuzzing  
- Dirsearch, ffuf, or other automated directory/fuzz scanners for LFI path discovery  
- GitHub Dorking to find vulnerable source code and endpoints (`include=`, `page=` parameters)  
- Manual testing with crafted payloads and encoded traversal sequences  

---

## Summary  
- LFI vulnerabilities provide unauthorized read access to sensitive local files and frequently escalate to RCE with log poisoning or file upload chaining.  
- Discovery relies on thoroughly fuzzing input points that build file paths, often URL parameters, headers, cookies, or hidden inputs.  
- Bypass techniques including encoding and wrapper abuse expand the attacker’s capabilities.  
- Mitigation focuses on proper input validation, whitelisting, and eliminating dynamic file includes where possible.

---

** BountyBoy: Elite Bug Bounty Program — trusted by learners. 
📄 Syllabus: https://lnkd.in/d6vTg3k9 
🎯 Enroll Now: https://lnkd.in/d7p5spcS

