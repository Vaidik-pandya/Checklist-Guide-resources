# 100 Ways to Achieve Remote Code Execution (RCE) — Exploits, CVEs & Techniques (2025)  
*With discovery tips and helpful links*

---

## 1–10: Microsoft & Windows Ecosystem RCEs  
1. **CVE-2025-47172** — SQL Injection leading to RCE in Microsoft SharePoint Server  
   - **To find:** Fingerprint SharePoint version via headers or pages; monitor for SQL errors; scan with SharePoint-specific scanners.  
2. **CVE-2025-32710** — Use-After-Free in Windows Remote Desktop Services Gateway  
   - **Tip:** Monitor RDP gateways with known vulnerable versions; check CVE defenses from Microsoft Patch Tuesday advisories.  
3. **CVE-2025-33071** — Use-After-Free in Windows Kerberos KDC Proxy  
   - **Hint:** Kerberos logs and network captures may indicate targeted exploitation.  
4. **CVE-2025-29828** — Memory corruption in Windows Secure Channel during TLS handshake  
   - **Find by:** Reviewing TLS implementation versions and CVE databases; network packet inspection.  
5. **CVE-2025-49696** — Microsoft Office RCE via crafted document  
   - **To discover:** Phishing campaigns or malware samples can be indicators; sandbox document handling to observe execution.  
6. **CVE-2025-48817** — Remote Desktop Client RCE  
7. **CVE-2025-47998** — Windows Routing and Remote Access Service RCE  
8. **CVE-2025-49674** — RRAS Remote Code Execution via crafted packets  
9. **CVE-2025-33054** — Remote Desktop Spoofing  
10. **CVE-2025-53770** — Critical SharePoint zero-day RCE (actively exploited)  
    - **Detection:** Monitor IIS worker process spawning `cmd.exe`/`powershell.exe` unusual chains ([Rapid7 Detection Guide](https://www.rapid7.com/blog/post/etr-zero-day-exploitation-of-microsoft-sharepoint-servers-cve-2025-53770/))  

---

## 11–20: Apache, Tomcat, and Java Web Stacks  
11. **CVE-2025-24813** — Apache Tomcat Path Equivalence RCE  
    - **Detect by:** Fuzzing HTTP PUT methods & NTFS junctions; monitor HTTP access logs for suspicious PUT calls ([CYFIRMA report](https://www.cyfirma.com/research/cve-2025-24813-apache-tomcat-rce-vulnerability-analysis/)).  
12. Java deserialization gadget chains — Test SOAP/REST APIs with crafted serialized objects.  
13. Expression Language Injection — Check user inputs reflected in JSP EL contexts.  
14. Unsafe JSP file uploads — Scan file uploader endpoints for missing extension or MIME checks.  
15. Apache Struts OGNL Injection — Scan form submissions for injection patterns.  
16. Spring Framework SpEL injection — Test JSON/XML payloads with expressions.  
17. Jenkins Groovy script console RCE — Look for exposed scripting consoles.  
18. Jenkins pre-auth file read + RCE (CVE-2024-23897) — Use PoCs to check vulnerable endpoint.  
19. Deserialization via SOAP or REST APIs — Analyze API request bodies for serialized data.  
20. SSRF leading to JNDI LDAP injection — Fuzz URL parameters for SSRF vectors.

---

## 21–30: Linux & Unix-specific RCE Vectors  
21. Shellshock bash exploit — Check CGI scripts with environment variable inputs.  
22. Sudo privilege escalations — Enumerate Sudo version and misconfigurations.  
23. Buffer overflows in setuid binaries — Use fuzz testers on local privilege binaries.  
24. Perl/Python CGI injection — Probe URL parameters and environment variables.  
25. CVE-2023-28531 — Exim command injection — Monitor mail server versions and logs.  
26. CVE-2023-0204 — PHP-FPM malformed FastCGI request — Analyze server FastCGI logs and fuzz input formatting.  
27. Exposed Redis allowing command injection — Scan port 6379 and test for open writes.  
28. NFS export path traversal — Review NFS configurations for insecure exports.  
29. CVE-2025-32433 — SSH server message processing RCE — Check SSH server versions.  
30. Cron job script injection — Audit cron jobs for unsafe script calls or env vars.

---

## 31–40: Web Application Framework RCEs  
31. Django Template Injection — Test template input fields with variables like `{{7*7}}`.  
32. Ruby on Rails YAML deserialization — Scan background job inputs.  
33. Express.js prototype pollution — Fuzz JSON inputs for overridden properties.  
34. Laravel PHP object injection — Check deserialized data from user inputs or cookies.  
35. Spring Boot actuator exposed endpoints — Scan `/actuator` paths for management APIs.  
36. Tomcat malformed path RCE — Similar to #11, test with path traversal fuzzing.  
37. Flask Jinja2 template injection — Inject payloads bypassing filters in templates.  
38. WordPress REST API authenticated RCE — Test vulnerable plugins and REST endpoints.  
39. Drupalgeddon RCE — Test vulnerable Drupal versions with SQL injection and file write.  
40. Magento insecure file upload in admin panel — Fuzz plugin upload and media paths.

---

## 41–50: Containerization & CI/CD Pipelines  
41. Jenkins pre-auth Groovy injection (CVE-2024-23897) — Use script console or POST attack vectors.  
42. Kubernetes API Server misconfig — Scan API endpoints open without auth.  
43. Docker socket exposure — Check if `/var/run/docker.sock` is mounted or exposed.  
44. GitLab Runner untrusted project execution — Test CI pipeline configs.  
45. GitHub Actions workflow injection — Review repo actions for improper inputs.  
46. Git hooks command injection — Check server-side hooks handling repo pushes.  
47. Git LFS smudge injection — Intercept LFS filters for malicious payloads.  
48. Template injection in CI/CD YAML files — Fuzz variable parsing.  
49. Tekton pipeline pod exec — Evaluate authorization for pod exec commands.  
50. CircleCI environment var injection — Review environment variable usage.

---

## 51–60: Networking Devices & IoT RCE Vulnerabilities  
51. Cisco IOS XE Web UI command injection (CVE-2023-20198) — Test web UI inputs.  
52. Cisco ASA VPN backdoor (ArcaneDoor CVE-2024-20359) — Check firmware versions and network exposure.  
53. Default credentials on routers — Attempt known default logins.  
54. Fortinet Fortigate RCE via HTTP requests — Fuzz API endpoints.  
55. D-Link Web Admin command injection — Scan management URLs with payloads.  
56. IoT telnet/SSH weak credentials — Scan open services and attempt weak passwords.  
57. DVR/IP camera backdoor shell — Check HTTP/RTSP admin paths.  
58. UPnP exploits — Scan for UPnP-enabled devices on internal networks.  
59. Nokia/Alcatel LTE appliance RCE — Fingerprint via banner grabbing.  
60. TR-069 protocol flaws — Audit remote management for exploits.

---

## 61–70: Cloud & Serverless RCE Techniques  
61. SSRF targeting cloud metadata services — Send URLs pointing to `http://169.254.169.254`.  
62. AWS Lambda function payload injection — Deploy malicious payloads via function input.  
63. Azure Functions deserialization — Fuzz function inputs with unsafe data types.  
64. Google Cloud Run container exploits — Send malformed HTTP requests to containers.  
65. Kubernetes UI misconfig — Scan for exposed dashboards without auth.  
66. Linux kernel eBPF container escapes — Monitor for eBPF exploits.  
67. Serverless SQL injection leading to shell exec — Inject SQL in serverless backends.  
68. CloudFormation injection — Check templates for injected commands.  
69. IAM privilege escalation to serverless RCE — Audit IAM policies for overprivileges.  
70. API Gateway tampering — Manipulate request transformations for code execution.

---

## 71–80: Popular CMS & Plugin/Theme Vulnerabilities  
71. WordPress plugin arbitrary file upload — Scan plugin upload points like AI Engine, TI Wishlist.  
72. Drupal plugin deserialization — Test known vulnerable Drupal modules.  
73. Joomla com_users SQLi → RCE — Fuzz user params.  
74. Magento admin file upload — Test admin panel endpoints.  
75. Adobe AEM unchecked file upload & JCR injection.  
76. Jira OGNL injection (CVE-2023-22527) — Probe endpoints with crafted OGNL expressions.  
77. Confluence XXE leading to RCE — Test XML upload endpoints.  
78. MediaWiki extension RCE — Scan vulnerable extensions.  
79. Prestashop deserialization — Test plugin input.  
80. OpenCart theme path traversal — Fuzz URL paths for traversal payloads.

---

## 81–90: API & Integration-based RCE Attacks  
81. JSON deserialization — Send crafted JSON objects to APIs.  
82. XXE in SOAP/REST APIs — Attach malicious external entities to XML payloads.  
83. If-Modified-Since HTTP header injection — Try injection in header formats.  
84. Parameter injection — Fuzz REST API parameters.  
85. GraphQL mutation injection — Inject malicious parameters in queries.  
86. CI webhook code execution — Create webhooks triggering code payloads.  
87. OAuth token abuse — Replay or forge tokens.  
88. API Gateway request transformation injection — Test transformations.  
89. Server Side Template Injection (SSTI) — Inject template code in web responses.  
90. SQL Injection chaining to OS command execution — Combine SQLi with command exec.

---

## 91–100: Miscellaneous & Advanced Exploits  
91. Log4Shell (CVE-2021-44228) in unpatched Java apps.  
92. Browser memory corruption via plugins.  
93. Email server exploits (Exim, Postfix) leading to RCE.  
94. LFI + NULL byte injection chaining for RCE.  
95. Apache Struts Jakarta Multipart parser RCE (CVE-2017-5638).  
96. BlueKeep RDP RCE (CVE-2019-0708).  
97. Redis/Memcached open-server RCE via command injection.  
98. Twig/Mustache template injection RCE.  
99. Groovy sandbox escapes in CI.  
100. Buffer overflow or heap exploitation in network daemons.

---

## Helpful Links & Tools to Detect/Discover RCE Vulnerabilities:  

- **NVD & MITRE CVE database:** Find detailed vulnerability descriptions and affected versions.  
- **ProjectDiscovery Nuclei Templates:** Community scans for hundreds of RCE CVEs ([Link](https://github.com/projectdiscovery/nuclei-templates)).  
- **Burp Suite:** Craft and automate injection payloads against APIs and web apps.  
- **SQLmap:** Semi-automated SQL injection discovery tool.  
- **GraphQLmap:** For finding injection and abuse in GraphQL APIs.  
- **JoomScan, WPScan:** Scanners tailored for Joomla and WordPress vulnerabilities.  
- **Shodan & Censys:** Find exposed vulnerable systems in the wild via fingerprinting.  
- **GitHub Dorks:** Search for leaked secrets, API endpoints, and configs to identify potential targets.  
- **Metasploit & RouterSploit:** Exploitation frameworks with modules targeting known Cisco and network device vulnerabilities.  
- **EchoPing Golang tools (like ffuf/dirsearch):** Bruteforce directories and endpoints for hidden attack surfaces.

---

** BountyBoy: Elite Bug Bounty Program — trusted by 8000+ learners.
📄 Syllabus: https://lnkd.in/d6vTg3k9 🎯 Enroll Now: https://lnkd.in/d7p5spcS
