# 100 Ways to Find and Exploit IDOR (Insecure Direct Object Reference) Vulnerabilities — Techniques, CVEs & Discovery Tips (2025)

---

## How to Use  
This cheat sheet compiles 100 actionable IDOR attack vectors, real-world bug scenarios, common CVEs, and best practices for finding and exploiting these access control weaknesses. Each entry includes hints for discovery/exploitation, making it practical for black-box bug bounty, pentesting, and security reviews.

---

## 1–10: Core IDOR Flaw Patterns and Testing
1. **URL Parameter Tampering (classic IDOR)**  
   - *Discovery:* Modify IDs in URLs (e.g., `/profile?id=2`) to access data of other users[12].
2. **Horizontal IDOR (same privilege level)**  
   - *Tip:* As a normal user, change object IDs to access/modify other users' data (accounts, files, messages)[7][12].
3. **Vertical IDOR (privilege escalation, BOLA)**  
   - *Discovery:* Use low-privilege user to access admin-level objects/actions through ID change[4][7].
4. **Object-level IDOR (resource manipulation)**  
   - *Tip:* Try altering, deleting, or updating objects you shouldn’t own via direct reference[7].
5. **Function-level IDOR (feature misuse)**  
   - *Discovery:* Find features accessible to all users that trigger privileged operations[7].
6. **Directory Traversal IDOR**  
   - *Discovery:* Fuzz file/folder IDs/paths for directory traversal sequences (e.g., `../../etc/passwd`)[1].
7. **IDOR via POST Body Manipulation**  
   - *Tip:* Change body JSON, form-data, or XML fields containing IDs[1][11].
8. **IDOR via Cookie Manipulation**  
   - *Discovery:* Edit cookies storing object/user IDs to escalate or pivot[1].
9. **IDOR in RESTful API Paths (`/user/12345`)**  
   - *Tip:* Increment or substitute the referenced resource ID in API routes[11][12].
10. **IDOR via File Download/Preview Parameters**  
    - *Discovery:* Modify file IDs to download/preview other users’ documents[11][12].

---

## 11–30: Advanced IDOR Exploitation and Edge Cases  
11. **Parameter Pollution (duplicating ID fields in a request)**  
    - *Discovery:* Supply multiple ID fields (e.g., `id=1&id=2`) to see which one is used[3].
12. **IDOR via JSON Globbing (arrays, wildcards, booleans)**  
    - *Tip:* Try sending payloads like `[1,2]`, `"*"` as IDs in JSON APIs[3].
13. **IDOR in Deprecated API Versions**  
    - *Discovery:* Find and interact with older, less-protected endpoints (`v1/`, `oldapi/`)[3].
14. **Changing HTTP Method (e.g. GET to POST)**  
    - *Tip:* Change method to access hidden/undocumented actions (e.g., POST `/user/delete`)[3].
15. **Manipulating Content-Type Headers**  
    - *Discovery:* Send requests with `application/xml` or `application/x-www-form-urlencoded` instead of JSON[3].
16. **IDOR in GraphQL (direct object querying)**  
    - *Tip:* Substitute resource IDs in GraphQL queries for accounts/files[6].
17. **IDOR via Server Response Analysis (status codes, error messages)**  
    - *Discovery:* Look for 403/404 vs 200 responses when manipulating IDs.
18. **Bypassing Obfuscated (hashed/base64) IDs**  
    - *Tip:* Decode, increment, or guess simple obfuscated/scrambled IDs[11].
19. **IDOR exploiting sequence or predictable file/database IDs**  
    - *Discovery:* Brute-force enumerated, incremental, or sequential IDs (e.g., 1000,1001,1002).
20. **IDOR in Multi-Tenant Platforms (cross-tenant access)**  
    - *Tip:* Try changing org/tenant ID parameters to access data from other organizations[11][12].

---

## 31–40: CVEs and Real-World Examples (2023–2025)  
31. **CVE-2025-2271 — Issuetrak v17.2.2 audit log IDOR (view others’ audit results as low-priv user)[20]**  
32. **CVE-2023-2025 — OpenBlue Enterprise Manager Data Collector exposes sensitive info to unauthorized users**[15]  
33. **CVE-2022-21713 — Grafana teams API IDOR (read others’ teams by changing teamId param)**[10]  
34. **CVE-2024-25983 — Moodle authorization bypass (user-controlled key allows IDOR)[4]**  
35. **CVE-2024-45806 — Envoy Proxy authorization bypass via insecure object reference**[4]  
36. **BOLA (Broken Object Level Authorization) exploit in RESTful APIs**[4]  
37. **WordPress plugin TeraWallet WooCommerce IDOR**  
38. **Magento Authorization bypass through user-controlled key (CVE-2019-7950)[4]**  
39. **Liferay DXP CVE-2022-42129 IDOR**  
40. **IDOR in direct references to static files: `/static/12144.txt` for chat logs[12]**

---

## 41–60: Fuzzing, Tools & Techniques for IDOR Discovery  
41. **Fuzz ID parameters using tools like `ffuf` or `wfuzz`**[9].  
42. **Brute-force user/account IDs in all request parameters**.
43. **Automate replay of requests with modified IDs using Burp Suite Intruder**[11].
44. **Test all known resource endpoints for parameter substitution**.
45. **Spider application to collect all endpoints and discover hidden ID parameters**[5].
46. **Try hidden/undocumented API endpoints by guessing conventions or inspecting JS code**.
47. **Use AuthMatrix/Authz/Authorize (Burp plugins) for access control testing**[11].
48. **Analyze browser dev tools network traffic for in-use IDs and replace with other values**[9].
49. **Test various HTTP methods (PUT, DELETE, PATCH) with manipulated IDs**[5].
50. **Enumerate all cookie and header values for potential object references**.
51. **Check for IDOR in batch/bulk operation endpoints**.
52. **Test IDOR for objects referenced in both URL and request body**.
53. **Replay requests captured as another user (different session/cookie)**.
54. **Test signed/encoded parameters by attempting to brute force or decode**.
55. **Use logic and business knowledge to guess “important” object references (e.g., invoices, escrow, tickets, etc.)**[14].
56. **Leverage browser plugin tools for response diffing to detect unauthorized access**.
57. **Manual API fuzzing with Postman for parameter and body manipulation**[9].
58. **Reverse engineer mobile/web app APIs for hidden ID usage**.
59. **Search for ID patterns in source code or client-side JS deployed on the app**.
60. **Check for access control flaws exposed in production but patched in admin/test/dev environments**.

---

## 61–80: Less Obvious IDOR Abuse & Chaining
61. **Try negative, zero, or large integer values for ID fields**[3].
62. **Manipulate array/object IDs in JSON params**[3].
63. **Use string or mixed type (e.g., float/integer) for ID parameter**[3].
64. **Access logs, invoices, or statistical reports by ID tampering**.
65. **Test nested resource IDs (e.g., `/user/1/items/45`)**.
66. **Chain IDOR with other bugs (XSS, SSRF, privilege escalation)**.
67. **Leverage “deleted” or “archived” object IDs for revival or access**.
68. **Attempt “expired”, “pending”, or “draft” object IDs for restricted access**.
69. **Change IDs in multipart form data on file upload or object creation**.
70. **Manipulate IDs when exporting or importing functions are present**.
71. **Try referencing uninitialized or unset objects**.
72. **Predict IDs for new users/objects by registering multiple test accounts**.
73. **Access admin-only or unlisted objects through weak API controls**.
74. **Probe for IDOR in legacy endpoints not shown in the main UI**.
75. **Use enumeration to discover hidden or non-incremental IDs**.
76. **Test combinations of parameter and header IDs (e.g., userId in param, X-User in header)**.
77. **Inject symbols/payloads into ID fields to test for backend quirks**.
78. **Try using valid IDs from other users or accounts from open-source dumps/paste sites**.
79. **Scan for probable “shared” resources in multi-user environments**.
80. **Attempt to access objects in a new session (no cookies) after guessing resource IDs**.

---

## 81–100: Best Practices, Review, and Prevention
81. **Review audit trails for suspicious ID manipulation attempts**.
82. **Map all flows where object references are user-controlled**.
83. **Avoid using predictable or sequential IDs for sensitive resources**[12].
84. **Implement indirect references (mapping user-friendly IDs to real object IDs)**[4].
85. **Always enforce access control checks server-side for every referenced object**[4][17].
86. **Regularly audit new/changed endpoints for IDOR bugs**[14].
87. **Employ least-privilege principle in all access control logic**[4].
88. **Integrate automated IDOR scanning in CI/CD pipelines**[5].
89. **Keep API docs and test cases up to date with all resources requiring access checks**.
90. **Red-team and bug bounty programs to crowdsource logic flaw discovery**.
91. **Log denied object access for security review and anomaly detection**.
92. **Train developers and auditors about the subtlety and commonality of IDORs**.
93. **Test especially for IDORs after refactorings, migration, or feature launches**.
94. **Document unusual workflows or object references for targeted review**.
95. **Combine IDOR prevention with access log monitoring and alerting**.
96. **Coordinate regular pen-testing to find business-logic and edge-case IDORs**.
97. **Use API gateways or middlewares to enforce access policies centrally**.
98. **Patch all third-party plugins/extensions with known IDORs**.
99. **Secure mobile/desktop app APIs, not just browser endpoints**.
100. **Never trust obfuscation (base64, hex, etc.) as protection: always check auth for every object reference!**

---

## Tools and Resources for IDOR Vulnerability Hunting  
- **Burp Suite, Postman, OWASP ZAP:** For intercepting and manipulating requests[9][11][16].
- **Fuzzers:** ffuf, wfuzz, and custom scripts to automate ID tampering[9].
- **Nuclei Templates** targeting IDOR: https://github.com/projectdiscovery/nuclei-templates
- **Browser Developer Tools & plugins**: Analyze request/response easily[9].
- **IDOR-IN** automated scanner: <https://github.com/GManOfficial/IDOR-IN>[5].
- **AuthMatrix, Authz, Authorize (Burp plugins)**: Bulk access control testing[11].

---

## Helpful Readings & CVE Databases
- [PortSwigger Academy IDOR Guide](https://portswigger.net/web-security/access-control/idor)[12]
- [GeeksforGeeks IDOR Explanation](https://www.geeksforgeeks.org/ethical-hacking/insecure-direct-object-reference-idor-vulnerability/)[1]
- [Intigriti Advanced IDOR Exploitation Guide](https://www.intigriti.com/blog/news/idor-a-complete-guide-to-exploiting-advanced-idor-vulnerabilities)[3]
- [NVD National Vulnerability Database – Search for IDOR CVEs](https://nvd.nist.gov/)

---

## Summary  
IDOR vulnerabilities are among the most common, subtle, and dangerous web application bugs. Effective discovery blends creative parameter manipulation, methodical brute-forcing, and business understanding. Robust server-side access checks for every referenced object are the only reliable fix.

---

**BountyBoy: Elite Bug Bounty Program — trusted by learners. 
📄 Syllabus: https://lnkd.in/d6vTg3k9 
🎯 Enroll Now: https://lnkd.in/d7p5spcS
