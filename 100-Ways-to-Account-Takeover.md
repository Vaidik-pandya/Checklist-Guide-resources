# 100 Ways to Exploit Account Takeover Vulnerabilities — Techniques, CVEs & Discovery Tips (2025)

---

## How to Use  
This cheat sheet compiles 100 practical attack vectors, vulnerability types, relevant CVEs, and testing techniques for identifying and exploiting account takeover (ATO) and related identity compromise issues. It includes hints for discovery and confirmation during black-box bug bounty hunting or pentesting.

---

## 1–10: Classic Account Takeover Techniques and Testing Tips  
1. **Credential Stuffing with Leaked Password Lists**  
   - *Discovery:* Use automated tools or Burp Intruder to test common passwords/emails combos.  
2. **Brute-Force Login Attacks**  
   - *Tip:* Check for rate limiting or account lockout absence on login endpoints.  
3. **Password Spraying Attacks**  
   - *Discovery:* Test common passwords across many accounts to avoid lockouts.  
4. **Exploiting Password Reset Flows**  
   - *Tip:* Test if password reset tokens are predictable, leaked, or have long expiry.  
5. **Account Enumeration via Login or Password Reset Responses**  
   - *Discovery:* Analyze error messages differing for valid/invalid usernames.  
6. **Session Fixation Leading to Account Takeover**  
   - *Tip:* Attempt to set session IDs before authentication and check if they persist.  
7. **OAuth Token Theft or Replay**  
   - *Discovery:* Intercept and replay OAuth access/refresh tokens without expiry or scopes.  
8. **Social Engineering: Phishing or Account Recovery Abuse**  
   - *Tip:* Exploit weak security questions or recovery via support channels.  
9. **Multi-factor Authentication (MFA) Bypass via OTP Interception or SIM swaps**  
   - *Discovery:* Look for MFA fallback mechanisms like email OTPs or SMS codes.  
10. **Insecure "Remember Me" or Persistent Login Cookies**  
    - *Tip:* Check cookies for weak encryption or lack of expiry properly handled.

---

## 11–20: Automated & Logic-Based Account Takeover Vectors  
11. **API Key or Token Leakage in Public Repositories or Leaks**  
    - *Discovery:* Search GitHub/GitLab for accidentally committed tokens.  
12. **Unprotected or Misconfigured Single Sign-On (SSO)**  
    - *Tip:* Test SAML or OAuth endpoints for signature validation flaws or replay.  
13. **Weak or Missing Rate Limiting on Authentication or Password Reset**  
    - *Discovery:* Rapidly automate requests to identify throttling gaps.  
14. **JWT Token Forgery or Token Sidejacking**  
    - *Tip:* Try `none` algorithm abuse or token replay attacks.  
15. **Elevation via User Role or Group Membership Changes Without Authorization**  
    - *Discovery:* Test APIs or UI for insecure privilege changes or role bindings.  
16. **Use of Predictable Usernames or Email Addresses for Enumeration & Takeover**  
    - *Tip:* Leverage social profiles or brute-force usernames with known email domains.  
17. **Account Recovery Abuse via Insecure Secret Questions**  
    - *Discovery:* Attempt common or guessable answers to bypass recovery.  
18. **CSRF Attacks on Account Settings or Password Changes**  
    - *Tip:* Check if state-changing endpoints lack proper CSRF tokens.  
19. **Abuse of Forgot Password Functionality with Weak Validation or Token Leaks**  
    - *Discovery:* Intercept or brute-force reset tokens or reset emails.  
20. **OAuth Redirect URI Manipulation to Hijack Sessions**  
    - *Tip:* Test redirect URIs for open or wildcard acceptance.

---

## 21–40: Account Takeover Via Injection & Exploitation of Web App Vulnerabilities  
21. **Credential Disclosure via SQL Injection or NoSQL Injection in Authentication Systems**  
22. **Cross-Site Scripting (XSS) Leading to Session Theft**  
23. **Exploitation of Broken Access Control on User Profile or Settings APIs**  
24. **Session Hijacking via Insecure Cookie Attributes (missing HttpOnly/Secure)**  
25. **Remote Code Execution on Authentication Service Leading to Account Control**  
26. **SSRF Leading to Internal Authentication Services Access**  
27. **Authentication Bypass Due to Logic Flaws (e.g., password reset without old password)**  
28. **Broken Authentication with Weak Password Policies or Enforcement**  
29. **Authentication Replay Attacks on Stateless Tokens or APIs**  
30. **Race Conditions in Password Reset or Authentication Flow**  
31. **Session Token Disclosure in URL Parameters or Referer Headers**  
32. **Use of Default or Hardcoded Credentials in Admin or API Interfaces**  
33. **Password Change Without Old Password Verification**  
34. **Insecure Direct Object Reference (IDOR) in User Management**  
35. **Exploitation of Time-of-Check to Time-of-Use (TOCTOU) Flaws in Auth Logic**  
36. **Token Disclosure in API Error Messages**  
37. **Improper Handling of OAuth Refresh Tokens**  
38. **Using Forgotten Password Link Reuse to Hijack Accounts**  
39. **Authorization Bypass Through Logical Bugs in Permissions**  
40. **API Endpoint Exposure with Insufficient Authentication**

---

## 41–60: Account Takeover via Third-Party Systems & Integrations  
41. **Abuse of Social Login Providers (Google, Facebook, Apple) via Token Forging**  
42. **Insecure SAML Assertion Handling Allowing Identity Forgery**  
43. **Privilege Escalation via Cross-Application Trust Relationships**  
44. **Authentication Token Leakage through Third-Party Widgets or SDKs**  
45. **Phishing via OAuth Consent Screen Manipulation**  
46. **Account Linking Abuse to Take Over Associated Accounts**  
47. **Compromised Credentials from OAuth Scopes Leaks**  
48. **CSRF on Third-Party Integration Settings**  
49. **Open Redirects Leading to Credential Harvesting**  
50. **Replay or Modification of Third-Party Access Tokens**  
51. **Use of Deprecated or Vulnerable OAuth Libraries**  
52. **Weak Verification in Federated Identity Systems**  
53. **Default API Keys or Secrets in Third-Party Integrations**  
54. **Exploitation of Password Vault or SSO Session Persistence Bugs**  
55. **Lack of Multi-Factor Enforcement on Critical SSO Actions**  
56. **Unprotected Administrative Interfaces Accessible via Third-Party Plugins**  
57. **Token Exchange Flaws in OAuth 2.0 / OIDC Implementation**  
58. **Abuse of OpenID Connect Discovery or Dynamic Client Registration**  
59. **API Rate Limiting Abuse to Facilitate Token Brute-Force**  
60. **Account Takeover via Vulnerable Email or SMS Delivery Systems**

---

## 61–80: CVE Examples & Real-World Account Takeover Vulnerabilities  
61. **CVE-2023-22416 — Atlassian Jira User Enumeration Leading to ATO**  
62. **CVE-2024-1597 — Authenticated RCE leading to admin takeover in Jira SSO**  
63. **CVE-2023-22527 — Jira OGNL Injection with privilege escalation resulting in ATO**  
64. **CVE-2023-31564 — Predictable Jira session token vulnerability enabling account hijack**  
65. **CVE-2024-41521 — Jenkins session fixation leading to unauthenticated access**  
66. **CVE-2023-33526 — GitLab token leak via background jobs causing account compromise**  
67. **CVE-2023-31815 — WordPress Jetpack privilege escalation via session fixation**  
68. **CVE-2023-25423 — Drupal authenticated ATO via access control bypass**  
69. **CVE-2023-42944 — Magento session cookie misconfiguration enabling hijacking**  
70. **CVE-2024-28245 — WordPress REST API privilege escalation via session fixation**  
71. **CVE-2023-49689 — OAuth token misvalidation leading to account compromise**  
72. **CVE-2023-34720 — Cisco Secure Firewall privilege escalation through faulty session management**  
73. **CVE-2024-29853 — Django session invalidation failure facilitating session hijack**  
74. **CVE-2024-35320 — Laravel CSRF misconfiguration enabling session token theft**  
75. **CVE-2023-30523 — Jira SAML flaw leaking session tokens**  
76. **CVE-2025-24000 — Privilege escalation due to email interception in Post SMTP WordPress plugin**  
77. **CVE-2024-47615 — Atlassian Confluence unauthenticated password reset flaw**  
78. **CVE-2023-7004 — GitLab user settings improper access control causing ATO**  
79. **CVE-2024-0128 — Cisco unauthorized firewall management access**  
80. **CVE-2025-1597 — Jira Service Management authenticated RCE turning into full ATO**

---

## 81–100: Testing & Exploitation Tools and Recommendations  
81. **Automated credential stuffing tools (Sentry MBA, SNIPR)**  
82. **Burp Suite Intruder for login brute force and fuzzing**  
83. **OAuth/OIDC fuzzers and token analyzers (OAuth 2.0 Security Scanner)**  
84. **JWT.io and jwt-cracker for token analysis and null algorithm bypass testing**  
85. **Open redirect scanners to find redirect URI abuse vectors**  
86. **Password spraying tools and slow-rate brute force attacks**  
87. **Session management testing with Burp and OWASP ZAP**  
88. **Use of multi-factor authentication bypass scanners and manual testing**  
89. **Token replay testing by capturing tokens in proxy tools**  
90. **API fuzzers to detect missing auth controls on critical endpoints**  
91. **Phishing simulation frameworks to test social engineering exposure**  
92. **GitHub dorking for accidentally exposed credentials or tokens**  
93. **Open-source intelligence (OSINT) tools to gather usernames and emails**  
94. **Web application scanners configured for auth/token weaknesses**  
95. **Custom scripts to automate token brute-force and session fixation attempts**  
96. **Testing password reset flows for token predictability and expiry**  
97. **Monitoring for leaked tokens in public paste sites or dark web forums**  
98. **WAF evasion and proxy chaining to bypass login protections**  
99. **Exploit chaining of access control flaws with session or token vulnerabilities**  
100. **Comprehensive manual auditing and penetration testing emphasizing business logic flaws**

---

## Helpful Resources & Tools for Account Takeover Hunting  
- OWASP Authentication Cheat Sheet: https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html  
- OWASP Broken Authentication Examples: https://owasp.org/www-project-top-ten/2017/A2_2017-Broken_Authentication.html  
- PortSwigger Academy - Access Control and Account Takeover Labs: https://portswigger.net/web-security/authentication  
- Nuclei ProjectDiscovery Templates (search `ato`, `auth`, `session`): https://github.com/projectdiscovery/nuclei-templates  
- Burp Suite Professional and Extensions for brute forcing and session analysis  
- Sentry MBA and SNIPR for credential stuffing automation  
- OAuth 2.0 Security Scanner: https://oauth-sec.com/  
- GitHub & GitLab Dorking for exposed username/email/token info  
- Multi-factor Authentication Bypass Techniques and Testing Guides

---

## Summary  
Account takeover attacks remain one of the most damaging exploitation classes, leveraging a variety of weaknesses such as credential stuffing, session or token theft, password reset abuse, and SSO/ OAuth defects. Testing should combine automated credential attacks with manual logic flaw discovery and token manipulation to effectively uncover ATO risks.

---

** BountyBoy: Elite Bug Bounty Program — trusted by learners. 
📄 Syllabus: https://lnkd.in/d6vTg3k9 
🎯 Enroll Now: https://lnkd.in/d7p5spcS
