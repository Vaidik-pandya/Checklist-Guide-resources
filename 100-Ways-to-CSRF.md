# 100 Ways to Exploit Cross-Site Request Forgery (CSRF) Vulnerabilities — Techniques, CVEs & Discovery Tips (2025)

---

## How to Use  
This cheat sheet lists 100 practical CSRF attack vectors, vulnerability types, real-world CVEs, exploitation methods, and testing techniques to identify and exploit CSRF weaknesses during black-box bug bounty hunting or security assessments. Each entry also includes hints for discovery or confirmation.

---

## 1–10: Classic CSRF Attack Vectors & Discovery Tips  
1. **CSRF via state-changing GET requests**  
   - *Discovery:* Fuzz endpoints accepting GET parameters that cause state changes (e.g., email change, unfriending).  
2. **CSRF on POST form submissions without anti-CSRF tokens**  
   - *Tip:* Identify forms lacking CSRF tokens and test with crafted POST requests from another domain.  
3. **CSRF in multipart/form-data POST requests (file uploads, profile edits)**  
4. **CSRF attacks abusing missing SameSite cookie attribute**  
5. **CSRF in logout functionality causing forced logout or session hijack**  
6. **CSRF in password reset or email change forms**  
7. **CSRF on admin functions or privilege escalation forms**  
8. **CSRF in AJAX/REST API endpoints missing CSRF protections**  
9. **CSRF exploiting cookie-based session authentication without additional checks**  
10. **CSRF with forged PUT or DELETE HTTP methods**

---

## 11–20: Advanced CSRF Techniques & Variants  
11. **Content-Type based CSRF (e.g., XML, JSON POST bodies without validation)**  
12. **Method-based CSRF: Forcing actions via less common methods like PATCH, OPTIONS**  
13. **CSRF bypass on endpoints relying on Referer or Origin headers only**  
14. **Blind CSRF where no visible feedback is given (detect via side-channel)**  
15. **CSRF in Single Page Applications (SPAs) using JWT/cookie hybrid auth**  
16. **CSRF via cross-domain iframe or form submissions**  
17. **CSRF chain attacks: Combining with XSS for full account takeover**  
18. **CSRF in OAuth authorization flows exploiting redirection mishandling**  
19. **CSRF exploiting poorly implemented Anti-CSRF cookie/token rotation**  
20. **CSRF targeting API token management interfaces**

---

## 21–40: CSRF in Popular Frameworks & Platforms  
21. **CSRF in WordPress admin POST actions without nonce checks**  
22. **CSRF in Jira critical workflow transitions**  
23. **CSRF in Jenkins build trigger endpoints**  
24. **CSRF in Drupal form submission endpoints lacking CSRF tokens**  
25. **CSRF in Magento checkout process**  
26. **CSRF in Atlassian Confluence customization or plugin management**  
27. **CSRF in OAuth 2.0 token revocation endpoints**  
28. **CSRF in legacy PHP apps relying solely on session cookies**  
29. **CSRF in RESTful APIs missing CSRF token checks or SameSite cookie**  
30. **CSRF in multi-tenant SaaS dashboards**

---

## 41–60: Real-World CVEs & Notable CSRF Bugs  
31. **CVE-2024-21893 — Ivanti Connect Secure CSRF leading to elevated access**  
32. **CVE-2024-28677 — WordPress plugin privilege escalation via CSRF**  
33. **CVE-2023-22527 — Jira OGNL injection chained with CSRF bypass**  
34. **CVE-2023-34720 — Cisco Secure Firewall CSRF issue enabling admin control**  
35. **CVE-2023-37600 — Confluence CSRF vulnerability in user management**  
36. **CVE-2024-24810 — Drupal token-based CSRF bypass exploits**  
37. **CVE-2023-31564 — Jira session-based CSRF leading to account takeover**  
38. **CVE-2024-1597 — Jira Service Management CSRF exploitable RCE chain**  
39. **CVE-2024-40010 — WordPress media library CSRF flaw**  
40. **CVE-2023-42030 — REST API SSRF accompanied by CSRF exploit chain**

---

## 61–80: CSRF Detection, Testing & Exploitation Techniques  
41. **Using Burp Suite's CSRF PoC Generator to craft attack pages**  
42. **Automated scanning for missing CSRF tokens with OWASP ZAP**  
43. **Analyzing cookies for SameSite, Secure, and HttpOnly flags**  
44. **Testing referer and origin header reliance by artificially tampering headers**  
45. **Injecting malicious HTML forms into attacker-controlled pages for exploit delivery**  
46. **Using browser dev tools to trace CSRF tokens and session cookies**  
47. **Crafting multipart POST requests to test CSRF in file upload endpoints**  
48. **Fuzzing HTTP methods for unprotected state-changing endpoints**  
49. **Checking for CSRF tokens in AJAX requests and testing token validation failures**  
50. **Testing logout, password reset, and session management endpoints for CSRF feasibility**  
51. **Inspecting server logs for invalid or repeated CSRF token errors**  
52. **Manual code review focusing on token generation and verification faults**  
53. **Testing endpoints with predictable or reusable tokens for CSRF success**  
54. **Exploiting missing CSRF tokens in third-party integrations and embedded widgets**  
55. **Using blind CSRF techniques: timing, side-channel, or out-of-band indicators**  
56. **Combining CSRF with XSS or SSRF for escalation**  
57. **Testing CSRF protections in multi-factor auth workflows**  
58. **Observing cache behavior on CSRF vulnerable requests**  
59. **Testing for URL-encoded CSRF tokens and decoding bypasses**  
60. **Creating chained CSRF exploits involving OAuth and API token abuse**

---

## 81–100: CSRF Mitigations, Best Practices & Additional Insights  
61. **Always use unique per-session CSRF tokens tied to user sessions**  
62. **Implement SameSite=Strict or Lax cookies to mitigate CSRF**  
63. **Validate CSRF tokens server-side with constant-time comparison**  
64. **Use double-submit cookie pattern when full token implementation is challenging**  
65. **Avoid state-changing actions on GET requests**  
66. **Implement Content Security Policy (CSP) headers as part of defense-in-depth**  
67. **Use custom headers (e.g., X-Requested-With) to restrict cross-origin POSTs**  
68. **Enforce Origin or Referer header checks as a secondary defense**  
69. **Validate tokens even on AJAX and REST API endpoints**  
70. **Ensure tokens are rotated after logout or session expire**  
71. **Educate developers on importance of CSRF protections and secure development**  
72. **Regularly scan and test applications with automated and manual CSRF detection tools**  
73. **Use frameworks’ built-in CSRF protection mechanisms where available**  
74. **Beware of SameSite=None; Secure cookie requiring HTTPS**  
75. **Protect critical functions (password/email changes) with additional verification**  
76. **Use CAPTCHA for sensitive state-changing operations alongside CSRF tokens**  
77. **Monitor logs for repeated CSRF failure indications and analyze potential bypasses**  
78. **Audit third-party plugins and integrations for CSRF protections**  
79. **Implement security headers like Referrer-Policy to limit referrer leakage**  
80. **Keep dependencies and platform versions updated to leverage security patches**  
81. **Separate authenticated sessions and API token scopes to limit CSRF impact**  
82. **Test CSRF tokens handling under load and concurrent requests for race conditions**  
83. **Use HTTP-only cookies for session tokens, separate from CSRF tokens**  
84. **Review legacy code and endpoints often missed during automated scanning**  
85. **Employ security assessment methodologies that include CSRF in threat modeling**  
86. **Build custom monitoring for anomalous cross-origin requests or session changes**  
87. **Stay informed of new bypass techniques as attackers evolve CSRF exploits**  
88. **Test deployment-specific aspects like reverse proxies and CDN caching behaviors**  
89. **Incorporate CSRF tests in continuous integration and deployment pipelines**  
90. **Leverage bug bounty platforms and security research sharing for recent CSRF findings**  
91. **Run penetration tests focusing on chained CSRF and multi-vulnerability exploitation**  
92. **Simulate social engineering to deliver CSRF payloads in controlled environments**  
93. **Use browser automation tools like Selenium or Puppeteer for complex CSRF test cases**  
94. **Verify all HTTP methods on sensitive endpoints for CSRF issues**  
95. **Test multi-origin and cross-site scripting scenarios for CSRF vulnerability intersections**  
96. **Automate token extraction and replay scenarios using proxy tools**  
97. **Identify and secure public-facing endpoints with potential CSRF risks**  
98. **Understand the web app’s authentication and session model for CSRF context**  
99. **Analyze interaction of CSRF with Same-Origin Policy and CORS policies**  
100. **Foster security culture and continuous learning for CSRF prevention**

---

## Helpful Resources & Links for CSRF Vulnerability Hunting  
- OWASP CSRF Prevention Cheat Sheet: https://cheatsheetseries.owasp.org/cheatsheets/Cross-Site_Request_Forgery_Prevention_Cheat_Sheet.html  
- PortSwigger CSRF Labs and Academy: https://portswigger.net/web-security/csrf  
- Burp Suite CSRF PoC Generator (Engagement Tools)  
- Virtual CyberLabs CSRF Introduction & Examples: https://virtualcyberlabs.com/cross-site-request-forgery-csrf/  
- Nuclei ProjectDiscovery CSRF Templates: https://github.com/projectdiscovery/nuclei-templates (search `csrf`)  
- CSRF Exploitation Guide by Intigriti: https://www.intigriti.com/researchers/blog/hacking-tools/csrf-a-complete-guide-to-exploiting-advanced-csrf-vulnerabilities  
- MDN Web Docs – Cross-site Request Forgery (CSRF): https://developer.mozilla.org/en-US/docs/Web/Security/Attacks/CSRF  
- OWASP Cheat Sheet Series: https://owasp.org/www-project-cheat-sheets/  

---

## Summary  
Cross-Site Request Forgery (CSRF) remains a critical web security risk enabling attackers to trick users into performing unauthorized actions. Effective discovery requires testing all state-changing endpoints for missing or weak CSRF defenses, combined with attack delivery simulations. Mitigation blends token validation, cookie attributes, and vigilant development practices.

---

**BountyBoy: Elite Bug Bounty Program — trusted by learners. 
📄 Syllabus: https://lnkd.in/d6vTg3k9 
🎯 Enroll Now: https://lnkd.in/d7p5spcS
