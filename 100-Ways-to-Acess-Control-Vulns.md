# 100 Ways to Exploit Access Control Vulnerabilities — Techniques, CVEs & Discovery Tips (2025)

---

## How to Use  
This cheat sheet compiles 100 practical attack paths, vulnerability types, relevant CVEs, and testing techniques for identifying and exploiting access control weaknesses in web applications and APIs. Each entry includes hints to discover or confirm access control flaws during black-box testing or bug bounty hunting.

---

## 1–10: Common Access Control Weaknesses and Discovery Tips  
1. **Insecure Direct Object References (IDOR)**  
   - *Discovery:* Fuzz object IDs in URLs or POST data (e.g., `?user_id=123`) and observe unauthorized data access.  
2. **Missing Function-Level Access Control**  
   - *Tip:* Attempt privilege escalation by accessing admin-only functions or API endpoints as low-privileged user.  
3. **Horizontal Privilege Escalation**  
   - *Discovery:* Modify parameters (user, account, resource IDs) to access other users’ data at the same privilege level.  
4. **Vertical Privilege Escalation**  
   - *Tip:* Gain higher privileges by exploiting flaws to access admin functions.  
5. **Business Logic Bypass**  
   - *Discovery:* Skip or reorder application steps relying on client-side validation only.  
6. **Parameter/Role Tampering**  
   - *Tip:* Modify role or access level parameters passed in hidden inputs, cookies, or headers.  
7. **Incorrect Session Handling**  
   - *Discovery:* Use session fixation or reuse to access other user sessions or elevate privileges.  
8. **Access Control Based on Client-Side Checks Only**  
   - *Tip:* Test access to restricted pages/endpoints directly, bypassing UI controls.  
9. **Referer and Origin Header Reliance**  
   - *Discovery:* Forge or tamper with `Referer` or `Origin` headers to bypass access checks.  
10. **HTTP Method-based Bypass**  
    - *Tip:* Attempt restricted actions using alternative HTTP methods (`GET`, `POST`, `PUT`, `DELETE`).  

---

## 11–20: Parameter and Token Related Access Control Flaws  
11. **Insecure Access Control Using URL Query Parameters**  
    - *Discovery:* Modify query strings controlling access (e.g., `?admin=true`).  
12. **Access Control Based on Unvalidated Cookies or JWT Claims**  
    - *Tip:* Manipulate JWT payloads or cookies to escalate privileges.  
13. **Token or API Key Guessing and Replay**  
    - *Discovery:* Attempt brute-force or reuse tokens without expiry or rotation.  
14. **Weak or Missing Token Scope Validation**  
    - *Tip:* Abuse tokens with excessive privileges or use without proper scope checks.  
15. **Role Elevation via Unvalidated Input in APIs**  
    - *Discovery:* Supply tampered role fields in JSON or form data.  
16. **Access Control via Client-side JavaScript Only**  
    - *Tip:* Disable JS or tamper with client logic to access hidden features.  
17. **ID Peny Filtering — Using Reference Objects Insecurely**  
    - *Discovery:* Use non-sequential or invalid IDs to gain unexpected access.  
18. **Session Authentication but No Authorization Check**  
    - *Tip:* Authenticate as user then access endpoints reserved for others.  
19. **Inconsistent Access Controls Across API Versions**  
    - *Discovery:* Test same functionality with different API versions or legacy endpoints.  
20. **Use of Predictable Session or Access Tokens**  
    - *Tip:* Monitor token pattern and try session hijacking.

---

## 21–40: Advanced and Contextual Access Control Testing  
21. **Bypassing Access Controls Using URL Encoding Variations**  
    - *Discovery:* Try encoded or double-encoded URLs to bypass path restrictions.  
22. **Exploitation of Misconfigured Reverse Proxies or Load Balancers**  
    - *Tip:* Use headers like `X-Forwarded-For` or `X-Original-URL` to bypass controls.  
23. **Access Control Failures in Multi-Step Workflows**  
    - *Discovery:* Submit requests skipping steps that invoke access checks.  
24. **Cross-Tenant Access in Multi-Tenant Platforms**  
    - *Tip:* Test accessing resources across tenant boundaries by modifying tenant or organization IDs.  
25. **Exploiting Over-Permissive CORS Policies**  
    - *Discovery:* Access sensitive APIs from unauthorized domains by abusing misconfigured CORS.  
26. **Race Conditions in Access Control Checks**  
    - *Tip:* Rapidly send requests to modify state and bypass checks.  
27. **API Endpoint Exposure Without Proper Authentication**  
    - *Discovery:* Check for undocumented or legacy endpoints that do not enforce access controls.  
28. **Bypassing Access Controls Using HTTP Verb Tunneling**  
    - *Tip:* Use methods like `X-HTTP-Method-Override` to circumvent restrictions.  
29. **Weak Object Ownership and Sharing Controls**  
    - *Discovery:* Verify if users can access or modify resources they do not own due to poor ACL configuration.  
30. **Access Control Bypass by Exploiting Missing or Weak Rate Limiting**  
    - *Tip:* Use brute-force or enumeration to discover valid object IDs or tokens.

---

## 41–60: Specific Vulnerability Examples & CVEs  
31. **CVE-2024-43793 — Jira Data Center Auth Bypass Allowing Admin Access**  
32. **CVE-2023-28162 — Atlassian Confluence Path Traversal Leading to Unauthorized Access**  
33. **CVE-2024-28677 — WordPress Plugin Privilege Escalation via Role Bypass**  
34. **CVE-2023-22527 — Jira OGNL Injection Leading to Access Control Bypass and RCE**  
35. **CVE-2022-36090 — Insecure Access Control in Kubernetes API Server**  
36. **CVE-2023-7004 — GitLab Improper Access Control on User Project Settings**  
37. **CVE-2024-0128 — Cisco Secure Firewall Management Center Unauthorized Access**  
38. **CVE-2023-34887 — Magento Unauthorized Admin Panel Access via IDOR**  
39. **CVE-2025-1597 — Jira Service Management Authenticated RCE and Access Bypass**  
40. **CVE-2023-49689 — OAuth Token Misvalidation Leading to Privilege Escalation**

---

## 61–80: Access Control Failures in Common Software & Platforms  
41. **WordPress REST API Privilege Escalation via Unprotected Endpoints**  
42. **Jenkins UI Access Control Bypass on Script Console Page (Pre-auth RCE)**  
43. **Unauthorized Access to AWS S3 Buckets via Insufficient IAM Policies**  
44. **Horizontal Access Control Bypass in Salesforce Custom Objects**  
45. **Unauthorized Admin Console Access in Cisco Network Devices with Default Credentials**  
46. **IDOR in Facebook Graph API (Historical, Conceptual Example)**  
47. **Access Control Bypass in Atlassian Bitbucket Webhooks**  
48. **Role Confusion Attacks in OAuth2 Implementations**  
49. **Privilege Escalation via Misconfigured Role-Based Access Control (RBAC) in Kubernetes**  
50. **Excessive Permissions Granted to Mobile App API Keys or Tokens**

---

## 81–100: Testing Techniques & Automation Tools  
51. **Parameter Fuzzing with Burp Suite Intruder or OWASP ZAP**  
52. **Automated IDOR detection with tools such as IDORer or Burp plugins**  
53. **JWT Manipulation and Forgery Testing Tools**  
54. **Session Fixation and Reuse Testing**  
55. **API Endpoint Discovery with ffuf or dirsearch**  
56. **Testing for Unprotected Admin/Debug Endpoints**  
57. **Tampering with HTTP Headers such as `X-Original-URL` or `X-Rewrite-URL`**  
58. **Automated Role & Permissions Crawling via API Fuzzing**  
59. **Use of GitHub dorks to find exposed endpoints or misconfigurations**  
60. **Combining Access Control Testing with SSRF/IDOR/XSS for Chained Attacks**  

---

## Additional Access Control Pitfalls & Edge Cases  
61. **Access Control Based on Client IP — Spoofing or VPN Use to Bypass**  
62. **Referer or Origin Header Based Access Restrictions**  
63. **Geo-based Access Controls — Bypass via Proxy or VPN**  
64. **Incomplete Access Control of Uploaded Files or URLs**  
65. **Privilege Escalation via Account Linking or Social Login Flaws**  
66. **Business Logic Flaws Allowing Revoke/Change of Roles without Auth**  
67. **Unauthenticated Access via CSRF on Privileged Actions**  
68. **SAML or OAuth Assertion Forgery Leading to Access Bypass**  
69. **Weak Multi-Factor Authentication Enforcement or Bypass**  
70. **Access Control Bypass Due to Unsafe Direct URL Access**

---

## Best Practices to Prevent Access Control Issues  
- Always enforce authorization checks on the server side, never rely on client-side controls.  
- Use a centralized policy enforcement mechanism rather than piecemeal ad hoc checks.  
- Implement fine-grained Role-Based Access Control (RBAC) tuned to business context.  
- Validate and sanitize all user-controlled parameters influencing access decisions.  
- Deny by default—only allow access when explicit authorization is confirmed.  
- Regularly audit logs and implement alerting for anomalous access patterns.  
- Test access controls as part of QA and pen-testing with dedicated test cases.  
- Avoid using security by obscurity or hidden URLs as an access control method.  
- Employ least privilege principle in permissions and token scopes.  
- Keep frameworks and third-party components updated to patch known vulnerabilities.

---

## Helpful Tools & Resources to Aid Discovery  
- [PortSwigger Access Control Labs and Academy](https://portswigger.net/web-security/access-control)  
- [OWASP Authorization Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Authorization_Cheat_Sheet.html)  
- [Burp Suite Professional and API Security Tools](https://portswigger.net/burp)  
- [IDORer - IDOR Scanning Tool](https://github.com/h3xstream/idorer)  
- [Nuclei ProjectDiscovery Templates (search 'access-control')](https://github.com/projectdiscovery/nuclei-templates)  
- [JWT.io Debugger for token manipulation](https://jwt.io/)  
- [GitHub Dorking for exposed endpoints](https://help.github.com/en/github/searching-for-information-on-github/searching-code)  
- [OWASP Web Security Testing Guide – Access Control Testing](https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/08-Authorization_Testing)  

---

## Summary  
Access control vulnerabilities remain some of the most critical yet overlooked security issues, allowing attackers both horizontal and vertical privilege escalation, data breaches, and unauthorized actions. Thorough testing, including parameter tampering, role manipulation, header injection, and business logic bypassing, is essential to secure modern web systems.

---

**BountyBoy: Elite Bug Bounty Program — trusted by learners. 
📄 Syllabus: https://lnkd.in/d6vTg3k9 
🎯 Enroll Now: https://lnkd.in/d7p5spcS
