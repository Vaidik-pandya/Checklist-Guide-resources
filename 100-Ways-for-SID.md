# 100 Ways to Find and Exploit Sensitive Information Leaks — Techniques, CVEs & Discovery Tips (2025)

---

## How to Use  
This cheat sheet covers 100 practical attack vectors, vulnerability types, example CVEs, and testing methodologies for detecting and exploiting sensitive information leakage in web applications and APIs. It includes tips for discovery, confirmation, and exploitation during bug bounty hunting, penetration testing, or security assessments.

---

## 1–10: Common Types of Sensitive Information Leaks  
1. **Disclosure via Detailed Error Messages and Stack Traces**  
   - *Discovery:* Trigger errors with malformed inputs and analyze verbose debug info leaking database schemas, file paths, or credentials.  
2. **Exposure through Misconfigured HTTP Headers (Server, X-Powered-By)**  
   - *Tip:* Inspect response headers revealing backend software versions or frameworks susceptible to known vulnerabilities.  
3. **Unprotected `/robots.txt` or Directory Listings Revealing Sensitive Paths**  
   - *Discovery:* Access `/robots.txt`, `.git/`, `.env`, `/backup/` directories exposing config or secrets.  
4. **Leakage in Source Code or Backup Files Accessible via Web Server**  
   - *Tip:* Look for URLs ending in `.bak`, `.old`, `.zip`, `.sql`, `.log` exposing sensitive data.  
5. **Information Disclosure through Timing or Behavioral Side-Channels**  
   - *Discovery:* Analyze response timings or content differences to infer presence or absence of sensitive data.  
6. **API Responses Exposing More Data Than Intended (Excessive Data Exposure)**  
   - *Tip:* Intercept API calls to check for sensitive fields (password hashes, tokens) returned inadvertently.  
7. **Sensitive Data in URL Parameters or Referer Headers**  
   - *Discovery:* Inspect URLs and referer headers for tokens, session IDs, or personal data.  
8. **Unsecured or Publicly Accessible Admin or Debug Interfaces**  
   - *Tip:* Scan for endpoints like `/admin`, `/debug`, `/status`, or `/health` revealing internal states and data.  
9. **Information Exposure via Third-Party Integrations (Analytics, SDKs)**  
   - *Discovery:* Review embedded third-party scripts for improper data transmission or logging.  
10. **Sensitive Data in Cookies or Local Storage**  
    - *Tip:* Inspect cookies/local storage for plaintext tokens, credentials, or personal details.

---

## 11–30: Data Leaks Through Application Logic & Misconfigurations  
11. **User Data Exposure via IDOR (Insecure Direct Object References)**  
    - *Discovery:* Manipulate object references in requests to access others’ info.  
12. **Email Enumeration during Account Creation or Password Reset Flows**  
    - *Tip:* Observe subtle response differences to valid/invalid usernames.  
13. **Excessive Permissions Exposed in OAuth or Token Scopes**  
    - *Discovery:* Analyze and abuse overly permissive OAuth tokens or scopes.  
14. **Publicly Accessible API Documentation Exposing Internal Details**  
    - *Tip:* Search for Swagger/OpenAPI files revealing sensitive API structure and parameters.  
15. **Debugging or Verbose Logging Enabled in Production**  
    - *Discovery:* Identify application outputs including debug info, sensitive SQL queries, or stack dumps.  
16. **Misconfigured CORS Exposing Sensitive Data to Untrusted Origins**  
    - *Tip:* Analyze CORS headers allowing overly broad cross-origin requests.  
17. **Information Disclosure via JSONP Callback Injection**  
    - *Discovery:* Abuse JSONP endpoints to expose data to malicious domains.  
18. **Sensitive Environment Variables Leaked via Build or Config Files**  
    - *Tip:* Search for `.env`, `config.json`, or other environment files accessible over HTTP.  
19. **Exposed Database Management Interfaces (phpMyAdmin, Adminer)**  
    - *Discovery:* Scan for these services left accessible with weak/no authentication.  
20. **Leaking Credentials/Tokens in JavaScript Source or HTML Comments**  
    - *Tip:* Inspect client-side code or inline scripts for exposed secrets.

---

## 31–50: Real-World CVEs and Known Sensitive Data Leak Vulnerabilities  
21. **CVE-2024-46513 — Arbitrary file upload in WP GDPR Compliance plugin leaking data**  
22. **CVE-2023-27289 — Atlassian Confluence data exposure through unauthenticated API**  
23. **CVE-2024-21893 — Ivanti Connect Secure SSRF leading to sensitive data leak**  
24. **CVE-2023-31564 — Jira session token disclosure via predictable session management**  
25. **CVE-2024-28677 — WordPress plugin improper role check leading to data leaks**  
26. **CVE-2023-34720 — Cisco Secure Firewall session and data exposure**  
27. **Disclosure of AWS credentials via metadata service SSRF**  
28. **Exposed S3 buckets or cloud storage with sensitive business documents**  
29. **Unintended Access to User Personally Identifiable Information (PII)**  
30. **Leakage via caching proxies or CDN misconfiguration exposing sensitive URLs**

---

## 51–70: Sensitive Data Exposure in Modern Technologies  
31. **Sensitive data in GraphQL API introspection queries**  
    - *Tip:* Use introspection to discover schema details and potentially accessed sensitive fields.  
32. **Leakage via Unsecured WebSocket Communications**  
    - *Discovery:* Monitor WebSocket frames for unencrypted sensitive info or tokens.  
33. **Source Code and Secrets in Container Images or Cloud Repositories**  
    - *Tip:* Search public GitHub/registry for leaked Dockerfiles or credentials.  
34. **Secrets Exposed in Continuous Integration/Delivery Pipelines Logs**  
    - *Discovery:* Check public build logs for tokens or passwords printed in clear.  
35. **Slack/Chatbot Integrations Logging Sensitive Information Improperly**  
    - *Tip:* Review message history or bot configurations for data leaks.  
36. **Sensitive Information Leaks in Mobile App Backends**  
    - *Discovery:* Intercept API calls to mobile app backends leaking tokens or user data.  
37. **Leakage via Third-Party Cloud Functions or Serverless Logs**  
    - *Tip:* Inspect serverless logs or endpoints exposing environment variables.  
38. **Hardcoded API Keys or Secrets in Public Repositories**  
    - *Discovery:* Search GitHub or GitLab for accidental commits exposing secrets.  
39. **Disclosure via DNS or Network Configuration Files Accessible via Web**  
    - *Tip:* Identify files like `resolv.conf`, `hosts` exposed accidentally.  
40. **Sensitive Info Leakage in Server Banner or Error Responses**  
    - *Discovery:* Analyze HTTP responses for internal software versions or patch levels.

---

## 71–90: Advanced Techniques to Detect and Exploit Data Leaks  
41. **Utilizing Timing Attacks to Infer Protected Data**  
    - *Tip:* Measure response time differences for valid vs invalid data queries.  
42. **Out-Of-Band (OOB) Data Exfiltration Using DNS or HTTP Callbacks**  
    - *Discovery:* Employ DNS interaction platforms (e.g., Interactsh) to confirm data exposure.  
43. **Leveraging Blind XXE Attacks to Retrieve Internal Files and Data**  
    - *Tip:* Exploit XML parsers with XXE payloads for file disclosure.  
44. **Bypassing Input Validation to Access Hidden Fields or Records**  
    - *Discovery:* Test raw API or app functionality with malformed or boundary inputs.  
45. **Chaining SSRF with Information Disclosure for Internal Network Recon**  
    - *Tip:* Use SSRF to probe internal metadata or admin services.  
46. **Fuzzing APIs for Overly Verbose or Sensitive Responses**  
    - *Discovery:* Send malformed or unauthorized requests to elicit info leaks.  
47. **Monitoring Cache-Control and Stored Responses for Leaked Data**  
    - *Tip:* Check if sensitive data is cached publicly or saved incorrectly.  
48. **Analyzing Third-Party SDKs for Data Leakage Risks**  
    - *Discovery:* Review SDK usage patterns or leaked telemetry data.  
49. **Using Web Archive and Historical Snapshots to Find Past Exposures**  
    - *Tip:* Check archives like Wayback Machine for exposed sensitive info later removed.  
50. **Analyzing Login/Password Reset Flows for Token or Personal Data Disclosure**

---

## 91–100: Tools, Resources & Best Practices to Detect Sensitive Information Leaks  
51. **Burp Suite Pro: Intercepting, logging, and fuzzing inputs to detect leaks**  
52. **Nuclei Templates: Automated scans for known info disclosure CVEs**  
53. **GitHub Dorking: Search for leaked keys, config files, and credentials**  
54. **Shodan/Censys: Scan for exposed servers and open services revealing info**  
55. **OWASP ZAP: Active and passive scanning for data leaks**  
56. **DNS and HTTP Interaction Platforms (Interactsh, DNSLogger) for OOB detect**  
57. **Source Code Review for Hardcoded Secrets and Misconfigurations**  
58. **Automated API fuzzing tools like Postman, SoapUI, or custom scripts**  
59. **Static and dynamic analysis tools to detect secret leaks in code or runtime**  
60. **Cloud Security Posture Management (CSPM) tools monitoring for exposed cloud data**  
61. **Monitor application logs and error reporting for sensitive output**  
62. **Penetration testing with focus on data privacy and leaks**  
63. **Continuous integration (CI) pipeline scanning for secret leaks**  
64. **Educate teams on secure handling of secrets and user data**  
65. **Implement least privilege and data minimization principles**  
66. **Use encryption at rest and in transit for sensitive data**  
67. **Configure proper access controls and audit logging**  
68. **Use environment variable management solutions instead of plaintext configs**  
69. **Employ Content Security Policy (CSP) to limit data exposure via XSS**  
70. **Regularly patch and update all software and dependencies**  

---

## Helpful Resources & Links for Sensitive Information Leak Hunting  
- [PortSwigger Information Disclosure Overview](https://portswigger.net/web-security/information-disclosure)  
- [OWASP Sensitive Data Exposure](https://owasp.org/www-project-top-ten/2017/A3_2017-Sensitive_Data_Exposure.html)  
- [PayloadsAllTheThings: Information Disclosure](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/Information_Disclosure)  
- [Nuclei Templates Repository](https://github.com/projectdiscovery/nuclei-templates) (search “info-leak”)  
- [GitHub Dorking Techniques](https://medium.com/@lmecalco/github-dorking-spotify-source-code-secrets-leaks-75990a6dad03)  
- [Burp Suite Extensions: Logger++, Collaborator client]  
- [OWASP Web Security Testing Guide: Information Leakage](https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/05-Information_Gathering_Testing/10-Testing_for_Information_Leakage)

---

## Summary  
Sensitive information leaks continue to be a critical attack vector leading to identity exposure, business secrets compromise, and facilitating downstream attacks like RCE or privilege escalation. Effective detection relies on thorough testing of error handling, misconfigurations, API outputs, and third-party integrations. Combining manual and automated methods with awareness of current CVEs maximizes bug bounty and penetration testing success.

---

**BountyBoy: Elite Bug Bounty Program — trusted by learners. 
📄 Syllabus: https://lnkd.in/d6vTg3k9 
🎯 Enroll Now: https://lnkd.in/d7p5spcS
