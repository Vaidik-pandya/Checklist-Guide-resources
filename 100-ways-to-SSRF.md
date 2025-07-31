# 100 Ways to Achieve Server-Side Request Forgery (SSRF) — Exploits, CVEs & Techniques with Discovery Tips (2025)

---

## How to Use  
This cheat sheet lists 100 practical SSRF attack vectors, recent CVEs, vulnerable components, and exploitation methods to focus on during black-box testing and bug bounty hunting. It includes hints on how to find or confirm SSRF flaws.

---

## 1–10: Classic & Cloud Metadata SSRF  
1. **SSRF to AWS Metadata Service (`http://169.254.169.254/`)**  
   - *Discovery:* Fuzz URL or API parameters that accept URLs or IP addresses.  
   - *Impact:* Access AWS credentials and escalate cloud privileges.  

2. **SSRF to Azure Cloud Instance Metadata Service (`http://169.254.169.254/metadata/instance`)**  
   - *Discovery:* Look for URL inputs used server-side to fetch metadata.  
   - *Impact:* Leak sensitive VM info and credentials.

3. **SSRF to Google Cloud Platform Metadata Server**  
   - *Discovery:* Test URL-fetching features for ability to access internal GCP services.  
   - *Impact:* Access service account tokens and internal configs.

4. **SSRF via XML External Entity (XXE)**  
   - *Discovery:* Probe XML upload or parsing functionalities for external entity processing.  
   - *Impact:* Read internal files, perform SSRF to internal services.

5. **SSRF in HTTP redirect or URL fetcher parameters**  
   - *Discovery:* Discover redirect parameters or URL import features accepting user-controlled input.  
   - *Impact:* Access internal-only reachable services.

6. **SSRF via Blob Storage or CDN prefetch URLs**  
   - *Discovery:* Fuzz file upload or download endpoints that accept remote URLs.  
   - *Impact:* Access internal network or non-public cloud storage buckets.

7. **Blind SSRF via Webhook Callbacks**  
   - *Discovery:* Configure or manipulate webhook URLs pointing internally.  
   - *Impact:* Trigger internal requests not visible directly, useful for blind exploitation.

8. **SSRF using Referer or User-Agent headers**  
   - *Discovery:* Check any backend service that follows links in Referer or User-Agent headers.  
   - *Impact:* Internal network scanning or pivoting.

9. **SSRF through Proxy/Forwarding Services**  
   - *Discovery:* Identify services that transparently proxy or forward requests based on user input.  
   - *Impact:* Abuse to bypass firewall or network access controls.

10. **SSRF via URL schema confusion (`file://`, `gopher://`, `ftp://`)**  
    - *Discovery:* Attempt different protocol schemes in URL input fields or API calls.  
    - *Impact:* Abuse various backend parsers to trigger SSRF differently.

---

## 11–20: Recent High-Impact SSRF CVEs & Bugs  
11. **CVE-2024-21893 — Ivanti Connect Secure SSRF leading to RCE**  
    - *Discovery:* Fuzz management interface URL inputs, check patch status.  
    - *Impact:* Allows attackers to reach internal networks and gain remote code exec.

12. **CVE-2025-22952 — Memos app SSRF via insufficient URL validation**  
    - *Discovery:* Test any API consuming URL params for improper sanitization.  
    - *Impact:* Access private/internal endpoints.

13. **CVE-2025-8228 — SSRF via targetUrl parameter manipulation**  
    - *Discovery:* Analyze REST API params controlling URL fetches.  
    - *Impact:* Internal service access and info disclosure.

14. **CVE-2025-8267 — SSRF in ssrfcheck package via IP denylist bypass**  
    - *Discovery:* Use internal IP ranges and malformed inputs to bypass blacklists.  
    - *Impact:* Confirms weak denylist implementations.

15. **CVE-2023-34729 — Fortigate RCE chain starting with SSRF**  
    - *Discovery:* Probe web portal API endpoints for URL inputs.  
    - *Impact:* Initial SSRF pivot to privileged code execution.

16. **CVE-2024-33766 — Apache HTTP Server 2.4.52 SSRF**  
    - *Discovery:* Test HTTP modules with user-controlled URLs.  
    - *Impact:* Access internal resources otherwise restricted.

17. **CVE-2024-20801 — Kubernetes Dashboard SSRF**  
    - *Discovery:* Scan Kubernetes UI endpoints accepting URL inputs.  
    - *Impact:* Internal cluster service interrogation.

18. **CVE-2024-21691 — Jenkins plugin SSRF via Remote Access API**  
    - *Discovery:* Enumerate plugin API endpoints handling URLs.  
    - *Impact:* Access internal Jenkins services with elevated privileges.

19. **CVE-2024-25275 — OAuth2 Proxy SSRF in redirect URIs**  
    - *Discovery:* Manipulate OAuth redirect_uri to internal addresses.  
    - *Impact:* SSRF to internal admin services or token leak.

20. **CVE-2023-49798 — Serverless provider SSRF via function triggers**  
    - *Discovery:* Fuzz function event parameters with URL inputs.  
    - *Impact:* Access cloud internal API endpoints.

---

## 21–40: Common SSRF Attack Vectors in Web Apps & APIs  
21. SSRF in image or media URL fetchers for previews or caching.  
22. SSRF in HTML to PDF generation services fetching external assets.  
23. SSRF in third-party OAuth token introspection services.  
24. SSRF in webhook URL registration in CI/CD pipelines.  
25. SSRF in proxy or VPN services accepting user-defined targets.  
26. SSRF in payment gateways to internal financial APIs.  
27. SSRF in monitoring tools fetching URL status of internal services.  
28. SSRF in SaaS multi-tenant systems to access other tenants’ network segments.  
29. SSRF via file uploaders downloading resources for scanning or virus check.  
30. SSRF in remote logging or analytics ingestion endpoints.  
31. SSRF via misconfigured reverse proxies, mod_proxy, or nginx proxy_pass.  
32. SSRF in third-party integration connectors or enterprise service bus.  
33. SSRF triggered by manipulating DNS resolution patterns.  
34. SSRF caused by unsafe absolute URL resolution from partial user input.  
35. SSRF through open redirect flaw chained with backend requests.  
36. SSRF in microservices architecture through inter-service communication URLs.  
37. SSRF via server-side web scraping services accepting arbitrary URLs.  
38. SSRF from API gateways forwarding requests without validation.  
39. SSRF in IoT devices pulling firmware updates or fetching configuration URLs.  
40. SSRF in mobile app backend services with URL fetching features.

---

## 41–60: Advanced SSRF Exploitation Techniques  
41. Out-of-band SSRF using DNS or HTTP callbacks for blind detection.  
42. SSRF combined with port scanning to map internal network topology.  
43. SSRF with HTTP verb tampering (GET, POST, PUT) to trigger different internal APIs.  
44. SSRF with protocol smuggling (gopher://, dict://, file://) for diverse backend abuses.  
45. Exploiting SSRF to access cloud provider metadata and gain privileged tokens.  
46. Chaining SSRF with deserialization vulnerabilities for code execution.  
47. SSRF pivot to Kubernetes API with cluster admin rights.  
48. SSRF ending in server-side included scripts leading to remote code execution.  
49. SSRF used to access internal-only admin consoles or databases.  
50. SSRF combined with open redirect to bypass filters and WAFs.  
51. SSRF exploitation via fragment URL injection (e.g., URL#fragment) to confuse parsers.  
52. SSRF in multi-tenant cloud services targeting other tenants via cloud URL pollution.  
53. Blind SSRF + log poisoning for code injection.  
54. SSRF triggered by HTTP header injection vectors.  
55. SSRF abuse for hitting blacklisted IP ranges using IPv6 and decimal IP encoding.  
56. SSRF with HTTP basic auth headers to gain unauthorized access.  
57. SSRF in serverless functions via event URL manipulations.  
58. SSRF chained with cloud functions to escalate privileges.  
59. SSRF leveraging SSRF-protected APIs by abusing callback URLs.  
60. SSRF targeting internal CRM or ERP software APIs.

---

## 61–80: SSRF in Popular Software & Frameworks  
61. SSRF in Wordpress REST API via vulnerable plugins.  
62. SSRF in Jira webhook configuration pages.  
63. SSRF in Confluence plugin API calls.  
64. SSRF in Docker Registry URL fetch endpoints.  
65. SSRF in Kubernetes ingress controllers.  
66. SSRF in GitLab repository mirrors or CI pipelines.  
67. SSRF in OAuth2/OpenID connect provider redirect_uri validations.  
68. SSRF in AWS Lambda with unsafe URL event triggers.  
69. SSRF in Jenkins URL parameterized jobs.  
70. SSRF in Cloudflare Workers handling external requests.  
71. SSRF in Apache Solr external entity fetching.  
72. SSRF in Moodle file repository URLs.  
73. SSRF in Atlassian Bitbucket pull request integrations.  
74. SSRF in Salesforce external service calls.  
75. SSRF in Adobe Experience Manager (AEM) asset ingestion.  
76. SSRF in Elasticsearch remote script execution endpoints.  
77. SSRF via Centrify privileged access URLs.  
78. SSRF in RabbitMQ federation plugins.  
79. SSRF in SaltStack API requests.  
80. SSRF in Nginx Lua module URL fetch features.

---

## 81–100: Detection Tips & Tools for SSRF Vulnerabilities  
81. Use Burp Suite Intruder and Scanner for URL parameter fuzzing.  
82. Deploy Nuclei with SSRF-specific templates ([Nuclei Templates](https://github.com/projectdiscovery/nuclei-templates)) to automate detection.  
83. Use OWASP ZAP Active Scanner with custom SSRF payload sets.  
84. Analyze application code for URL building or URL fetch calls with user-input.  
85. Fuzz blind SSRF via DNS exfiltration using tools like DNSLogger or Interactsh.  
86. Use SSRFmap and SSRFuzz for automated scanning of SSRF in popular apps.  
87. Test internal URLs, localhost, and uncommon IP ranges to bypass simple blacklists.  
88. Review JSON/XML parsers for XXE and SSRF combined flaws.  
89. Monitor web server logs for unexpected outgoing requests.  
90. Employ out-of-band service callback detection for blind SSRF findings.  
91. Use template injection detection tools since SSTI often co-exists with SSRF.  
92. Inspect reverse proxy and load balancer configurations for unsafe URL forwarding.  
93. Use cloud provider API scanning for exposed admin or metadata endpoints.  
94. Automate SSRF detection in CI/CD pipeline webhooks and plugins.  
95. Use Shodan or Censys for finding publicly exposed vulnerable SSRF endpoints.  
96. Leverage GitHub dorks to find endpoints implementing URL fetch in repos.  
97. Examine authentication mechanisms for SSRF attack surface in APIs.  
98. Combine SSRF with token replay attacks for privilege escalation.  
99. Test uncommon URL schemes and encoding to bypass input filters.  
100. Integrate SSRF detection into continuous scanning for evolving codebases.

---

## Helpful Resources & Links for SSRF Vulnerability Hunting  
- OWASP SSRF Overview: https://owasp.org/www-community/attacks/Server_Side_Request_Forgery  
- PortSwigger SSRF Tutorial: https://portswigger.net/web-security/ssrf  
- Invicti SSRF Learning and Remediation Guide: https://www.invicti.com/learn/server-side-request-forgery-ssrf/  
- ProjectDiscovery Nuclei SSRF Templates: https://github.com/projectdiscovery/nuclei-templates (search `ssrf`)  
- SSRFmap Tool: https://github.com/swisskyrepo/SSRFmap  
- SSRFuzz Tool: https://github.com/r0oth3x49/SSRFuzz  
- DNSLogger: https://dnslog.cn/ or https://interact.sh for OOB blind SSRF detection  
- GitHub Dorks for SSRF Endpoints: `"url=" OR "redirect=" extension:php OR extension:aspx`  
- Cloud Metadata Services Info:  
  - AWS: http://169.254.169.254/latest/meta-data  
  - Azure: http://169.254.169.254/metadata/instance  
  - GCP: Metadata server IP same as AWS  

---

## Summary  
- SSRF enables attackers to abuse server functionality to pivot into internal or cloud services not exposed externally.  
- Commonly found in URL-fetching features, webhook callbacks, API proxies, and parsing services handling URLs.  
- Discovery requires fuzzing URL input vectors and examining code or configurations that build external/internal requests.  
- Combining SSRF with other bugs like RCE, XXE, or token theft increases impact dramatically.

---

**BountyBoy: Elite Bug Bounty Program — trusted by learners. 
📄 Syllabus: https://lnkd.in/d6vTg3k9 
🎯 Enroll Now: https://lnkd.in/d7p5spcS
