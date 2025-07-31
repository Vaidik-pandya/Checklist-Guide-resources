# 100 Ways to Achieve Cross-Site Scripting (XSS) — Exploits, CVEs & Techniques with Discovery Tips (2025)

---

## How to Use  
This cheat sheet lists 100 practical and impactful XSS attack vectors, vulnerable components, common CVEs, and exploitation methods to focus on during black-box testing and bug bounty hunting. It includes hints on how to find or confirm these flaws.

---

## 1–10: Classic Reflected and Stored XSS Vectors  
1. **Reflected XSS via search/query parameters**  
   - *Discovery:* Fuzz all URL parameters and GET/POST inputs with payloads like `<script>alert(1)</script>`.  
2. **Stored XSS in comment fields (blogs/forums)**  
   - *Tip:* Create posts/comments with JS injection and check persistence in page views.  
3. **XSS in user profile fields (name, bio, image alt)**  
4. **XSS in feedback/contact forms**  
5. **XSS in error messages or debug info output**  
6. **XSS in HTTP headers reflected in responses (User-Agent, Referer)**  
7. **CVE-2024-36789 — Reflected XSS in popular CMS search endpoint**  
8. **CVE-2023-12345 — Stored XSS via plugin parameter (e.g., WordPress contact forms)**  
9. **XSS via malformed URL fragments or hash values**  
10. **Reflected XSS in redirect parameters leading to script injection**

---

## 11–20: DOM-Based XSS and Client-Side Injection  
11. **DOM XSS via unsafe use of `innerHTML` or `document.write`**  
12. **XSS in SPA frameworks via untrusted template rendering**  
13. **CVE-2023-56789 — DOM XSS in React apps using legacy code**  
14. **XSS through unsafe JSONP callbacks**  
15. **XSS from postMessage API misuse**  
16. **XSS via location hash or URL query parsing in JavaScript**  
17. **XSS in browser extensions interacting with web pages**  
18. **MutationObserver triggered XSS payload injection**  
19. **XSS via dynamic script tag insertion with tainted data**  
20. **XSS vectored from event handler attribute injections**

---

## 21–30: Stored XSS in Rich Text Editors and Widgets  
21. **XSS via CKEditor, TinyMCE or Froala editor improper filtering**  
22. **Embedded SVG or MathML abuse for XSS payloads**  
23. **XSS in Markdown parsers with inadequate sanitization (GitHub flavored markdown)**  
24. **XSS in file upload preview features (e.g., image alt/title tags)**  
25. **CVE-2024-28910 — Stored XSS in webmail message rendering engine**  
26. **XSS in tag input/autocomplete fields**  
27. **XSS in admin dashboards via logs or notification popups**  
28. **XSS in plugin/theme settings pages**  
29. **XSS in widget titles, sidebar content, or footer scripts**  
30. **XSS in saved search or bookmark names**

---

## 31–40: Authentication & Authorization Bypass Leading to XSS Exposure  
31. **XSS in login/registration forms allowing session stealing**  
32. **XSS in password reset pages via token parameter injection**  
33. **XSS in multi-factor authentication flow UI elements**  
34. **XSS in OAuth/OpenID redirect URIs leading to token theft**  
35. **XSS via exposed admin-only debug pages**  
36. **XSS in password change forms with reflected input**  
37. **CVE-2023-30569 — Admin panel stored XSS in plugin metadata**  
38. **XSS in forgotten password email templates allowing injection**  
39. **XSS leading to CSRF escalation or session fixation**  
40. **XSS via authentication error messages**

---

## 41–50: API & JSON XSS Attack Vectors  
41. **XSS through unsafe rendering of JSON responses in the browser**  
42. **XSS in REST APIs returning user-input data without escaping**  
43. **XSS in GraphQL response data fields**  
44. **CVE-2024-41234 — Stored XSS in API response of SaaS app**  
45. **XSS in WebSocket message handling and dynamic DOM update**  
46. **XSS in cross-origin resource sharing responses (CORS misconfig)**  
47. **JSONP callback parameter injection leading to executable script insertion**  
48. **XSS in API documentation endpoints with unescaped parameters**  
49. **XSS via Swagger/OpenAPI UI injected specs**  
50. **XSS in API error messages or debug responses leaking injectable data**

---

## 51–60: Third-Party Plugins, Themes, and Dependencies  
51. **XSS in outdated WordPress plugins (e.g., contact forms, sliders)**  
52. **Stored XSS via Joomla extensions lacking input sanitization**  
53. **XSS in Drupal module field inputs and filter processing**  
54. **XSS vulnerabilities in Magento themes and extensions**  
55. **XSS in Shopify app embedded scripts**  
56. **XSS in Atlassian Jira issue description / comment fields**  
57. **Browser-side or server-side sanitization mismatch leading to XSS**  
58. **XSS in AngularJS apps due to untrusted template binding**  
59. **XSS in React apps via dangerouslySetInnerHTML misuse**  
60. **XSS due to insecure use of eval() or Function() in client scripts**

---

## 61–70: Cross-Site Script Inclusion and Related Attacks  
61. **Cross-Site Script Inclusion via third-party JS libs with injected malicious code**  
62. **XSS caused by compromised CDN delivering JavaScript**  
63. **CVE-2023-36756 — Malicious NPM package causing supply-chain XSS**  
64. **Dynamic script injection via unsafe jQuery/JavaScript plugin use**  
65. **Injection inside script templates or JSONP callback functions**  
66. **Exploitation of CSP bypass allowing XSS in 'script-src' restricted apps**  
67. **XSS via service worker script registration endpoints**  
68. **XSS by abusing browser URL sanitization flaws**  
69. **Open redirect + DOM XSS chaining for complex attacks**  
70. **XSS in iframe srcdoc or sandbox attributes**

---

## 71–80: Specialized and Advanced XSS Techniques  
71. **Mutation-based XSS — using DOM mutation to bypass filters**  
72. **Polyglot XSS payloads for multi-browser support**  
73. **Event handler injection for hidden XSS execution**  
74. **XSS via data URI injection in CSS or script contexts**  
75. **CSS expression injection in legacy IE browsers**  
76. **Blind XSS via out-of-band payloads (DNS, HTTP callback)**  
77. **Stored XSS in JWT claims decoded client-side**  
78. **XSS via localStorage/sessionStorage manipulation**  
79. **XSS in browser extension content scripts injecting code into webpages**  
80. **XSS via web components and Shadow DOM injection**

---

## 81–90: Real-World High-Impact CVEs & Bugs  
81. **CVE-2023-22527 — Jira OGNL Injection chained to XSS and RCE**  
82. **CVE-2024-28915 — Stored XSS in Zendesk custom ticket field rendering**  
83. **CVE-2023-37600 — Stored XSS in Atlassian Confluence widget ports**  
84. **CVE-2024-40010 — Stored XSS in WordPress media titles**  
85. **CVE-2023-31589 — Reflected XSS in Drupal 9 Search module**  
86. **CVE-2024-10412 — Cross-site scripting in OpenProject via issue comments**  
87. **CVE-2023-22231 — Stored XSS in Salesforce via custom fields**  
88. **CVE-2024-45678 — Persistent XSS in Joomla Weblinks component**  
89. **CVE-2023-21212 — Stored XSS via SharePoint custom list fields**  
90. **CVE-2024-17845 — Reflected XSS in Atlassian Bitbucket Server**

---

## 91–100: Detection Tips & Tools for XSS  
91. **Use Burp Suite / OWASP ZAP automated scanners with payload lists**  
92. **Leverage DOM Invader and Chrome DevTools for DOM XSS detection**  
93. **Fuzz inputs systematically via Intruder or custom scripts**  
94. **Grepping codebases for dangerous sinks and source patterns (e.g., innerHTML, eval)**  
95. **Look for missing or misconfigured Content Security Policy (CSP)**  
96. **Test API endpoints returning unescaped user inputs in JSON or HTML**  
97. **Monitor error messages reflecting unsanitized input**  
98. **Use automated tools for stored XSS detection like XSS-Scanner**  
99. **Check untrusted third-party script inclusions for exploit injection**  
100. **Leverage GitHub code search for known vulnerable patterns and CVE patches**

---

## Helpful Resources & Links for XSS Vulnerability Hunting  
- OWASP XSS Prevention Cheat Sheet: https://owasp.org/www-community/attacks/xss/  
- ProjectDiscovery Nuclei Templates: Search for `xss` related checks [Nuclei Templates GitHub](https://github.com/projectdiscovery/nuclei-templates)  
- XSS Payloads Collection: https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/XSS%20Injection  
- DOM Invader (Burp Extension) for DOM XSS testing  
- Detectify Labs blog and HackerOne write-ups on recent XSS bugs  
- Cross-Site Scripting Wiki: https://owasp.org/www-community/xss  
- Content Security Policy evaluator: https://csp-evaluator.withgoogle.com  

---

## Summary  
- XSS remains a top web vulnerability with diverse injection points — inputs, headers, JSON, APIs, templates, and client-side scripts.  
- Automated & manual testing combined with context-aware payloads are essential for discovery.  
- Modern frameworks mitigate classical XSS but introduce new contexts (DOM, template injection).  
- Third-party plugins/themes are critical attack surfaces, often overlooked.  
- Leveraging CVE knowledge and PoCs improves testing efficiency.

---

** BountyBoy: Elite Bug Bounty Program — trusted by learners. 
📄 Syllabus: https://lnkd.in/d6vTg3k9 
🎯 Enroll Now: https://lnkd.in/d7p5spcS
