# Enhanced Web Application Security Tools

HexStrike AI Phase 3: Advanced web application security testing tools.

## JavaScript Security Analysis (8 tools)

### retire-js
Scan for vulnerable JavaScript libraries.
```python
from tools.web.js_analysis import retire_js_scan
result = retire_js_scan("https://example.com")
print(result['output'])
```

### linkfinder
Extract endpoints and URLs from JavaScript files.
```python
from tools.web.js_analysis import linkfinder_extract
result = linkfinder_extract("https://example.com/app.js")
print(f"Found {result['count']} endpoints")
```

### trufflehog
Scan for secrets and credentials in code repositories.

### secretfinder
Find API keys, tokens, and secrets in JavaScript files.

### sourcemapper
Extract and analyze JavaScript source maps for code review.

### jsluice
Extract URLs, API endpoints, and secrets from JavaScript using regex patterns.

## Injection Testing (7 tools)

### nosqlmap
NoSQL injection testing for MongoDB, CouchDB, and other NoSQL databases.
```python
from tools.web.injection_testing import nosqlmap_scan
result = nosqlmap_scan("https://api.example.com/users", method="POST", data="username=admin")
```

### ssrf-sheriff
Server-Side Request Forgery (SSRF) vulnerability scanner.

### xxeinjector
XML External Entity (XXE) vulnerability testing.

### ldap-injector
LDAP injection testing for directory services.

### xpath-injector
XPath injection vulnerability scanner.

### ssti-scanner
Server-Side Template Injection detection (Jinja2, Twig, Freemarker).

### crlf-injection-scanner
CRLF injection testing for HTTP response splitting.

## Authentication Testing (6 tools)

### csrf-scanner
Cross-Site Request Forgery (CSRF) vulnerability detection.
```python
from tools.web.auth_testing import csrf_scanner
result = csrf_scanner("https://example.com/dashboard")
print(f"Found {len(result['findings'])} CSRF issues")
```

### session-hijacking-kit
Session security testing (fixation, prediction, hijacking).

### cookie-analyzer
Cookie security analysis (HttpOnly, Secure, SameSite flags).

### saml-raider
SAML authentication testing and bypass techniques.

### keycloak-scanner
Keycloak security scanner for exposed admin consoles and misconfigurations.

### password-reset-analyzer
Password reset flow security testing (token predictability, rate limiting).

## CMS Security Scanners (5 tools)

### joomscan
Joomla vulnerability scanner.
```bash
joomscan -u https://example.com --enumerate-components
```

### droopescan
Drupal vulnerability scanner with plugin enumeration.

### magescan
Magento e-commerce security scanner.

### shopware-scanner
Shopware security testing (exposed files, admin panels).

### prestashop-scanner
PrestaShop security scanner for misconfigurations.

## CDN & Caching Tools (4 tools)

### cdn-scanner
CDN detection and enumeration (Cloudflare, Akamai, Fastly, CloudFront).
```python
from tools.web.cdn_tools import cdn_scanner
result = cdn_scanner("example.com")
if result['cdn_detected']:
    print(f"CDN: {result['findings']}")
```

### cache-poisoner
Web cache poisoning vulnerability testing.

### cdn-bypass
CDN bypass techniques (origin IP discovery, subdomain enumeration).

### cloudflare-bypass
Cloudflare-specific bypass methods and origin leak detection.

## Usage Examples

### Complete Web Security Assessment
```python
from tools.web.js_analysis import retire_js_scan, linkfinder_extract
from tools.web.injection_testing import nosqlmap_scan, ssrf_sheriff_scan
from tools.web.auth_testing import csrf_scanner, cookie_analyzer

# 1. JS Security Analysis
js_vulns = retire_js_scan("https://example.com")
endpoints = linkfinder_extract("https://example.com/app.js")

# 2. Injection Testing
nosql_results = nosqlmap_scan("https://api.example.com/users")
ssrf_results = ssrf_sheriff_scan("https://example.com/proxy")

# 3. Authentication Security
csrf_results = csrf_scanner("https://example.com/dashboard")
cookie_results = cookie_analyzer("https://example.com")
```

### CMS Vulnerability Scanning
```python
from tools.web.cms_scanners import joomscan, droopescan, shopware_scanner

# Detect and scan CMS
joomla_scan = joomscan("https://joomla-site.com", enumerate=True)
drupal_scan = droopescan("https://drupal-site.com", cms_type="drupal")
shopware_scan = shopware_scanner("https://shop.example.com")
```

## Tool Count
**30 enhanced web application security tools** across JS analysis, injection testing, authentication, CMS scanning, and CDN/caching domains.

## Safety Notice
⚠️ **WARNING**: These tools may trigger security alerts and are for authorized testing only.
Only use on systems you own or have written permission to test.
