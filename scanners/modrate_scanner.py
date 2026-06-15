import sys
import json
import time
import re
import os
import shutil
import subprocess
from urllib.parse import urlparse, urljoin
import requests
from html.parser import HTMLParser

class WebParser(HTMLParser):
    def __init__(self):
        super().__init__()
        self.links = []
        self.scripts = []
        self.forms = []
        self.current_form = None

    def handle_starttag(self, tag, attrs):
        attrs_dict = dict(attrs)
        for attr, val in attrs:
            if attr in ['href', 'src']:
                self.links.append(val)
            if tag == 'script' and attr == 'src':
                self.scripts.append(val)

        if tag == 'form':
            self.current_form = {
                'action': attrs_dict.get('action', ''),
                'method': attrs_dict.get('method', 'get').lower(),
                'inputs': []
            }
            self.forms.append(self.current_form)
        elif tag == 'input' and self.current_form is not None:
            self.current_form['inputs'].append({
                'name': attrs_dict.get('name', ''),
                'type': attrs_dict.get('type', 'text').lower(),
                'value': attrs_dict.get('value', '')
            })

    def handle_endtag(self, tag):
        if tag == 'form':
            self.current_form = None

def check_cors_url(url, findings):
    test_origin = "https://attacker-vulnerable-test.com"
    headers = {
        "Origin": test_origin,
        "Access-Control-Request-Method": "GET"
    }
    try:
        # Check CORS using OPTIONS first, then fallback to GET
        res = requests.options(url, headers=headers, timeout=3)
        res_headers = res.headers
        
        if 'Access-Control-Allow-Origin' not in res_headers:
            res = requests.get(url, headers=headers, timeout=3)
            res_headers = res.headers
            
        allow_origin = res_headers.get('Access-Control-Allow-Origin', '')
        allow_creds = res_headers.get('Access-Control-Allow-Credentials', '').lower()
        
        if allow_origin == '*' or allow_origin == test_origin:
            if allow_creds == 'true':
                findings.append({
                    "id": "CORS_MISCONFIG_CREDENTIALS",
                    "severity": "high",
                    "title": "CORS Misconfiguration with Credentials Allowed",
                    "description": f"The server allows Origin '{allow_origin}' with Access-Control-Allow-Credentials set to true.",
                    "impact": "Allows malicious websites to read sensitive authenticated responses (session data, user details) via CSRF-style browser queries.",
                    "remediation": "Do not allow wildcard origins or reflect arbitrary origins when credentials are allowed. Specify exact trusted origin domains.",
                    "reference": "https://portswigger.net/web-security/cors"
                })
            elif allow_origin == test_origin:
                findings.append({
                    "id": "CORS_ARBITRARY_ORIGIN_ALLOWED",
                    "severity": "medium",
                    "title": "CORS Arbitrary Origin Reflection",
                    "description": "The server reflects arbitrary requested origins in the Access-Control-Allow-Origin header.",
                    "impact": "Exposes API endpoints to cross-origin resource access by unauthorized web domains.",
                    "remediation": "Validate the incoming Origin header against a strict whitelist of trusted domains before reflecting it.",
                    "reference": "https://owasp.org/www-project-top-ten/2021/A05_2021-Security_Misconfiguration"
                })
    except Exception:
        pass

def check_swagger_url(url, findings):
    swagger_paths = [
        "/swagger-ui.html", 
        "/swagger-ui/", 
        "/api-docs", 
        "/openapi.json", 
        "/swagger.json", 
        "/v2/api-docs", 
        "/redoc"
    ]
    for path in swagger_paths:
        test_url = urljoin(url, path)
        try:
            res = requests.get(test_url, timeout=3)
            if res.status_code == 200:
                body = res.text
                content_type = res.headers.get('content-type', '').lower()
                
                is_json_spec = "json" in content_type and ("swagger" in body.lower() or "openapi" in body.lower() or "\"paths\"" in body)
                is_ui = "swagger ui" in body.lower() or "redoc" in body.lower() or "swagger-ui" in body.lower()
                
                if is_json_spec or is_ui:
                    findings.append({
                        "id": "EXPOSED_SWAGGER_API_DOCS",
                        "severity": "medium",
                        "title": f"Exposed Interactive API Documentation at {path}",
                        "description": f"Swagger or OpenAPI documentation UI/specification was found publicly exposed at {path}.",
                        "impact": "Provides attackers with an interactive sandbox and detailed schema map of all backend API endpoints and parameters.",
                        "remediation": "Restrict access to Swagger/OpenAPI docs in production (e.g. require authentication or block in production build config).",
                        "reference": "https://cwe.mitre.org/data/definitions/200.html"
                    })
                    break
        except Exception:
            pass

def check_sqli_csrf_url(url, findings, parser):
    parsed = urlparse(url)
    sql_payloads = ["'", "\"", " OR 1=1 --", " --"]
    sql_errors = [
        "sql syntax", "mysql_fetch_", "unclosed quotation mark",
        "postgresql query failed", "sqlite3.operationalerror",
        "ora-00933", "syntax error near", "mariadb", "db error"
    ]
    
    if parsed.query:
        for payload in sql_payloads:
            params = []
            for param in parsed.query.split('&'):
                if '=' in param:
                    k, v = param.split('=', 1)
                    params.append(f"{k}={v}{payload}")
                else:
                    params.append(f"{param}{payload}")
            test_url = url.split('?')[0] + "?" + "&".join(params)
            try:
                res = requests.get(test_url, timeout=3)
                content = res.text.lower()
                if any(err in content for err in sql_errors):
                    findings.append({
                        "id": "SQL_INJECTION_QUERY",
                        "severity": "high",
                        "title": "Potential SQL Injection in Query Parameter",
                        "description": f"Injecting '{payload}' in URL query parameter returned database syntax error indicators.",
                        "impact": "Allows unauthorized users to run arbitrary commands on the database, bypass authentication, and extract all tables.",
                        "remediation": "Use parameterized queries (prepared statements) for all database operations instead of dynamic string concatenation.",
                        "reference": "https://owasp.org/www-project-top-ten/2021/A03_2021-Injection"
                    })
                    break
            except Exception:
                pass

    for form in parser.forms:
        action = form.get('action', '')
        method = form.get('method', 'get').lower()
        inputs = form.get('inputs', [])
        
        if method == 'post':
            csrf_token_names = ['csrf', 'token', '_csrf', 'xsrf', 'authenticity']
            has_csrf = False
            for inp in inputs:
                name = inp.get('name', '').lower()
                for token_name in csrf_token_names:
                    if token_name in name:
                        has_csrf = True
                        break
                if has_csrf:
                    break
            
            parsed_action = urlparse(action)
            is_local = not parsed_action.netloc or parsed_action.netloc == parsed.netloc
            
            if not has_csrf and is_local:
                findings.append({
                    "id": "CSRF_TOKEN_MISSING",
                    "severity": "medium",
                    "title": f"Missing CSRF Token in POST Form ({action})",
                    "description": f"The form acting on '{action}' uses POST method but does not contain a CSRF token field.",
                    "impact": "Enables Cross-Site Request Forgery, where attackers trick authenticated users into submitting unintended write actions.",
                    "remediation": "Implement an anti-CSRF token verification system on the server side and include the token in all write-state HTML forms.",
                    "reference": "https://owasp.org/www-community/attacks/csrf"
                })

def check_ssrf_idor_url(url, findings, parser):
    parsed = urlparse(url)
    ssrf_params = ["url", "fetch", "image", "uri", "path", "file", "src", "u", "link", "api", "target"]
    idor_params = ["id", "uid", "user_id", "account", "invoice", "doc", "document", "order", "file_id", "project_id"]
    
    if parsed.query:
        for param in parsed.query.split('&'):
            if '=' in param:
                k, v = param.split('=', 1)
                if k.lower() in ssrf_params:
                    loopback_payload = "http://127.0.0.1:44444"
                    test_query = parsed.query.replace(f"{k}={v}", f"{k}={loopback_payload}")
                    test_url = url.split('?')[0] + "?" + test_query
                    try:
                        res = requests.get(test_url, timeout=3)
                        content = res.text.lower()
                        ssrf_signatures = ["connection refused", "failed to connect", "127.0.0.1", "host unreachable", "connection timed out"]
                        if any(sig in content for sig in ssrf_signatures):
                            findings.append({
                                "id": "POTENTIAL_SSRF_PARAMETER",
                                "severity": "high",
                                "title": "Potential Server-Side Request Forgery (SSRF)",
                                "description": f"The query parameter '{k}' was injected with a loopback URL and leaked internal connection error indicators.",
                                "impact": "Allows attackers to make the server scan internal ports, query private metadata services, or access internal microservices.",
                                "remediation": "Enforce a strict whitelist of permitted host domains for outgoing HTTP requests. Do not accept arbitrary user-supplied URLs.",
                                "reference": "https://owasp.org/www-project-top-ten/2021/A10_2021-Server-Side_Request_Forgery_%28SSRF%29"
                            })
                            break
                    except Exception:
                        pass
        
        for param in parsed.query.split('&'):
            if '=' in param:
                k, v = param.split('=', 1)
                if k.lower() in idor_params:
                    if v.isdigit():
                        findings.append({
                            "id": "SEQUENTIAL_ID_EXPOSED",
                            "severity": "medium",
                            "title": "Sequential Resource Identifier Exposed (Potential IDOR)",
                            "description": f"Exposes sequential database ID '{v}' in query parameter '{k}'.",
                            "impact": "Exposes resource references directly. If object-level authorization is missing, attackers can iterate IDs to scrape data.",
                            "remediation": "Verify that backend endpoints enforce strict ownership validation on resource objects, and consider using UUIDs instead of sequential integers.",
                            "reference": "https://cheatsheetseries.owasp.org/cheatsheets/Insecure_Direct_Object_Reference_Prevention_Cheat_Sheet.html"
                        })
                        break

def check_outdated_crypto_deserialization_url(url, findings, headers, html_content, parser, cookies):
    server = headers.get('Server', '')
    x_powered = headers.get('X-Powered-By', '')
    version_pattern = r'([a-zA-Z\-_]+)/(\d+\.\d+(\.\d+)?)'
    detected = []
    for h_val in [server, x_powered]:
        if h_val:
            matches = re.findall(version_pattern, h_val)
            for name, version, _ in matches:
                detected.append(f"{name} v{version}")
                
    if detected:
        findings.append({
            "id": "OUTDATED_SERVER_COMPONENTS",
            "severity": "medium",
            "title": "Outdated Server Component Version Exposed",
            "description": f"The target returned version-specific server headers: {', '.join(detected)}.",
            "impact": "Exposing specific version tags makes it easier for attackers to identify known public vulnerabilities (CVEs) targeting that environment.",
            "remediation": "Configure the web server to hide specific product and version identifiers (e.g. ServerTokens ProductOnly, expose_php = Off).",
            "reference": "https://cwe.mitre.org/data/definitions/200.html"
        })

    weak_crypto_terms = ["cryptojs.md5", "md5(", "sha1.js", "sha1(", "hex_md5"]
    found_terms = []
    for term in weak_crypto_terms:
        if term in html_content.lower():
            found_terms.append(term)
    for script in parser.scripts:
        if any(term in script.lower() for term in ["md5", "sha1", "crypto-js"]):
            found_terms.append(script)
            
    if found_terms:
        findings.append({
            "id": "WEAK_CLIENT_CRYPTOGRAPHY",
            "severity": "medium",
            "title": "Weak Cryptographic Algorithms Reference in Client Scripts",
            "description": f"Detected reference to legacy cryptographic algorithms (MD5/SHA1) in client scripts. Found: {', '.join(found_terms)}.",
            "impact": "Using obsolete algorithms like MD5 or SHA-1 for sensitive hashing/signatures makes them vulnerable to collision attacks and password cracking.",
            "remediation": "Migrate to stronger cryptographic standards (SHA-256, SHA-3, or bcrypt/argon2 for passwords).",
            "reference": "https://cwe.mitre.org/data/definitions/328.html"
        })

    for cookie_name, cookie_val in cookies.items():
        if "ro0ab" in cookie_val.lower():
            findings.append({
                "id": "INSECURE_DESERIALIZATION_COOKIE_JAVA",
                "severity": "high",
                "title": f"Java Serialized Object in Cookie ({cookie_name})",
                "description": "Cookie value contains the Java serialized object magic signature 'rO0AB'.",
                "impact": "Allows Remote Code Execution (RCE) if the application deserializes the user-supplied cookie value without object validation.",
                "remediation": "Avoid using native serialization format. Use standard data exchange formats like JSON or XML with input validation.",
                "reference": "https://owasp.org/www-project-top-ten/2021/A08_2021-Software_and_Data_Integrity_Failures"
            })
            break
        elif re.search(r'(o:\d+:|a:\d+:\{)', cookie_val, re.IGNORECASE):
            findings.append({
                "id": "INSECURE_DESERIALIZATION_COOKIE_PHP",
                "severity": "medium",
                "title": f"PHP Serialized Object in Cookie ({cookie_name})",
                "description": "Cookie value contains a plaintext PHP serialized object string.",
                "impact": "Can lead to Object Injection vulnerabilities, privilege escalation, or code execution.",
                "remediation": "Use JSON encoding (json_encode) instead of native php serialization (serialize/unserialize).",
                "reference": "https://cwe.mitre.org/data/definitions/502.html"
            })
            break

def check_rate_limiting_url(url, findings):
    import concurrent.futures
    def send_req(u):
        try:
            res = requests.get(u, timeout=2)
            return res.status_code
        except Exception:
            return None
            
    status_codes = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=10) as executor:
        futures = [executor.submit(send_req, url) for _ in range(15)]
        for fut in concurrent.futures.as_completed(futures):
            status_codes.append(fut.result())
            
    if 429 in status_codes:
        pass
    else:
        findings.append({
            "id": "RATE_LIMITING_MISSING",
            "severity": "medium",
            "title": "Missing Rate Limiting / Request Throttling",
            "description": "Fired 15 rapid concurrent requests to the target, and all requests succeeded without receiving HTTP 429 (Too Many Requests).",
            "impact": "Exposes the application to brute-force attacks, high-frequency credential stuffing, scraper bots, and denial-of-service (DoS) attempts.",
            "remediation": "Configure request throttling at the gateway (e.g. Cloudflare, Nginx limit_req) or application layer (e.g. express-rate-limit).",
            "reference": "https://cheatsheetseries.owasp.org/cheatsheets/Denial_of_Service_Prevention_Cheat_Sheet.html"
        })

def scan_github_content(rel_path, content, findings):
    cors_patterns = [
        (r'Access-Control-Allow-Origin.*\*', "CORS_WILDCARD_HEADERS", "medium", "Wildcard Access-Control-Allow-Origin configured in code", 
         "Allows resource access from any arbitrary domain on the web.", 
         "Specify trusted origin domains rather than wildcards."),
        (r'cors\(\s*\{\s*origin\s*:\s*true\s*,\s*credentials\s*:\s*true', "CORS_REFLECT_CREDENTIALS_EXPRESS", "high", "CORS Credentials Allowed with Origin Reflection",
         "Allows any origin to send requests with credentials (cookies) and read response payload.",
         "Implement origin verification against a whitelist before reflecting the Origin header."),
        (r'cors\s*\(\s*origin\s*=\s*[\'"]\*[\'"]', "CORS_WILDCARD_PYTHON", "medium", "Permissive CORS origin wildcard in Python settings",
         "Enables cross-origin access from any remote site.",
         "Restrict origins to trusted domains in CORS configuration.")
    ]
    for pattern, fid, severity, title, impact, remediation in cors_patterns:
        match = re.search(pattern, content, re.IGNORECASE)
        if match:
            findings.append({
                "id": fid,
                "severity": severity,
                "title": f"{title} ({rel_path})",
                "description": f"Found permissive CORS configuration matching: '{match.group(0)}' in {rel_path}.",
                "impact": impact,
                "remediation": remediation,
                "reference": "https://portswigger.net/web-security/cors"
            })

    swagger_patterns = [
        (r'import.*swagger', "GIT_SWAGGER_IMPORT", "medium", "Swagger Documentation Module imported",
         "Indicates api documentation is generated from code, which could leak to production.",
         "Ensure Swagger UI route definitions are disabled in production builds."),
        (r'swagger-ui-express', "GIT_EXPRESS_SWAGGER_DEP", "medium", "Swagger Express dependency declared",
         "The project declares swagger UI module in package.json, which could expose routing schemas.",
         "Restrict API documentation endpoints behind authentication gates in production."),
        (r'drf-yasg|django-rest-swagger', "GIT_DJANGO_SWAGGER_DEP", "medium", "Django Rest Swagger package referenced",
         "Exposes automatic API documentation generation routes in Django application.",
         "Configure settings to enable API docs only for local dev environments.")
    ]
    for pattern, fid, severity, title, impact, remediation in swagger_patterns:
        match = re.search(pattern, content, re.IGNORECASE)
        if match:
            findings.append({
                "id": fid,
                "severity": severity,
                "title": f"{title} ({rel_path})",
                "description": f"Detected Swagger configuration package '{match.group(0)}' in {rel_path}.",
                "impact": impact,
                "remediation": remediation,
                "reference": "https://cwe.mitre.org/data/definitions/200.html"
            })

    sqli_patterns = [
        (r'db\.(query|execute)\s*\(\s*([\'"`].*SELECT.*FROM.*\+\s*\w+|f?[\'"`].*SELECT.*FROM.*\{\w+\})', "GIT_SQL_INTERPOLATION_JS", "high", "SQL Query Concatenation in Javascript",
         "Dynamic SQL query construction can lead to SQL Injection vulnerabilities.",
         "Utilize parameterization or ORM query builders (e.g. prepared statements) to separate query template from data input."),
        (r'execute\s*\(\s*([\'"`].*SELECT.*FROM.*\s*%\s*\w+|f[\'"`].*SELECT.*FROM.*\{\w+\})', "GIT_SQL_INTERPOLATION_PY", "high", "SQL Query Concatenation in Python",
         "Direct string formatting or interpolation in SQL queries bypasses standard filters, leading to injection.",
         "Pass query parameters as a separate tuple/list argument to the execute() method."),
        (r'\.query\s*\(\s*[\'"`].*SELECT.*FROM.*\.format\(', "GIT_SQL_FORMAT_CONCAT", "high", "SQL Query String format usage",
         "String format operations inside database queries allow attackers to manipulate queries.",
         "Ensure query bindings are handled natively by database driver parameterized wrappers.")
    ]
    for pattern, fid, severity, title, impact, remediation in sqli_patterns:
        match = re.search(pattern, content, re.IGNORECASE)
        if match:
            findings.append({
                "id": fid,
                "severity": severity,
                "title": f"{title} ({rel_path})",
                "description": f"Detected potential SQL Injection query construct: '{match.group(0)}' in {rel_path}.",
                "impact": impact,
                "remediation": remediation,
                "reference": "https://owasp.org/www-community/attacks/SQL_Injection"
            })

    csrf_patterns = [
        (r'@csrf_exempt', "GIT_CSRF_EXEMPT_DECORATOR", "high", "CSRF Protection Exempted",
         "Exempting CSRF validation on views allows attackers to execute cross-site request forgery.",
         "Avoid using csrf_exempt unless necessary, and enforce strict custom token/signature checks on those routes."),
        (r'WTF_CSRF_ENABLED\s*=\s*False', "GIT_CSRF_DISABLED_FLASK", "high", "WTF CSRF Disabled in Flask settings",
         "Explicitly disabling CSRF validation exposes the Flask application to write action exploits.",
         "Ensure WTF_CSRF_ENABLED is configured to True in production environment settings.")
    ]
    for pattern, fid, severity, title, impact, remediation in csrf_patterns:
        match = re.search(pattern, content, re.IGNORECASE)
        if match:
            findings.append({
                "id": fid,
                "severity": severity,
                "title": f"{title} ({rel_path})",
                "description": f"Detected CSRF protection disabled: '{match.group(0)}' in {rel_path}.",
                "impact": impact,
                "remediation": remediation,
                "reference": "https://owasp.org/www-community/attacks/csrf"
            })

    ssrf_patterns = [
        (r'(fetch|axios\.(get|post|request))\(\s*(req\.(query|params|body)\.\w+|\w*\+req\.)', "GIT_SSRF_JS", "high", "Potential SSRF in Javascript Fetch",
         "Sourcing request URL directly from user inputs allows Server-Side Request Forgery.",
         "Validate and whitelist URL target inputs against a strict list of allowed domain names."),
        (r'requests\.(get|post|request)\(\s*(\w*req|\w*input|\w*url)', "GIT_SSRF_PY", "high", "Potential SSRF in Python Requests",
         "Outgoing request URL is dynamically formatted from variable parameters without validation.",
         "Ensure user input is strictly validated or restricted to local path routing."),
        (r'urlopen\(\s*(\w*req|\w*input|\w*url)', "GIT_SSRF_URLLIB", "high", "Potential SSRF in urllib open call",
         "urllib is allowed to query arbitrary resource strings.",
         "Restrict urlopen arguments or use safe library layers.")
    ]
    for pattern, fid, severity, title, impact, remediation in ssrf_patterns:
        match = re.search(pattern, content, re.IGNORECASE)
        if match:
            findings.append({
                "id": fid,
                "severity": severity,
                "title": f"{title} ({rel_path})",
                "description": f"Found potential SSRF fetch construct: '{match.group(0)}' in {rel_path}.",
                "impact": impact,
                "remediation": remediation,
                "reference": "https://owasp.org/www-project-top-ten/2021/A10_2021-Server-Side_Request_Forgery_%28SSRF%29"
            })

    idor_patterns = [
        (r'\.(findById|findOne|findByPk)\(\s*req\.(query|params)\.', "GIT_IDOR_JS", "high", "Direct Database Lookup on User Parameter (Potential IDOR)",
         "Queries database objects directly using client-controlled keys without visible authorization gates.",
         "Verify user session ownership on the queried resource before returning it to the client."),
        (r'get_object_or_404\(\s*\w+\s*,\s*id\s*=\s*(request\.GET|request\.query|id)', "GIT_IDOR_PYTHON", "high", "Direct object reference lookup in Django view",
         "Saves sequential integers directly to fetch objects without permission validation.",
         "Ensure access control permissions check ownership rules for the fetched object.")
    ]
    for pattern, fid, severity, title, impact, remediation in idor_patterns:
        match = re.search(pattern, content, re.IGNORECASE)
        if match:
            findings.append({
                "id": fid,
                "severity": severity,
                "title": f"{title} ({rel_path})",
                "description": f"Found direct database reference mapping: '{match.group(0)}' in {rel_path}.",
                "impact": impact,
                "remediation": remediation,
                "reference": "https://cheatsheetseries.owasp.org/cheatsheets/Insecure_Direct_Object_Reference_Prevention_Cheat_Sheet.html"
            })

    if rel_path == "package.json":
        lodash_match = re.search(r'"lodash"\s*:\s*["\']\^?([0-3]\.\d+\.\d+|4\.[0-9]\.\d+|4\.1[0-6]\.\d+)["\']', content)
        if lodash_match:
            findings.append({
                "id": "OUTDATED_VULNERABLE_LODASH",
                "severity": "medium",
                "title": "Outdated Vulnerable Dependency (lodash < 4.17.21)",
                "description": f"Found outdated lodash version '{lodash_match.group(1)}' in package.json.",
                "impact": "Older versions of lodash are vulnerable to Prototype Pollution, leading to remote code execution or crashes.",
                "remediation": "Update lodash to version 4.17.21 or higher.",
                "reference": "https://nvd.nist.gov/vuln/detail/CVE-2020-8203"
            })

    if rel_path == "requirements.txt":
        django_match = re.search(r'django==([0-2]\.\d+\.\d+|3\.[0-1]\.\d+|4\.0\.\d+)', content, re.IGNORECASE)
        if django_match:
            findings.append({
                "id": "OUTDATED_VULNERABLE_DJANGO",
                "severity": "high",
                "title": "Outdated Vulnerable Framework (Django < 4.2)",
                "description": f"Found outdated Django version '{django_match.group(1)}' in requirements.txt.",
                "impact": "Exposes Django applications to multiple security vulnerabilities fixed in newer releases.",
                "remediation": "Update Django to version 4.2 LTS or higher in your requirements.txt.",
                "reference": "https://docs.djangoproject.com/en/5.0/releases/"
            })

    weak_crypto_patterns = [
        (r'hashlib\.md5\(', "GIT_WEAK_HASH_MD5_PY", "medium", "Use of Weak Cryptographic Hash (MD5) in Python",
         "MD5 is cryptographically broken and vulnerable to collision attacks.",
         "Upgrade hash function to SHA-256 or SHA-3."),
        (r'hashlib\.sha1\(', "GIT_WEAK_HASH_SHA1_PY", "medium", "Use of Weak Cryptographic Hash (SHA-1) in Python",
         "SHA-1 has severe security weaknesses and collisions are practical.",
         "Migrate to SHA-256 or bcrypt for password hashing."),
        (r'crypto\.createHash\(\s*[\'"]md5[\'"]\)', "GIT_WEAK_HASH_MD5_JS", "medium", "Use of Weak Hash (MD5) in Javascript",
         "MD5 is susceptible to collisions and is unsafe for password verification.",
         "Utilize SHA-256 or pbkdf2 with high iteration counts."),
        (r'crypto\.createHash\(\s*[\'"]sha1[\'"]\)', "GIT_WEAK_HASH_SHA1_JS", "medium", "Use of Weak Hash (SHA-1) in Javascript",
         "SHA-1 is no longer considered secure for signature verification.",
         "Upgrade hash algorithm to SHA-256.")
    ]
    for pattern, fid, severity, title, impact, remediation in weak_crypto_patterns:
        match = re.search(pattern, content, re.IGNORECASE)
        if match:
            findings.append({
                "id": fid,
                "severity": severity,
                "title": f"{title} ({rel_path})",
                "description": f"Detected weak hash algorithm: '{match.group(0)}' in {rel_path}.",
                "impact": impact,
                "remediation": remediation,
                "reference": "https://cwe.mitre.org/data/definitions/328.html"
            })

    deserialization_patterns = [
        (r'pickle\.loads\(', "GIT_INSECURE_DESERIALIZATION_PICKLE_PY", "high", "Insecure Deserialization via pickle.loads()",
         "Python pickle allows arbitrary object construction, leading to Remote Code Execution.",
         "Do not deserialize untrusted inputs with pickle. Use JSON or XML serialization instead."),
        (r'yaml\.load\(\s*[^,)]+\s*\)', "GIT_INSECURE_YAML_LOAD_PY", "high", "Unsafe YAML Deserialization",
         "Using yaml.load() without SafeLoader allows arbitrary python command execution.",
         "Always load YAML files using yaml.safe_load() or specify Loader=yaml.SafeLoader."),
        (r'unserialize\(', "GIT_INSECURE_DESERIALIZATION_PHP", "high", "Insecure Deserialization via PHP unserialize()",
         "Deserializing user input using PHP unserialize() can trigger Object Injection and execution of arbitrary code.",
         "Use json_decode() for passing structured user-supplied data safely.")
    ]
    for pattern, fid, severity, title, impact, remediation in deserialization_patterns:
        match = re.search(pattern, content, re.IGNORECASE)
        if match:
            findings.append({
                "id": fid,
                "severity": severity,
                "title": f"{title} ({rel_path})",
                "description": f"Detected insecure deserialization pattern: '{match.group(0)}' in {rel_path}.",
                "impact": impact,
                "remediation": remediation,
                "reference": "https://cwe.mitre.org/data/definitions/502.html"
            })

    rate_limit_patterns = [
        (r'express-rate-limit', "GIT_EXPRESS_RATE_LIMIT_DEP", "medium", "Express Rate Limit dependency configured",
         "Protects API endpoints from automated brute forcing and volumetric abuse.",
         "Configure rate limiter options (max requests, windowMs) on sensitive auth routes."),
        (r'flask_limiter|FlaskLimiter', "GIT_FLASK_RATE_LIMIT", "medium", "Flask Limiter module referenced in code",
         "Ensures route-level request throttling is enabled in Flask application.",
         "Initialize Limiter(app) and apply @limiter.limit decorator to authentication routes."),
        (r'DEFAULT_THROTTLE_CLASSES|DEFAULT_THROTTLE_RATES', "GIT_DJANGO_RATE_LIMIT", "medium", "Django Rest Framework Throttling Configured",
         "Ensures Django REST APIs have throttling classes active to prevent API abuse.",
         "Configure REST_FRAMEWORK settings with AnonRateThrottle and UserRateThrottle classes.")
    ]
    for pattern, fid, severity, title, impact, remediation in rate_limit_patterns:
        match = re.search(pattern, content, re.IGNORECASE)
        if match:
            findings.append({
                "id": fid,
                "severity": severity,
                "title": f"{title} ({rel_path})",
                "description": f"Detected rate limiting package configuration: '{match.group(0)}' in {rel_path}.",
                "impact": impact,
                "remediation": remediation,
                "reference": "https://cheatsheetseries.owasp.org/cheatsheets/Denial_of_Service_Prevention_Cheat_Sheet.html"
            })

def calculate_scores(target_type, target, findings, html_content=None, headers=None, response_time=None, repo_path=None):
    # 1. Security Score
    security_score = 100
    for f in findings:
        severity = f.get('severity', 'low').lower()
        if severity == 'critical':
            security_score -= 30
        elif severity == 'high':
            security_score -= 20
        elif severity == 'medium':
            security_score -= 10
        else:
            security_score -= 5
    security_score = max(0, security_score)

    # 2. Quality Score & 3. Performance Score
    quality_score = 100
    performance_score = 100

    if target_type == 'url':
        # Quality (HTTPS and SEO checks)
        if not target.startswith('https://'):
            quality_score -= 15
        
        if html_content:
            html_lower = html_content.lower()
            if '<title>' not in html_lower or '</title>' not in html_lower:
                quality_score -= 15
            if 'name="description"' not in html_lower and "name='description'" not in html_lower:
                quality_score -= 15
            if '<h1' not in html_lower or '</h1>' not in html_lower:
                quality_score -= 15
            
            img_tags = re.findall(r'<img[^>]*>', html_content, re.IGNORECASE)
            if img_tags:
                missing_alt = 0
                for img in img_tags:
                    if 'alt=' not in img.lower():
                        missing_alt += 1
                if missing_alt > 0:
                    quality_score -= min(15, missing_alt * 5)
        else:
            quality_score = 50

        # Performance (Response time & Caching)
        if response_time is not None:
            if response_time < 0.2:
                pass
            elif response_time < 0.5:
                performance_score -= 5
            elif response_time < 1.0:
                performance_score -= 15
            elif response_time < 2.0:
                performance_score -= 30
            else:
                performance_score -= 50
        else:
            performance_score = 50

        if headers:
            cache_header = headers.get('Cache-Control', '')
            if not cache_header:
                performance_score -= 10
            elif 'no-store' in cache_header or 'no-cache' in cache_header:
                performance_score -= 5
        else:
            performance_score -= 10

    elif target_type == 'github':
        # Quality
        has_readme = False
        has_gitignore = False
        has_lint = False
        has_test = False
        total_lines = 0
        comment_lines = 0
        
        if repo_path and os.path.exists(repo_path):
            for root, dirs, files in os.walk(repo_path):
                if '.git' in dirs: dirs.remove('.git')
                if 'node_modules' in dirs: dirs.remove('node_modules')
                
                for file in files:
                    file_lower = file.lower()
                    if 'readme' in file_lower:
                        has_readme = True
                    if file_lower == '.gitignore':
                        has_gitignore = True
                    if file_lower in ['.eslintrc', '.eslintrc.json', '.eslintrc.js', '.prettierrc', 'tsconfig.json', 'pylintrc', 'setup.cfg', '.jshintrc']:
                        has_lint = True
                    if 'test' in file_lower or 'jest.config' in file_lower or 'pytest.ini' in file_lower or 'conftest.py' in file_lower:
                        has_test = True
                        
                    if file.endswith(('.js', '.ts', '.py', '.java', '.cpp', '.h', '.cs', '.go', '.rb', '.php')):
                        try:
                            filepath = os.path.join(root, file)
                            with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
                                for line in f:
                                    total_lines += 1
                                    trimmed = line.strip()
                                    if trimmed.startswith(('#', '//', '/*', '*')):
                                        comment_lines += 1
                        except:
                            pass
            
            if not has_readme:
                quality_score -= 20
            if not has_gitignore:
                quality_score -= 15
            if not has_lint:
                quality_score -= 15
            if not has_test:
                quality_score -= 15
                
            if total_lines > 0:
                doc_pct = comment_lines / total_lines
                if doc_pct < 0.05:
                    quality_score -= 15
                elif doc_pct < 0.10:
                    quality_score -= 10
                elif doc_pct < 0.15:
                    quality_score -= 5
            else:
                quality_score -= 10
        else:
            quality_score = 50

        # Performance (large files, uncompressed assets, dependencies count)
        large_files_count = 0
        uncompressed_assets = 0
        dependency_count = 0
        
        if repo_path and os.path.exists(repo_path):
            for root, dirs, files in os.walk(repo_path):
                if '.git' in dirs: dirs.remove('.git')
                if 'node_modules' in dirs: dirs.remove('node_modules')
                
                for file in files:
                    filepath = os.path.join(root, file)
                    try:
                        size_mb = os.path.getsize(filepath) / (1024 * 1024)
                        if size_mb > 1.0:
                            large_files_count += 1
                    except:
                        pass
                        
                    file_lower = file.lower()
                    if file_lower.endswith(('.png', '.jpg', '.jpeg', '.gif')):
                        if any(folder in root.lower().replace('\\', '/') for folder in ['public', 'static', 'assets', 'dist', 'www']):
                            try:
                                if os.path.getsize(filepath) > 200 * 1024:
                                    uncompressed_assets += 1
                            except:
                                pass
                    
                    if file_lower == 'package.json':
                        try:
                            with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
                                pkg_data = json.load(f)
                                deps = pkg_data.get('dependencies', {})
                                dev_deps = pkg_data.get('devDependencies', {})
                                dependency_count = len(deps) + len(dev_deps)
                        except:
                            pass
                            
            if large_files_count > 0:
                performance_score -= min(30, large_files_count * 10)
            if uncompressed_assets > 0:
                performance_score -= min(15, uncompressed_assets * 5)
            if dependency_count > 25:
                performance_score -= 10
            elif dependency_count > 15:
                performance_score -= 5
        else:
            performance_score = 50

    quality_score = max(30, quality_score)
    performance_score = max(30, performance_score)
    total_score = int(round((security_score + quality_score + performance_score) / 3))
    
    return {
        "securityScore": security_score,
        "qualityScore": quality_score,
        "performanceScore": performance_score,
        "totalScore": total_score
    }

def scan_github(target):
    findings = []
    temp_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), "temp_medium", f"repo_{int(time.time() * 1000)}")
    os.makedirs(temp_dir, exist_ok=True)
    
    try:
        result = subprocess.run(["git", "clone", "--depth=1", target, temp_dir], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, timeout=15)
        if result.returncode != 0:
            raise Exception(f"Git clone failed: {result.stderr}")
            
        for root, dirs, files in os.walk(temp_dir):
            if '.git' in dirs:
                dirs.remove('.git')
            if 'node_modules' in dirs:
                dirs.remove('node_modules')
                
            for filename in files:
                filepath = os.path.join(root, filename)
                rel_path = os.path.relpath(filepath, temp_dir)
                
                if filename.endswith(('.png', '.jpg', '.jpeg', '.gif', '.ico', '.pdf', '.woff', '.woff2', '.ttf', '.eot', '.mp3', '.mp4', '.zip', '.gz')):
                    continue
                    
                try:
                    with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
                        content = f.read()
                    scan_github_content(rel_path, content, findings)
                except Exception:
                    pass
                    
        scores = calculate_scores('github', target, findings, repo_path=temp_dir)
        return findings, scores
    finally:
        if os.path.exists(temp_dir):
            shutil.rmtree(temp_dir, ignore_errors=True)

def scan(target_type, target):
    print(json.dumps({"progress": 20}))
    sys.stdout.flush()
    
    findings = []
    scores = None
    
    if target_type == 'url':
        if not target.startswith(('http://', 'https://')):
            target = 'https://' + target
            
        print(json.dumps({"progress": 40}))
        sys.stdout.flush()
        
        # Verify URL is reachable first
        start_time = time.time()
        try:
            res = requests.get(target, timeout=5)
            response_time = time.time() - start_time
            html_content = res.text
        except Exception as e:
            raise RuntimeError(f"Failed to connect to target URL '{target}': {str(e)}")
            
        # Check CORS
        check_cors_url(target, findings)
        
        print(json.dumps({"progress": 60}))
        sys.stdout.flush()
        
        # Check Swagger
        check_swagger_url(target, findings)
        
        parser = WebParser()
        parser.feed(html_content)
        
        print(json.dumps({"progress": 80}))
        sys.stdout.flush()
        
        # Check SQLi & CSRF
        check_sqli_csrf_url(target, findings, parser)
        # Check SSRF & IDOR
        check_ssrf_idor_url(target, findings, parser)
        # Check Outdated, Crypto & Deserialization
        check_outdated_crypto_deserialization_url(target, findings, res.headers, html_content, parser, res.cookies)
        # Check Rate Limiting
        check_rate_limiting_url(target, findings)
        
        scores = calculate_scores('url', target, findings, html_content=html_content, headers=res.headers, response_time=response_time)
        
    elif target_type == 'github':
        print(json.dumps({"progress": 50}))
        sys.stdout.flush()
        
        # Verify repository exists and is accessible before scanning
        try:
            check_res = requests.head(target, timeout=5, headers={"User-Agent": "Mozilla/5.0"})
            if check_res.status_code == 404:
                raise ValueError("The GitHub repository does not exist or is private.")
        except Exception as e:
            if "private" in str(e):
                raise
            raise RuntimeError(f"Failed to verify GitHub repository connectivity: {str(e)}")

        findings, scores = scan_github(target)
            
    print(json.dumps({"progress": 100}))
    sys.stdout.flush()
    
    return {
        "status": "success",
        "target": target,
        "mode": "medium",
        "findings": findings,
        "scores": scores
    }
