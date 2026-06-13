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
    finally:
        if os.path.exists(temp_dir):
            shutil.rmtree(temp_dir, ignore_errors=True)
            
    return findings

def scan(target_type, target):
    print(json.dumps({"progress": 20}))
    sys.stdout.flush()
    
    findings = []
    
    if target_type == 'url':
        if not target.startswith(('http://', 'https://')):
            target = 'https://' + target
            
        print(json.dumps({"progress": 40}))
        sys.stdout.flush()
        
        # Check CORS
        check_cors_url(target, findings)
        
        print(json.dumps({"progress": 60}))
        sys.stdout.flush()
        
        # Check Swagger
        check_swagger_url(target, findings)
        
        try:
            res = requests.get(target, timeout=5)
            html_content = res.text
            parser = WebParser()
            parser.feed(html_content)
            
            print(json.dumps({"progress": 80}))
            sys.stdout.flush()
            
            # Check SQLi & CSRF
            check_sqli_csrf_url(target, findings, parser)
        except Exception:
            pass
        
    elif target_type == 'github':
        print(json.dumps({"progress": 50}))
        sys.stdout.flush()
        try:
            findings = scan_github(target)
        except Exception as e:
            findings.append({
                "id": "MEDIUM_GITHUB_SCAN_FAILED",
                "severity": "high",
                "title": "GitHub Scan Failed",
                "description": f"Failed to clone or scan the repository: {str(e)}",
                "impact": "No source code checks could be performed.",
                "remediation": "Verify the GitHub repository is public and accessible.",
                "reference": "https://cwe.mitre.org/data/definitions/30.html"
            })
            
    print(json.dumps({"progress": 100}))
    sys.stdout.flush()
    
    return {
        "status": "success",
        "target": target,
        "mode": "medium",
        "findings": findings
    }
