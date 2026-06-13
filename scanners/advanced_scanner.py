import sys
import json
import time
import re
import os
import shutil
import subprocess
from urllib.parse import urlparse, urljoin
import requests

def check_git_exposure_url(url, findings):
    paths = ["/.git/config", "/.git/HEAD"]
    for path in paths:
        test_url = urljoin(url, path)
        try:
            res = requests.get(test_url, timeout=3)
            if res.status_code == 200:
                body = res.text
                if path == "/.git/config" and ("[core]" in body or "repositoryformatversion" in body):
                    findings.append({
                        "id": "EXPOSED_GIT_FOLDER",
                        "severity": "critical",
                        "title": "Publicly Exposed Git Configuration (.git/config)",
                        "description": f"The version control repository configuration was found publicly accessible at {path}.",
                        "impact": "Attackers can download the entire source code history, branches, configuration files, and committed secrets using tools like git-dumper.",
                        "remediation": "Configure your web server to return a 403 Forbidden or 404 Not Found for any requests starting with /.git, or use CI/CD deployment pipelines that strip version control metadata.",
                        "reference": "https://cwe.mitre.org/data/definitions/538.html"
                    })
                    break
                elif path == "/.git/HEAD" and ("ref: refs/" in body or re.match(r'^[0-9a-f]{40}', body.strip())):
                    findings.append({
                        "id": "EXPOSED_GIT_HEAD",
                        "severity": "critical",
                        "title": "Publicly Exposed Git HEAD Metadata (.git/HEAD)",
                        "description": f"The Git repository HEAD pointer file is publicly accessible at {path}.",
                        "impact": "Exposes active development branch names and commit hashes, allowing repository cloning and structure mapping.",
                        "remediation": "Restrict web server access to hidden metadata directories.",
                        "reference": "https://cwe.mitre.org/data/definitions/538.html"
                    })
                    break
        except Exception:
            pass

def check_debug_actuators_url(url, findings):
    paths = {
        "/actuator/env": ("management.endpoints", "Spring Boot Actuator Environment Endpoint Exposed", "high"),
        "/actuator/heapdump": ("JVM heap dump", "Spring Boot Actuator Heapdump Endpoint Exposed", "critical"),
        "/actuator": ("_links", "Spring Boot Actuator Discovery Page Exposed", "medium"),
        "/phpinfo.php": ("php version", "PHP Info Page Exposed", "medium"),
        "/info.php": ("php version", "PHP Info Page Exposed", "medium"),
        "/_debug/": ("debug", "Interactive Debug UI Exposed", "high")
    }
    
    for path, (signature, title, severity) in paths.items():
        test_url = urljoin(url, path)
        try:
            res = requests.get(test_url, timeout=3)
            if res.status_code == 200:
                body = res.text.lower()
                
                if path == "/actuator/heapdump":
                    ct = res.headers.get('content-type', '').lower()
                    if "octet-stream" in ct:
                        findings.append({
                            "id": "EXPOSED_ACTUATOR_HEAPDUMP",
                            "severity": severity,
                            "title": title,
                            "description": f"Exposed JVM memory snapshot endpoint detected at {path}.",
                            "impact": "Allows attackers to download a full heap dump of the active application memory, leaking active sessions, database connections, and decryption keys.",
                            "remediation": "Secure Spring Actuator endpoints using Spring Security, or disable exposed web endpoints entirely (management.endpoints.web.exposure.exclude=*).",
                            "reference": "https://cwe.mitre.org/data/definitions/530.html"
                        })
                        continue
                
                if signature in body:
                    findings.append({
                        "id": f"EXPOSED_DEBUG_{path.replace('/', '_').strip('_').upper()}",
                        "severity": severity,
                        "title": title,
                        "description": f"Exposed debug interface/actuator endpoint detected at {path}.",
                        "impact": "Exposes server environment variables, system configuration details, loaded classes, or internal variables to remote attackers.",
                        "remediation": "Disable debug mode in production settings and restrict actuator endpoints to private networks or local host bindings.",
                        "reference": "https://cwe.mitre.org/data/definitions/489.html"
                    })
        except Exception:
            pass

def check_clickjacking_url(url, findings):
    try:
        res = requests.get(url, timeout=3)
        headers = {k.lower(): v for k, v in res.headers.items()}
        
        has_xfo = False
        xfo = headers.get('x-frame-options', '').lower()
        if 'deny' in xfo or 'sameorigin' in xfo:
            has_xfo = True
            
        has_csp_fa = False
        csp = headers.get('content-security-policy', '').lower()
        if csp and 'frame-ancestors' in csp:
            has_csp_fa = True
            
        if not has_xfo and not has_csp_fa:
            findings.append({
                "id": "CLICKJACKING_PROTECTION_MISSING",
                "severity": "medium",
                "title": "Clickjacking (UI Redress) Protection Missing",
                "description": f"The website at {url} does not configure X-Frame-Options or Content-Security-Policy with frame-ancestors to restrict framing.",
                "impact": "Malicious websites can embed this site in an iframe, potentially hijacking user interactions (e.g. click hijacking, UI redressing).",
                "remediation": "Set X-Frame-Options header to 'DENY' or 'SAMEORIGIN', or use the 'frame-ancestors' directive in your Content-Security-Policy.",
                "reference": "https://cwe.mitre.org/data/definitions/1021.html"
            })
    except Exception:
        pass

def check_xxe_url(url, findings):
    xml_payload = """<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE test [
  <!ENTITY xxe "XXE_REFLECTED_TEST_PAYLOAD" >
]>
<test>&xxe;</test>"""

    # We send it to common endpoints
    endpoints = [
        url,
        urljoin(url, "/api/xml"),
        urljoin(url, "/xml"),
        urljoin(url, "/api/v1/xml")
    ]
    
    headers = {
        "Content-Type": "application/xml"
    }
    
    for endpoint in endpoints:
        try:
            res = requests.post(endpoint, data=xml_payload, headers=headers, timeout=3)
            if res.status_code in [200, 201] and "XXE_REFLECTED_TEST_PAYLOAD" in res.text:
                findings.append({
                    "id": "XXE_INJECTION_ENABLED",
                    "severity": "high",
                    "title": "XML External Entity (XXE) Injection Enabled",
                    "description": f"The endpoint {endpoint} parsed XML input and reflected the content of a custom entity.",
                    "impact": "Indicates that the XML parser is processing entity declarations, which can be abused to perform local file read, internal port scanning (SSRF), or Denial of Service.",
                    "remediation": "Configure your XML parser to disable external entities (DTDs) and external schema resolutions.",
                    "reference": "https://cwe.mitre.org/data/definitions/611.html"
                })
                break
        except Exception:
            pass

def check_unauthenticated_endpoints_url(url, findings):
    paths = {
        "/api/admin": ["admin", "users", "config", "settings", "role", "system"],
        "/api/v1/users": ["email", "username", "role", "password", "id"],
        "/admin/config": ["db_", "key", "secret", "host", "config", "password"],
        "/admin/settings": ["setting", "config", "enable", "disable"],
        "/config/": ["index of", "config", "database", "settings"],
        "/admin/": ["dashboard", "admin panel", "login", "management", "console"]
    }
    
    for path, keywords in paths.items():
        test_url = urljoin(url, path)
        try:
            res = requests.get(test_url, timeout=3, allow_redirects=False)
            if res.status_code == 200:
                body = res.text.lower()
                matched_keywords = [kw for kw in keywords if kw in body]
                ct = res.headers.get('content-type', '').lower()
                
                is_sensitive = False
                if "application/json" in ct and len(matched_keywords) >= 1:
                    is_sensitive = True
                elif len(matched_keywords) >= 2 and not ("login" in body and "username" in body and "password" in body and "form" in body):
                    is_sensitive = True
                    
                if is_sensitive:
                    findings.append({
                        "id": f"UNAUTHENTICATED_ENDPOINT_{path.replace('/', '_').strip('_').upper()}",
                        "severity": "high",
                        "title": f"Unauthenticated API/Admin Endpoint Exposed: {path}",
                        "description": f"The endpoint {path} was found publicly accessible and returned potentially sensitive data without authentication.",
                        "impact": "Exposes administrative controls, user directories, or system configuration data to unauthenticated remote users.",
                        "remediation": "Implement proper authentication and authorization checks (e.g. JWT verification, session middleware) before exposing this endpoint.",
                        "reference": "https://cwe.mitre.org/data/definitions/306.html"
                    })
        except Exception:
            pass

def check_outdated_software_url(url, findings):
    try:
        res = requests.get(url, timeout=3)
        headers = {k.lower(): v for k, v in res.headers.items()}
        
        server = headers.get('server', '').lower()
        x_powered = headers.get('x-powered-by', '').lower()
        
        old_signatures = [
            (r'apache/1\.', "Apache 1.x (End of Life)", "high"),
            (r'apache/2\.[0-2]\.', "Apache 2.0-2.2 (End of Life / Vulnerable)", "high"),
            (r'php/5\.', "PHP 5.x (End of Life)", "high"),
            (r'php/4\.', "PHP 4.x (End of Life)", "critical"),
            (r'microsoft-iis/[1-7]\.', "IIS 1.0-7.x (Outdated & Vulnerable)", "high"),
            (r'nginx/1\.[0-9]\.', "Nginx <1.10 (Outdated)", "medium")
        ]
        
        for pattern, name, severity in old_signatures:
            if re.search(pattern, server) or re.search(pattern, x_powered):
                findings.append({
                    "id": "OUTDATED_SERVER_SOFTWARE",
                    "severity": severity,
                    "title": f"Outdated Server Software: {name}",
                    "description": f"The server header/powered-by header exposes outdated software: Server: {res.headers.get('Server', '')}, X-Powered-By: {res.headers.get('X-Powered-By', '')}.",
                    "impact": "Exposing outdated software versions allows attackers to look up known CVE exploits for the specific target version.",
                    "remediation": "Disable server version disclosure headers (e.g., ServerTokens Prod in Apache, expose_php = Off in php.ini) and update the server software to the latest stable version.",
                    "reference": "https://cwe.mitre.org/data/definitions/933.html"
                })
                break
    except Exception:
        pass

def scan_github_content(rel_path, content, findings):
    patterns = [
        (r'cp\s+-r\s+\.git\s+', "GIT_EXPOSING_METADATA_SCRIPT", "high", "Script copying .git folder to build output",
         "Copies the entire repository history into the deployable web folders, causing public exposure.",
         "Modify build scripts to exclude the .git directory when packaging assets.", "https://cwe.mitre.org/data/definitions/489.html"),
        
        (r'management\.endpoints\.web\.exposure\.include\s*=\s*([\'"]\*[\'"]|\*|\d)', "GIT_SPRING_ACTUATOR_EXPOSED", "high", "Spring Boot Actuators publicly exposed",
         "Exposes administrative monitoring features (like heapdump or env) to all users.",
         "Restrict web exposure to health and info endpoints: management.endpoints.web.exposure.include=health,info.", "https://cwe.mitre.org/data/definitions/489.html"),
         
        (r'frameguard\s*:\s*false', "GITHUB_CLICKJACKING_HELMET_DISABLED", "medium", "Express Helmet Frameguard Disabled",
         "The application explicitly disables helmet's frameguard middleware, leaving the site unprotected against Clickjacking.",
         "Enable frameguard in helmet: remove frameguard: false or set x-frame-options header manually.", "https://cwe.mitre.org/data/definitions/1021.html"),
         
        (r'X_FRAME_OPTIONS\s*=\s*[\'"]ALLOW-FROM[\'"]', "GITHUB_CLICKJACKING_DJANGO_ALLOW_FROM", "medium", "Django Insecure X-Frame-Options Configuration",
         "The application configures Django's X_FRAME_OPTIONS to ALLOW-FROM, which is obsolete and unsupported in many modern browsers.",
         "Update X_FRAME_OPTIONS to 'DENY' or 'SAMEORIGIN' in Django settings.", "https://cwe.mitre.org/data/definitions/1021.html"),

        (r'resolve_entities\s*=\s*True', "XXE_LXML_RESOLVE_ENTITIES_ENABLED", "high", "LXML XML External Entity Resolution Enabled",
         "The application configures the lxml XML parser to resolve entities, which makes it vulnerable to XXE injection.",
         "Set resolve_entities=False in your XMLParser configuration.", "https://cwe.mitre.org/data/definitions/611.html"),

        (r'DocumentBuilderFactory\s+\w+\s*=\s*DocumentBuilderFactory\.newInstance', "XXE_JAVA_DOCUMENT_BUILDER_FACTORY", "medium", "Java DocumentBuilderFactory potentially vulnerable to XXE",
         "DocumentBuilderFactory is instantiated. If DTD and external entities are not explicitly disabled, this parser is vulnerable to XXE.",
         "Configure DocumentBuilderFactory to disallow DOCTYPE declarations: factory.setFeature(\"http://apache.org/xml/features/disallow-doctype-decl\", true).", "https://cwe.mitre.org/data/definitions/611.html"),

        (r'libxml_disable_entity_loader\s*\(\s*false\s*\)', "XXE_PHP_ENTITY_LOADER_ENABLED", "high", "PHP XML External Entity Loader Enabled",
         "The PHP script explicitly enables the libxml entity loader, which allows resolving external XML entities.",
         "Remove libxml_disable_entity_loader(false) or set it to true to disable resolving external entities.", "https://cwe.mitre.org/data/definitions/611.html"),

        (r'\.\s*(create|update|updateMany|updateOne|findOneAndUpdate|insert|insertMany)\s*\(\s*(?:[^)]*,\s*)?req\.body\s*\)', "GITHUB_MASS_ASSIGNMENT_AUTOBINDING", "medium", "Mass Assignment / Parameter Binding Vulnerability",
         "The application passes the raw request body (req.body) directly into database model updates/creation without filtering allowed fields.",
         "Whitelist allowed fields before passing them to the database model (e.g. update({ email: req.body.email }) or use destructuring).", "https://cwe.mitre.org/data/definitions/915.html"),

        (r'new\s+\w+\s*\(\s*req\.body\s*\)', "GITHUB_MASS_ASSIGNMENT_AUTOBINDING_NEW", "medium", "Mass Assignment / Parameter Binding Vulnerability (Instantiator)",
         "The application passes the raw request body (req.body) directly into a class constructor, potentially autobinding database properties.",
         "Sanitize and restrict the incoming request body object properties before instantiating.", "https://cwe.mitre.org/data/definitions/915.html"),

        (r'router\.(get|post|put|delete)\s*\(\s*[\'"]\/(?:api\/)?(?:admin|settings|config|users)(?:\/[a-zA-Z0-9_:-]+)*[\'"]\s*,\s*(?:async\s*)?(?:\([^)]*\)|[a-zA-Z0-9_]+)\s*=>', "GITHUB_MISSING_AUTH_MIDDLEWARE", "high", "Potentially Unauthenticated Administrative Route",
         "An administrative or sensitive route is declared without apparent intermediate authentication/authorization middleware.",
         "Add authentication and role-based access control middleware (e.g. requireAuth, isAdmin) to the route definition.", "https://cwe.mitre.org/data/definitions/306.html"),

        (r'router\.(get|post|put|delete)\s*\(\s*[\'"]\/(?:api\/)?(?:admin|settings|config|users)(?:\/[a-zA-Z0-9_:-]+)*[\'"]\s*,\s*function\s*\(', "GITHUB_MISSING_AUTH_MIDDLEWARE_FUNC", "high", "Potentially Unauthenticated Administrative Route (Function syntax)",
         "An administrative or sensitive route is declared without apparent intermediate authentication/authorization middleware.",
         "Add authentication and role-based access control middleware (e.g. requireAuth, isAdmin) to the route definition.", "https://cwe.mitre.org/data/definitions/306.html"),

        (r'(?:let|const)\s+(\w+)\s*=\s*await\s+\w+\.(?:findOne|findById)[\s\S]*?\1\.\w+\s*=\s*.*?\1\.\w+[\s\S]*?await\s+\1\.save', "GITHUB_POTENTIAL_RACE_CONDITION", "high", "Potential Race Condition in Database Update",
         "The codebase contains a read-modify-write pattern on a database model without transactions or atomic operations.",
         "Use atomic database operations (e.g., $inc in MongoDB, UPDATE balance = balance + X in SQL) or database transactions/locks to prevent race conditions.", "https://cwe.mitre.org/data/definitions/362.html"),

        (r'FROM\s+(?:ubuntu:14\.04|ubuntu:12\.04|node:8|node:10|node:6|python:2\.7|python:3\.5|debian:8|centos:6)', "GITHUB_OUTDATED_DOCKER_BASE", "high", "Outdated Docker Base Image Used",
         "The Dockerfile uses a severely outdated and end-of-life base image, which likely contains numerous unpatched OS-level vulnerabilities.",
         "Update the FROM instruction in your Dockerfile to use a modern, supported LTS base image (e.g., node:18-alpine, python:3.10-slim, ubuntu:22.04).", "https://cwe.mitre.org/data/definitions/1104.html"),

        (r'"lodash"\s*:\s*["\'](?:\^|~)?(?:[0-3]\.|4\.(?:[0-9]|1[0-6])\.)', "GITHUB_VULNERABLE_LODASH", "high", "Vulnerable Dependency: lodash < 4.17.21",
         "The package.json specifies a version of lodash that is vulnerable to Prototype Pollution (CVE-2020-8203, CVE-2020-28500).",
         "Upgrade lodash dependency to version 4.17.21 or higher.", "https://cwe.mitre.org/data/definitions/1104.html"),

        (r'"axios"\s*:\s*["\'](?:\^|~)?0\.(?:[0-9]|1[0-9]|20|21\.0)\.', "GITHUB_VULNERABLE_AXIOS", "medium", "Vulnerable Dependency: axios < 0.21.1",
         "The package.json specifies a version of axios vulnerable to Server-Side Request Forgery (SSRF) or Denial of Service.",
         "Upgrade axios dependency to version 0.21.1 or higher.", "https://cwe.mitre.org/data/definitions/1104.html")
    ]
    for pattern, fid, severity, title, impact, remediation, ref in patterns:
        match = re.search(pattern, content, re.IGNORECASE)
        if match:
            findings.append({
                "id": fid,
                "severity": severity,
                "title": f"{title} ({rel_path})",
                "description": f"Found signature: '{match.group(0)}' in {rel_path}.",
                "impact": impact,
                "remediation": remediation,
                "reference": ref
            })

def scan_github(target):
    findings = []
    temp_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), "temp_advanced", f"repo_{int(time.time() * 1000)}")
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
    print(json.dumps({"progress": 25}))
    sys.stdout.flush()
    
    findings = []
    
    if target_type == 'url':
        if not target.startswith(('http://', 'https://')):
            target = 'https://' + target
            
        print(json.dumps({"progress": 40}))
        sys.stdout.flush()
        
        # Check Exposed .git files
        check_git_exposure_url(target, findings)
        
        print(json.dumps({"progress": 60}))
        sys.stdout.flush()
        
        # Check Exposed Debug/Actuator endpoints
        check_debug_actuators_url(target, findings)
        
        print(json.dumps({"progress": 80}))
        sys.stdout.flush()
        
        # Check Clickjacking protection
        check_clickjacking_url(target, findings)
        
        # Check XXE Injection
        check_xxe_url(target, findings)
        
        # Check Unauthenticated endpoints
        check_unauthenticated_endpoints_url(target, findings)
        
        # Check Outdated software
        check_outdated_software_url(target, findings)
        
    elif target_type == 'github':
        print(json.dumps({"progress": 50}))
        sys.stdout.flush()
        try:
            findings = scan_github(target)
        except Exception as e:
            findings.append({
                "id": "ADVANCED_GITHUB_SCAN_FAILED",
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
        "mode": "advanced",
        "findings": findings
    }
