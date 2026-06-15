import sys
import json
import time
import socket
import re
import os
import shutil
import subprocess
from urllib.parse import urlparse, urljoin
import concurrent.futures
from html.parser import HTMLParser
import requests

class WebParser(HTMLParser):
    def __init__(self):
        super().__init__()
        self.forms = []
        self.current_form = None
        self.s3_urls = []
        self.links = []

    def handle_starttag(self, tag, attrs):
        attrs_dict = dict(attrs)
        
        # Capture S3 URLs and other links
        for attr, val in attrs:
            if attr in ['src', 'href', 'action']:
                if 's3.amazonaws.com' in val or '.s3' in val:
                    self.s3_urls.append(val)
                if attr in ['href', 'src']:
                    self.links.append(val)

        if tag == 'form':
            self.current_form = {
                'action': attrs_dict.get('action', ''),
                'method': attrs_dict.get('method', 'get').lower(),
                'inputs': []
            }
            self.forms.append(self.current_form)
        elif tag == 'input' and self.current_form is not None:
            input_type = attrs_dict.get('type', 'text').lower()
            name = attrs_dict.get('name')
            if name:
                self.current_form['inputs'].append({
                    'name': name,
                    'type': input_type,
                    'value': attrs_dict.get('value', '')
                })

    def handle_endtag(self, tag):
        if tag == 'form':
            self.current_form = None

def check_headers(headers, findings):
    checks = {
        "Content-Security-Policy": ("HEADER_CSP_MISSING", "high", "Content-Security-Policy header missing", 
                                    "The CSP header was not found in the server response.", 
                                    "Allows inline script execution, enabling XSS attacks.", 
                                    "Add Content-Security-Policy to your server response headers."),
        "X-Frame-Options": ("HEADER_XFO_MISSING", "medium", "X-Frame-Options header missing", 
                            "The X-Frame-Options header was not found.", 
                            "Exposes the site to clickjacking attacks.", 
                            "Configure the web server to send X-Frame-Options: DENY or SAMEORIGIN."),
        "X-Content-Type-Options": ("HEADER_XCTO_MISSING", "medium", "X-Content-Type-Options header missing", 
                                   "The X-Content-Type-Options header is missing.", 
                                   "Allows MIME-type sniffing, which can lead to code execution.", 
                                   "Set X-Content-Type-Options: nosniff on all responses."),
        "Strict-Transport-Security": ("HEADER_HSTS_MISSING", "high", "Strict-Transport-Security header missing", 
                                      "HTTP Strict Transport Security (HSTS) is not enabled.", 
                                      "Exposes users to man-in-the-middle attacks over HTTP.", 
                                      "Configure HSTS (Strict-Transport-Security: max-age=31536000; includeSubDomains)."),
        "Referrer-Policy": ("HEADER_RP_MISSING", "low", "Referrer-Policy header missing", 
                            "The Referrer-Policy header is missing.", 
                            "May leak sensitive URL parameters to third-party sites via referer header.", 
                            "Implement a Referrer-Policy header like Referrer-Policy: no-referrer-when-downgrade."),
        "Permissions-Policy": ("HEADER_PP_MISSING", "low", "Permissions-Policy header missing", 
                               "The Permissions-Policy header is missing.", 
                               "Allows unrestricted browser feature permissions (e.g. camera, geolocation).", 
                               "Set Permissions-Policy header to restrict unused browser features.")
    }
    for header, info in checks.items():
        if header.lower() not in [h.lower() for h in headers.keys()]:
            findings.append({
                "id": info[0],
                "severity": info[1],
                "title": info[2],
                "description": info[3],
                "impact": info[4],
                "remediation": info[5],
                "reference": "https://owasp.org/www-project-secure-headers/"
            })

def check_http_transport(url, findings):
    parsed = urlparse(url)
    if parsed.scheme == 'http':
        findings.append({
            "id": "UNENCRYPTED_TRANSPORT_HTTP",
            "severity": "high",
            "title": "Unencrypted Transport (HTTP) Used",
            "description": "The target website uses HTTP instead of HTTPS.",
            "impact": "Data transmitted in plaintext can be intercepted or modified by attackers.",
            "remediation": "Deploy a TLS certificate and redirect all HTTP traffic to HTTPS.",
            "reference": "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Strict-Transport-Security"
        })
    else:
        http_url = url.replace("https://", "http://")
        try:
            res = requests.get(http_url, timeout=3, allow_redirects=False)
            if res.status_code in [301, 302, 307, 308]:
                location = res.headers.get('Location', '')
                if not location.startswith("https"):
                    findings.append({
                        "id": "HTTP_REDIRECT_MISSING",
                        "severity": "medium",
                        "title": "HTTP to HTTPS Redirection Insecure",
                        "description": "The server redirects HTTP but not securely to HTTPS.",
                        "impact": "Users might accidentally connect via HTTP, risking credentials interception.",
                        "remediation": "Configure your web server to return a 301 redirect to HTTPS for all HTTP requests.",
                        "reference": "https://owasp.org/www-project-top-ten/2021/A05_2021-Security_Misconfiguration"
                    })
            else:
                findings.append({
                    "id": "HTTP_REDIRECT_MISSING",
                    "severity": "medium",
                    "title": "HTTP to HTTPS Redirection Missing",
                    "description": "The server does not enforce redirection from HTTP to HTTPS.",
                    "impact": "Users might connect via HTTP without encryption, risking interception.",
                    "remediation": "Configure your web server to return a 301 redirect to HTTPS for all HTTP requests.",
                    "reference": "https://owasp.org/www-project-top-ten/2021/A05_2021-Security_Misconfiguration"
                })
        except Exception:
            pass

def check_verbose_errors(url, findings):
    bad_url = urljoin(url, "/non_existent_path_vulnerability_test_12345")
    error_patterns = [
        r"stack\s*trace", r"traceback", r"line\s+\d+", r"exception\s+in", 
        r"fatal\s+error", r"warning:", r"syntaxerror", r"database\s+error",
        r"sql\s+syntax", r"at\s+Express\.", r"django\.views\.debug", 
        r"ignition\.laravel", r"phpinfo"
    ]
    try:
        res = requests.get(bad_url, timeout=3)
        content = res.text.lower()
        matched = []
        for pattern in error_patterns:
            if re.search(pattern, content):
                matched.append(pattern)
        if matched:
            findings.append({
                "id": "VERBOSE_ERROR_MESSAGES",
                "severity": "medium",
                "title": "Verbose Error Messages / Stack Traces Enabled",
                "description": f"The application leaked debug details or stack traces on a 404 response. Matched: {', '.join(matched)}",
                "impact": "Exposes stack trace patterns, library versions, and internal file paths to attackers.",
                "remediation": "Configure the web application to display generic, user-friendly error pages in production.",
                "reference": "https://cwe.mitre.org/data/definitions/209.html"
            })
    except Exception:
        pass

def check_directory_listing(url, findings):
    common_dirs = ["/images/", "/uploads/", "/assets/", "/static/", "/admin/", "/css/", "/js/"]
    for d in common_dirs:
        test_url = urljoin(url, d)
        try:
            res = requests.get(test_url, timeout=3)
            content = res.text.lower()
            if res.status_code == 200 and any(kw in content for kw in ["index of", "parent directory", "autoindex", "directory listing"]):
                findings.append({
                    "id": "DIRECTORY_LISTING_ENABLED",
                    "severity": "medium",
                    "title": f"Web Server Directory Listing Enabled on {d}",
                    "description": f"Requesting {d} returned an interactive folder contents listing.",
                    "impact": "Enables attackers to browse and download sensitive files, config assets, and uploads.",
                    "remediation": "Disable directory indexes in your web server config (e.g. Apache 'Options -Indexes', Nginx 'autoindex off;').",
                    "reference": "https://cwe.mitre.org/data/definitions/548.html"
                })
                break
        except Exception:
            pass

def check_backup_files(url, findings):
    backup_paths = ["/backup.zip", "/db.sql", "/.env", "/index.php.bak", "/config.php.old", "/dump.sql", "/project.tar.gz"]
    for path_suffix in backup_paths:
        test_url = urljoin(url, path_suffix)
        try:
            res = requests.get(test_url, timeout=3, stream=True)
            if res.status_code == 200:
                content_type = res.headers.get('content-type', '').lower()
                
                if path_suffix == "/.env":
                    content_preview = res.raw.read(100).decode('utf-8', errors='ignore')
                    if "=" in content_preview or "DB_" in content_preview or "PORT=" in content_preview:
                        findings.append({
                            "id": "EXPOSED_ENV_FILE",
                            "severity": "critical",
                            "title": "Exposed Environment Variable (.env) File",
                            "description": "An environment configuration file (.env) was found exposed in the web root.",
                            "impact": "Exposes sensitive credentials (database passwords, API keys, mail tokens) to the public.",
                            "remediation": "Move the .env file outside of the web document root and block access in server configuration files.",
                            "reference": "https://cwe.mitre.org/data/definitions/538.html"
                        })
                        continue
                
                if "zip" in content_type or "tar" in content_type or "octet-stream" in content_type or "sql" in content_type or path_suffix.endswith(('.sql', '.bak', '.old')):
                    findings.append({
                        "id": "BACKUP_FILE_EXPOSED",
                        "severity": "high",
                        "title": f"Backup or Archive File Exposed: {path_suffix}",
                        "description": f"Found a backup/archive file at {path_suffix} with content type {content_type}.",
                        "impact": "Allows download of source code archives, configuration backups, or raw database dumps.",
                        "remediation": "Remove backup and archive files from public directories immediately. Keep backups in separate, secure folders.",
                        "reference": "https://cwe.mitre.org/data/definitions/530.html"
                    })
        except Exception:
            pass

def scan_port(host, port):
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(1.5)
        res = s.connect_ex((host, port))
        s.close()
        return port, res == 0
    except Exception:
        return port, False

def check_ports_and_services(url, findings):
    parsed = urlparse(url)
    host = parsed.hostname
    if not host:
        return
    
    ports_to_scan = [21, 22, 23, 25, 110, 143, 3306, 27017, 6379, 9200]
    open_ports = {}
    
    with concurrent.futures.ThreadPoolExecutor(max_workers=10) as executor:
        future_to_port = {executor.submit(scan_port, host, p): p for p in ports_to_scan}
        for future in concurrent.futures.as_completed(future_to_port):
            try:
                port, is_open = future.result()
                if is_open:
                    open_ports[port] = True
            except Exception:
                pass

    if 21 in open_ports or 23 in open_ports:
        findings.append({
            "id": "LEGACY_UNSECURE_SERVICES",
            "severity": "medium",
            "title": "Legacy / Unsecure Service Ports Exposed",
            "description": f"Found open unsecure administrative ports: {', '.join([str(p) for p in [21, 23] if p in open_ports])}.",
            "impact": "Exposes administrative login services like FTP or Telnet which transmit credentials in plaintext.",
            "remediation": "Disable FTP and Telnet. Use SFTP and SSH (port 22) instead. Enforce firewalls to restrict public access.",
            "reference": "https://cwe.mitre.org/data/definitions/319.html"
        })

    # Redis Check
    if 6379 in open_ports:
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(1.5)
            s.connect((host, 6379))
            s.sendall(b"PING\r\n")
            response = s.recv(1024)
            s.close()
            if b"+PONG" in response:
                findings.append({
                    "id": "UNSECURED_REDIS_DATABASE",
                    "severity": "critical",
                    "title": "Unsecured Redis Database (No Authentication)",
                    "description": "The Redis database on port 6379 responded to PING without authentication.",
                    "impact": "Attackers can read, modify, or flush the database contents completely.",
                    "remediation": "Configure Redis to require a strong password (requirepass option) and bind strictly to localhost.",
                    "reference": "https://cwe.mitre.org/data/definitions/306.html"
                })
            else:
                findings.append({
                    "id": "EXPOSED_REDIS_PORT",
                    "severity": "medium",
                    "title": "Exposed Redis Database Port",
                    "description": "The Redis port (6379) is open to the public internet, though password protected.",
                    "impact": "Exposes database to brute-force connection attacks and resource exhaustion.",
                    "remediation": "Configure Redis to bind strictly to internal interfaces (127.0.0.1) and block external port access via firewall.",
                    "reference": "https://cwe.mitre.org/data/definitions/668.html"
                })
        except Exception:
            pass

    # MongoDB Check
    if 27017 in open_ports:
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(1.5)
            s.connect((host, 27017))
            payload = b'\x3b\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00\x00\xd4\x07\x00\x00\x00\x00\x00\x00admin.$cmd\x00\x00\x00\x00\x00\xff\xff\xff\xff\x13\x00\x00\x00\x10isMaster\x00\x01\x00\x00\x00\x00'
            s.sendall(payload)
            resp = s.recv(1024)
            s.close()
            if b"ismaster" in resp.lower() or b"ok" in resp.lower():
                findings.append({
                    "id": "UNSECURED_MONGODB_DATABASE",
                    "severity": "critical",
                    "title": "Unsecured MongoDB Database (No Authentication)",
                    "description": "The MongoDB database on port 27017 accepted commands without authentication.",
                    "impact": "Attackers can dump, overwrite, or delete all database collections.",
                    "remediation": "Enable MongoDB access control (security.authorization: enabled) and bind to localhost.",
                    "reference": "https://cwe.mitre.org/data/definitions/306.html"
                })
            else:
                findings.append({
                    "id": "EXPOSED_MONGODB_PORT",
                    "severity": "medium",
                    "title": "Exposed MongoDB Database Port",
                    "description": "MongoDB port 27017 is open to the public internet.",
                    "impact": "Vulnerable to denial-of-service, remote exploits, and credential brute-forcing.",
                    "remediation": "Restrict port 27017 using a firewall and bind MongoDB to 127.0.0.1.",
                    "reference": "https://cwe.mitre.org/data/definitions/668.html"
                })
        except Exception:
            pass

    # Elasticsearch Check
    if 9200 in open_ports:
        try:
            res = requests.get(f"http://{host}:9200/", timeout=2)
            if res.status_code == 200 and "tagline" in res.text:
                findings.append({
                    "id": "UNSECURED_ELASTICSEARCH_DB",
                    "severity": "critical",
                    "title": "Unsecured Elasticsearch Cluster",
                    "description": "Elasticsearch REST API on port 9200 is open without authentication.",
                    "impact": "Allows anyone to read cluster state, retrieve all indexes, and delete indexes.",
                    "remediation": "Enable security features (xpack.security.enabled: true) and restrict access behind firewall.",
                    "reference": "https://cwe.mitre.org/data/definitions/306.html"
                })
        except Exception:
            pass

    # MySQL Check
    if 3306 in open_ports:
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(1.5)
            s.connect((host, 3306))
            handshake = s.recv(1024)
            s.close()
            if len(handshake) > 4 and (handshake[4] == 10 or b"mysql" in handshake.lower() or b"mariadb" in handshake.lower()):
                findings.append({
                    "id": "EXPOSED_MYSQL_PORT",
                    "severity": "medium",
                    "title": "Exposed MySQL Database Port",
                    "description": "MySQL database service is listening publicly on port 3306.",
                    "impact": "Allows attackers to execute brute-force password guessing attacks on database accounts.",
                    "remediation": "Bind MySQL to 127.0.0.1 and block port 3306 in host firewall.",
                    "reference": "https://cwe.mitre.org/data/definitions/668.html"
                })
        except Exception:
            pass

def check_xss(url, findings, html_content, parser):
    xss_payload = "<script>xsstest_1</script>"
    test_url = url
    parsed = urlparse(url)
    
    if parsed.query:
        params = []
        for param in parsed.query.split('&'):
            if '=' in param:
                k, v = param.split('=', 1)
                params.append(f"{k}={xss_payload}")
            else:
                params.append(param)
        test_url = url.split('?')[0] + "?" + "&".join(params)
    else:
        test_url = urljoin(url, f"?q={xss_payload}&search={xss_payload}")
        
    try:
        res = requests.get(test_url, timeout=3)
        if xss_payload in res.text:
            findings.append({
                "id": "REFLECTED_XSS_QUERY",
                "severity": "high",
                "title": "Reflected Cross-Site Scripting (XSS) via Query",
                "description": f"Query parameters injected with '{xss_payload}' were reflected unsanitized in response.",
                "impact": "Attackers can execute arbitrary JavaScript in the victim's session, stealing cookies and session tokens.",
                "remediation": "Sanitize and HTML-encode all user input before rendering it in the HTML body.",
                "reference": "https://owasp.org/www-community/attacks/xss/"
            })
            return
    except Exception:
        pass

    for form in parser.forms:
        action = form.get('action', '')
        method = form.get('method', 'get')
        inputs = form.get('inputs', [])
        
        if not inputs:
            continue
            
        submit_data = {}
        for inp in inputs:
            if inp['type'] in ['text', 'search', 'email', 'url']:
                submit_data[inp['name']] = xss_payload
            else:
                submit_data[inp['name']] = inp['value']
                
        target_action = urljoin(url, action)
        try:
            if method == 'post':
                res = requests.post(target_action, data=submit_data, timeout=3)
            else:
                res = requests.get(target_action, params=submit_data, timeout=3)
                
            if xss_payload in res.text:
                findings.append({
                    "id": "REFLECTED_XSS_FORM",
                    "severity": "high",
                    "title": "Reflected Cross-Site Scripting (XSS) in Form Field",
                    "description": f"Form at {action} reflects the test payload '{xss_payload}' unsanitized in response.",
                    "impact": "Allows attackers to run client-side script payloads in the browser context of the user.",
                    "remediation": "Apply context-aware output encoding (HTML, Javascript, CSS) when rendering inputs.",
                    "reference": "https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html"
                })
                break
        except Exception:
            pass

def check_open_redirect(url, findings):
    evil_site = "http://example-evil.com"
    redirect_params = ["redirect", "url", "next", "to", "return", "target", "dest", "destination"]
    
    for param in redirect_params:
        test_url = urljoin(url, f"?{param}={evil_site}")
        try:
            res = requests.get(test_url, timeout=3, allow_redirects=False)
            if res.status_code in [301, 302, 307, 308]:
                location = res.headers.get('Location', '')
                if evil_site in location or location.startswith("example-evil.com"):
                    findings.append({
                        "id": "OPEN_REDIRECT",
                        "severity": "medium",
                        "title": "Open Redirect Vulnerability",
                        "description": f"The query parameter '{param}' allowed redirection to '{evil_site}'.",
                        "impact": "Attackers can construct phishing campaigns that redirect trusted site users to malicious domains.",
                        "remediation": "Implement an allowlist of permitted redirect hosts, or use local paths (e.g. starting with '/') only.",
                        "reference": "https://cheatsheetseries.owasp.org/cheatsheets/Unvalidated_Redirects_and_Forwards_Prevention_Cheat_Sheet.html"
                    })
                    break
        except Exception:
            pass

def check_s3_buckets(findings, s3_urls):
    buckets_tested = set()
    for url in s3_urls:
        bucket_name = None
        match1 = re.search(r'https?://([^.]+)\.s3\.amazonaws\.com', url)
        if match1:
            bucket_name = match1.group(1)
        else:
            match2 = re.search(r'https?://s3\.amazonaws\.com/([^/]+)', url)
            if match2:
                bucket_name = match2.group(1)
                
        if bucket_name and bucket_name not in buckets_tested:
            buckets_tested.add(bucket_name)
            bucket_url = f"https://{bucket_name}.s3.amazonaws.com"
            try:
                res = requests.get(bucket_url, timeout=3)
                if res.status_code == 200 and "<ListBucketResult>" in res.text:
                    findings.append({
                        "id": "PUBLIC_S3_BUCKET_LISTING",
                        "severity": "critical",
                        "title": f"Public S3 Bucket Exposed: '{bucket_name}'",
                        "description": f"The S3 bucket '{bucket_name}' allows public file indexing.",
                        "impact": "Public users can list and download files stored in this bucket.",
                        "remediation": "Enable 'Block Public Access' on the S3 bucket and review bucket policies.",
                        "reference": "https://aws.amazon.com/premiumsupport/knowledge-center/s3-block-public-access/"
                      })
            except Exception:
                pass

def scan_file_content(rel_path, content, findings):
    cred_patterns = [
        (r'(password|pass|passwd|pwd)\s*=\s*[\'"](admin|root|123456|1111|password|secret)[\'"]', "DEFAULT_CREDENTIALS_IN_CODE", "high", "Hardcoded Default/Weak Credentials in Source Code", "Exposes system accounts to automated brute forcing and immediate compromise.", "Remove hardcoded passwords from source code and use environment variables."),
        (r'AWS_SECRET_ACCESS_KEY\s*=\s*[\'"][A-Za-z0-9+/=]{40}[\'"]', "AWS_SECRET_KEY_EXPOSED", "critical", "Committed AWS Secret Access Key", "Allows full programmatic access to AWS account assets.", "Revoke the exposed key immediately and inject secrets dynamically."),
        (r'mongodb://[^:]+:[^@]+@', "MONGO_CONN_EXPOSED", "high", "Hardcoded MongoDB Credentials", "Exposes database access credentials in version control.", "Use environment variables for database connection strings.")
    ]
    for pattern, fid, severity, title, impact, remediation in cred_patterns:
        match = re.search(pattern, content, re.IGNORECASE)
        if match:
            findings.append({
                "id": fid,
                "severity": severity,
                "title": f"{title} ({rel_path})",
                "description": f"Found sensitive secret pattern matching: '{match.group(0)}' in {rel_path}.",
                "impact": impact,
                "remediation": remediation,
                "reference": "https://owasp.org/www-community/Source_Code_Analysis_Tools"
            })

    s3_pattern = r'https?://([^.]+)\.s3\.amazonaws\.com'
    match_s3 = re.search(s3_pattern, content)
    if match_s3:
        findings.append({
            "id": "GIT_S3_BUCKET_URL",
            "severity": "medium",
            "title": f"Hardcoded S3 Bucket URL in {rel_path}",
            "description": f"Found S3 bucket reference: '{match_s3.group(0)}'.",
            "impact": "Exposes bucket namespace to attackers for enumeration and potential data theft.",
            "remediation": "Restrict S3 bucket permissions and avoid exposing bucket name strings unnecessarily.",
            "reference": "https://cwe.mitre.org/data/definitions/668.html"
        })

    bind_pattern = r'bind\s*=\s*[\'"]?0\.0\.0\.0[\'"]?'
    if "bind" in content.lower() and re.search(bind_pattern, content):
        findings.append({
            "id": "DATABASE_WILDCARD_BIND",
            "severity": "high",
            "title": f"Wildcard Interface Binding (0.0.0.0) in {rel_path}",
            "description": "Found network binding configuration to listen on all interfaces (0.0.0.0).",
            "impact": "Allows database services to accept connections from external public IP addresses.",
            "remediation": "Bind services to loopback interface (127.0.0.1) or internal subnet IP.",
            "reference": "https://cwe.mitre.org/data/definitions/668.html"
        })

    if rel_path.endswith(('nginx.conf', 'httpd.conf', '.htaccess', 'apache2.conf')):
        if "autoindex on" in content or "options +indexes" in content.lower() or "options indexes" in content.lower():
            findings.append({
                "id": "DIRECTORY_LISTING_ENABLED_CONFIG",
                "severity": "medium",
                "title": f"Directory Listing Enabled in Server Config ({rel_path})",
                "description": "Found active configuration option enabling web directory listing.",
                "impact": "Allows users to index and download raw directory folders.",
                "remediation": "Set 'autoindex off' or 'Options -Indexes' in the server config.",
                "reference": "https://cwe.mitre.org/data/definitions/548.html"
            })

    debug_patterns = [
        (r'DEBUG\s*=\s*True', "django/python"),
        (r'APP_DEBUG\s*=\s*true', "laravel/php"),
        (r'display_errors\s*=\s*On', "php"),
        (r'error_reporting\(E_ALL\)', "php")
    ]
    for pattern, platform in debug_patterns:
        if re.search(pattern, content):
            findings.append({
                "id": "DEBUG_MODE_ENABLED_GIT",
                "severity": "high",
                "title": f"Debug Mode Enabled in {rel_path}",
                "description": f"Found debug configuration '{pattern}' active in code.",
                "impact": "Exposes stack traces and sensitive database parameters on error screens.",
                "remediation": "Disable debug mode in production configurations (e.g. set DEBUG = False).",
                "reference": "https://cwe.mitre.org/data/definitions/489.html"
            })

    if rel_path == "package.json":
        if "express" in content and "helmet" not in content:
            findings.append({
                "id": "EXPRESS_HELMET_MISSING",
                "severity": "medium",
                "title": "Express Helmet Middleware Missing",
                "description": "An Express application was detected, but 'helmet' is not listed in package.json dependencies.",
                "impact": "The application lacks basic HTTP security headers, making it vulnerable to XSS and framing.",
                "remediation": "Install helmet (`npm install helmet`) and load it: `app.use(helmet())`.",
                "reference": "https://helmetjs.github.io/"
            })

    if rel_path.endswith(('Dockerfile', 'docker-compose.yml')):
        expose_match = re.search(r'EXPOSE\s+(21|23|25|110|143)', content, re.IGNORECASE)
        if expose_match:
            findings.append({
                "id": "UNNECESSARY_PORT_EXPOSED_DOCKER",
                "severity": "medium",
                "title": f"Legacy/Unsecure Port Exposed in Docker ({rel_path})",
                "description": f"Exposes unsecure service port {expose_match.group(1)}.",
                "impact": "Containers running unsecure services expose the system to traffic interception.",
                "remediation": "Remove EXPOSE instructions for legacy ports (like FTP 21 or Telnet 23) in Docker configs.",
                "reference": "https://cwe.mitre.org/data/definitions/658.html"
            })

    xss_patterns = [
        (r'dangerouslySetInnerHTML\s*:', "React dangerouslySetInnerHTML"),
        (r'\.html\s*\(', "jQuery html method"),
        (r'v-html\s*=', "Vue v-html directive"),
        (r'innerHTML\s*=', "Vanilla JS innerHTML"),
        (r'document\.write\s*\(', "JS document.write")
    ]
    for pattern, tech in xss_patterns:
        match = re.search(pattern, content)
        if match:
            findings.append({
                "id": "POTENTIAL_DOM_XSS",
                "severity": "medium",
                "title": f"Potential XSS Sink used in {rel_path}",
                "description": f"Found raw HTML rendering pattern '{match.group(0)}' ({tech}).",
                "impact": "If user input flows into this function without escaping, it leads to Cross-Site Scripting.",
                "remediation": "Ensure all inputs are safely escaped, or use framework-native safe bindings (e.g. innerText / textContent).",
                "reference": "https://owasp.org/www-community/attacks/xss/"
            })

    redirect_pattern = r'(res\.redirect|redirect|HttpResponseRedirect)\s*\(\s*req\.(query|params)\.'
    if re.search(redirect_pattern, content):
        findings.append({
            "id": "POTENTIAL_OPEN_REDIRECT",
            "severity": "high",
            "title": f"Unvalidated Input Redirect in {rel_path}",
            "description": "Found a redirect function sourcing redirect destination directly from request input.",
            "impact": "Exposes users to open redirection vulnerability and phishing scams.",
            "remediation": "Validate the redirect destination against a safe domains list before redirecting.",
            "reference": "https://cwe.mitre.org/data/definitions/601.html"
        })

    if "session" in content.lower() and "cookie" in content.lower():
        if "secure" in content.lower() and re.search(r'secure\s*:\s*false', content, re.IGNORECASE):
            findings.append({
                "id": "INSECURE_SESSION_COOKIE",
                "severity": "medium",
                "title": f"Insecure Session Cookie Configuration in {rel_path}",
                "description": "Found session cookie configured with 'secure: false'.",
                "impact": "Cookies sent over HTTP (unencrypted) can be intercepted on shared networks.",
                "remediation": "Configure cookies with 'secure: true' to ensure they are only transmitted over HTTPS.",
                "reference": "https://cwe.mitre.org/data/definitions/614.html"
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
    temp_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), "temp", f"repo_{int(time.time() * 1000)}")
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
                
                if filename.endswith(('.zip', '.sql', '.bak', '.old', '.tar.gz', '.tar', '.rar', '.db')):
                    if any(pub_folder in root.lower().replace('\\', '/') for pub_folder in ['public', 'static', 'www', 'assets', 'dist']):
                        findings.append({
                            "id": "GIT_EXPOSED_BACKUP",
                            "severity": "high",
                            "title": f"Backup File inside Public Folder: {rel_path}",
                            "description": f"A backup file '{filename}' was found in a public directory.",
                            "impact": "Exposes code archives or database files to download if the public folder is served as static web root.",
                            "remediation": "Remove backup files from source tree, or move them out of public static folders.",
                            "reference": "https://cwe.mitre.org/data/definitions/530.html"
                        })
                
                if filename.endswith(('.png', '.jpg', '.jpeg', '.gif', '.ico', '.pdf', '.woff', '.woff2', '.ttf', '.eot', '.mp3', '.mp4', '.zip', '.gz')):
                    continue
                    
                try:
                    with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
                        content = f.read()
                    scan_file_content(rel_path, content, findings)
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
        
        check_http_transport(target, findings)
        
        start_time = time.time()
        try:
            res = requests.get(target, timeout=5)
            response_time = time.time() - start_time
            headers = res.headers
            html_content = res.text
        except Exception as e:
            raise RuntimeError(f"Failed to connect to target URL '{target}': {str(e)}")
            
        parser = WebParser()
        parser.feed(html_content)
        
        print(json.dumps({"progress": 60}))
        sys.stdout.flush()
        
        check_headers(headers, findings)
        check_verbose_errors(target, findings)
        check_directory_listing(target, findings)
        check_backup_files(target, findings)
        check_xss(target, findings, html_content, parser)
        check_open_redirect(target, findings)
        check_s3_buckets(findings, parser.s3_urls)
        
        scores = calculate_scores('url', target, findings, html_content=html_content, headers=headers, response_time=response_time)
        
        print(json.dumps({"progress": 80}))
        sys.stdout.flush()
        
        check_ports_and_services(target, findings)
        
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
        "mode": "basic",
        "findings": findings,
        "scores": scores
    }
