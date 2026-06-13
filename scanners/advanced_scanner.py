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

def scan_github_content(rel_path, content, findings):
    git_expose_patterns = [
        (r'cp\s+-r\s+\.git\s+', "GIT_EXPOSING_METADATA_SCRIPT", "high", "Script copying .git folder to build output",
         "Copies the entire repository history into the deployable web folders, causing public exposure.",
         "Modify build scripts to exclude the .git directory when packaging assets."),
        (r'management\.endpoints\.web\.exposure\.include\s*=\s*([\'"]\*[\'"]|\*|\d)', "GIT_SPRING_ACTUATOR_EXPOSED", "high", "Spring Boot Actuators publicly exposed",
         "Exposes administrative monitoring features (like heapdump or env) to all users.",
         "Restrict web exposure to health and info endpoints: management.endpoints.web.exposure.include=health,info.")
    ]
    for pattern, fid, severity, title, impact, remediation in git_expose_patterns:
        match = re.search(pattern, content, re.IGNORECASE)
        if match:
            findings.append({
                "id": fid,
                "severity": severity,
                "title": f"{title} ({rel_path})",
                "description": f"Found deployment signature exposing metadata: '{match.group(0)}' in {rel_path}.",
                "impact": impact,
                "remediation": remediation,
                "reference": "https://cwe.mitre.org/data/definitions/489.html"
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
            
        print(json.dumps({"progress": 50}))
        sys.stdout.flush()
        
        # Check Exposed .git files
        check_git_exposure_url(target, findings)
        
        print(json.dumps({"progress": 75}))
        sys.stdout.flush()
        
        # Check Exposed Debug/Actuator endpoints
        check_debug_actuators_url(target, findings)
        
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
