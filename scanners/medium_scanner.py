import sys
import json
import time

def scan(target_type, target):
    # Print initial progress
    print(json.dumps({"progress": 30}))
    sys.stdout.flush()
    time.sleep(1)
    
    print(json.dumps({"progress": 60}))
    sys.stdout.flush()
    time.sleep(1)

    return {
        "status": "success",
        "target": target,
        "mode": "medium",
        "findings": [
            {
                "id": "MEDIUM_STUB_CHECK",
                "title": "Medium Scan Stub Check",
                "severity": "medium",
                "description": "Medium level scanning is configured. Deep codebase checks are pending implementation details.",
                "impact": "Code audit and dependency analysis for intermediate risks are not fully active.",
                "remediation": "No action needed. Placeholder verification successful.",
                "reference": "https://owasp.org"
            }
        ]
    }
