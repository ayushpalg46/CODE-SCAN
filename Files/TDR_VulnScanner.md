# Technical Design Document (TDR)
## Lightweight Vulnerability Scanner Dashboard

**Version:** 1.0  
**Author:** Ayzen  
**Date:** June 2026  
**Status:** Draft

---

## 1. System Overview

The scanner is a full-stack web application with three layers:

- **Frontend** — React.js (user input, results dashboard)
- **Backend** — Node.js / Express (API server, job orchestration)
- **Scanner Scripts** — Python (the actual security checks)

The backend acts as the orchestrator: it receives the scan request, spawns the Python scanner scripts as child processes, collects results, scores them, and returns a structured JSON report to the frontend.

---

## 2. Tech Stack

| Layer | Technology | Reason |
|-------|-----------|--------|
| Frontend | React.js + Tailwind CSS | Component-based UI, fast iteration |
| Backend | Node.js + Express | Lightweight API server, easy process spawning |
| Scanner scripts | Python 3 | Rich security libraries (requests, safety, etc.) |
| Database | None (v1) | Results returned in-memory, not persisted |
| Deployment | Render (free tier) | Free hosting for both Node and Python |

---

## 3. Architecture

```
Client (React)
     |
     | POST /api/scan { target: "https://..." }
     v
Express API Server (Node.js)
     |
     |-- spawns --> scanner_headers.py
     |-- spawns --> scanner_deps.py
     |-- spawns --> scanner_xss.py
     |
     | collects stdout (JSON) from each script
     v
Risk Engine (Node.js)
     |
     | scores + merges all findings
     v
Response { findings: [...], score: 72, summary: {...} }
     |
     v
Client renders report
```

---

## 4. API Design

### POST `/api/scan`

**Request body:**
```json
{
  "target": "https://example.com",
  "type": "url"
}
```

For GitHub repos:
```json
{
  "target": "https://github.com/username/repo",
  "type": "github"
}
```

**Response:**
```json
{
  "scan_id": "abc123",
  "target": "https://example.com",
  "score": 68,
  "summary": {
    "critical": 1,
    "high": 2,
    "medium": 3,
    "low": 1
  },
  "findings": [
    {
      "id": "HEADER_CSP_MISSING",
      "title": "Content-Security-Policy header missing",
      "severity": "high",
      "description": "The CSP header was not found in the server response.",
      "impact": "Allows inline script execution, enabling XSS attacks.",
      "remediation": "Add Content-Security-Policy to your server response headers.",
      "reference": "https://developer.mozilla.org/en-US/docs/Web/HTTP/CSP"
    }
  ]
}
```

---

## 5. Scanner Modules

### 5.1 Header Scanner (`scanner_headers.py`)

**What it does:**  
Sends an HTTP GET request to the target URL and inspects the response headers.

**Headers checked:**

| Header | Severity if missing |
|--------|-------------------|
| `Content-Security-Policy` | High |
| `X-Frame-Options` | Medium |
| `X-Content-Type-Options` | Medium |
| `Strict-Transport-Security` | High |
| `Referrer-Policy` | Low |
| `Permissions-Policy` | Low |

**Libraries:** `requests`

**Output:** JSON array of findings to stdout

**Example:**
```python
import requests, json, sys

def scan_headers(url):
    findings = []
    res = requests.get(url, timeout=10)
    headers = res.headers

    checks = {
        "Content-Security-Policy": ("HEADER_CSP_MISSING", "high"),
        "X-Frame-Options": ("HEADER_XFO_MISSING", "medium"),
        "Strict-Transport-Security": ("HEADER_HSTS_MISSING", "high"),
        "X-Content-Type-Options": ("HEADER_XCTO_MISSING", "medium"),
    }

    for header, (finding_id, severity) in checks.items():
        if header not in headers:
            findings.append({ "id": finding_id, "severity": severity, "header": header })

    print(json.dumps(findings))

scan_headers(sys.argv[1])
```

---

### 5.2 Dependency Scanner (`scanner_deps.py`)

**What it does:**  
For GitHub repo targets — clones the repo (shallow clone), detects the package manager, and runs a vulnerability audit.

**Supported package managers:**

| File detected | Tool used | Language |
|--------------|-----------|----------|
| `package.json` | `npm audit --json` | Node.js |
| `requirements.txt` | `safety check --json` | Python |
| `Pipfile` | `safety check --json` | Python |

**Libraries:** `subprocess`, `json`, `os`, `git` (via `gitpython`)

**Flow:**
```
1. git clone --depth=1 <repo_url> into /tmp/<scan_id>/
2. Detect package manager from file presence
3. Run appropriate audit tool
4. Parse JSON output
5. Map each vulnerability to internal finding format
6. Clean up /tmp/<scan_id>/
7. Print findings JSON to stdout
```

**Risk mapping from npm audit:**

| npm severity | Internal severity |
|-------------|------------------|
| critical | critical |
| high | high |
| moderate | medium |
| low | low |

---

### 5.3 XSS Scanner (`scanner_xss.py`)

**What it does:**  
Crawls the target URL for HTML forms and input fields. Submits test payloads and checks if the payload is reflected unsanitised in the response body.

**Test payloads (benign — no actual execution):**
```python
PAYLOADS = [
    "<script>xsstest_1</script>",
    '"><img src=x onerror=xsstest_2>',
    "';alert(xsstest_3)//",
]
```

> Note: These payloads contain unique markers (`xsstest_N`), not `alert()` calls. The scanner checks if the marker appears in the response — it never executes JS.

**Detection logic:**
- If the exact payload string appears in the response HTML → reflected XSS finding (High)
- If only the marker string appears but HTML-encoded → potential finding (Medium), manual review suggested

**Libraries:** `requests`, `BeautifulSoup4`

**Limitations (v1):**
- Does not handle JavaScript-rendered forms (no headless browser)
- Does not test URL parameters automatically (v1 tests form fields only)
- Does not follow redirects more than 1 hop

---

## 6. Risk Engine (Node.js)

After all scanner scripts complete, the backend merges results and calculates an overall risk score.

**Scoring weights:**

| Severity | Points per finding |
|----------|------------------|
| Critical | 40 |
| High | 20 |
| Medium | 10 |
| Low | 5 |

**Score calculation:**
```
raw_score = sum of all finding weights
capped_score = min(raw_score, 100)
display_score = 100 - capped_score  // higher = safer
```

A score of 0 = maximum risk. A score of 100 = no issues found.

---

## 7. Frontend (React.js)

### 7.1 Pages / Views

| Route | Component | Purpose |
|-------|-----------|---------|
| `/` | `HomePage` | Input form — URL or GitHub link |
| `/scan/:id` | `ReportPage` | Scan results dashboard |
| `/loading` | `ScanLoading` | Polling state while scan runs |

### 7.2 Key Components

```
<HomePage>
  <ScanInput />         // text field + scan button + type toggle (URL / GitHub)

<ScanLoading>
  <ProgressBar />       // animated, shows estimated progress

<ReportPage>
  <ScoreMeter />        // circular score display (0–100)
  <SeveritySummary />   // count badges: Critical / High / Medium / Low
  <FindingsList />      // list of FindingCard components
    <FindingCard />     // collapsible: title, severity badge, description, fix
```

### 7.3 Severity Badge Colors

```css
.critical { background: #ef4444; color: #fff; }   /* red */
.high     { background: #f97316; color: #fff; }   /* orange */
.medium   { background: #eab308; color: #000; }   /* yellow */
.low      { background: #3b82f6; color: #fff; }   /* blue */
```

### 7.4 Polling Strategy

The frontend polls `GET /api/scan/:id/status` every 2 seconds until status is `complete` or `error`. Max 60 poll attempts before timeout.

---

## 8. Process Spawning (Node.js → Python)

```javascript
const { spawn } = require('child_process');

function runScanner(scriptPath, args) {
  return new Promise((resolve, reject) => {
    const proc = spawn('python3', [scriptPath, ...args]);
    let output = '';

    proc.stdout.on('data', (data) => { output += data.toString(); });
    proc.stderr.on('data', (err) => console.error(err.toString()));
    proc.on('close', (code) => {
      if (code !== 0) return reject(new Error(`Scanner exited with code ${code}`));
      try {
        resolve(JSON.parse(output));
      } catch {
        reject(new Error('Scanner returned invalid JSON'));
      }
    });
  });
}
```

All three scanners run in **parallel** using `Promise.all()` to minimise total scan time.

---

## 9. Error Handling

| Scenario | Behaviour |
|----------|-----------|
| Target URL unreachable | Return error finding: "Target could not be reached" |
| GitHub repo is private | Return error: "Private repos not supported in v1" |
| Python script crashes | Log stderr, skip that module, flag in report |
| Scan exceeds 60s | Timeout, return partial results with warning |
| Invalid URL format | Validate on frontend before submitting |

---

## 10. Security Considerations for the Scanner Itself

- **No storing of scan targets** — v1 is stateless, nothing written to disk beyond /tmp
- **Input sanitisation** — validate URL format strictly before passing to Python scripts
- **Rate limiting** — max 5 scans per IP per hour (add in v1 before public launch)
- **XSS payloads are markers only** — no real attack strings that could trigger WAFs or cause harm to the target
- **Shallow git clones only** — `--depth=1` to avoid pulling full repo history

---

## 11. Folder Structure

```
vuln-scanner/
├── client/                    # React frontend
│   ├── src/
│   │   ├── components/
│   │   │   ├── ScanInput.jsx
│   │   │   ├── FindingCard.jsx
│   │   │   ├── ScoreMeter.jsx
│   │   │   └── SeveritySummary.jsx
│   │   ├── pages/
│   │   │   ├── HomePage.jsx
│   │   │   ├── ScanLoading.jsx
│   │   │   └── ReportPage.jsx
│   │   └── App.jsx
│   └── package.json
│
├── server/                    # Node.js backend
│   ├── routes/
│   │   └── scan.js
│   ├── engine/
│   │   └── riskScorer.js
│   ├── index.js
│   └── package.json
│
├── scanners/                  # Python scanner scripts
│   ├── scanner_headers.py
│   ├── scanner_deps.py
│   ├── scanner_xss.py
│   └── requirements.txt       # requests, beautifulsoup4, safety, gitpython
│
└── README.md
```

---

## 12. Dependencies

### Node.js (server)
```json
{
  "express": "^4.18.0",
  "cors": "^2.8.5",
  "uuid": "^9.0.0"
}
```

### Python (scanners)
```
requests>=2.31.0
beautifulsoup4>=4.12.0
safety>=2.3.0
gitpython>=3.1.0
```

### React (client)
```json
{
  "react": "^18.0.0",
  "react-router-dom": "^6.0.0",
  "axios": "^1.4.0",
  "tailwindcss": "^3.0.0"
}
```

---

## 13. Build & Run (Local Dev)

```bash
# 1. Start backend
cd server && npm install && node index.js

# 2. Install Python deps
cd scanners && pip install -r requirements.txt

# 3. Start frontend
cd client && npm install && npm run dev
```

Backend runs on `localhost:5000`, frontend on `localhost:5173`.

---

## 14. Known Limitations (v1)

- XSS scanner only tests static HTML forms — JavaScript-rendered forms (React, Vue apps) are not covered
- Dependency scanner requires the repo to be public
- No persistent storage — scan results lost on page refresh
- Header scanner sends one GET request only — does not follow subdomains or subpages
- No HTTPS certificate validation issues are checked (planned for v2)
