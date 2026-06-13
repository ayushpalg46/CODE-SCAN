# Product Requirements Document (PRD)
## Lightweight Vulnerability Scanner Dashboard

**Version:** 1.0  
**Author:** Ayzen  
**Date:** June 2026  
**Status:** Draft

---

## 1. Overview

### 1.1 Problem Statement

Developers — especially students and early-career engineers — routinely push web projects without performing even basic security checks. They don't run dependency audits, don't configure HTTP security headers, and don't test input fields for injection vulnerabilities. The result: publicly accessible projects with glaring, well-known security holes that could be caught automatically in minutes.

There is no simple, free, zero-setup tool that lets a developer paste a URL or GitHub repo link and immediately get a readable, actionable security report.

### 1.2 Solution

A web-based vulnerability scanner dashboard. The user inputs a URL or GitHub repository link. The backend runs three automated security checks. The frontend displays a clean, color-coded risk report classifying findings by severity.

No installation. No configuration. Paste and scan.

### 1.3 Goals

- Detect the most common, highest-impact security misconfigurations automatically
- Present findings in a report that a non-security developer can understand and act on
- Deliver scan results within a reasonable time (under 60 seconds for most targets)
- Be free to use, with no account required for basic scans

### 1.4 Non-Goals

- This is not a full penetration testing suite
- It will not perform authenticated scans (no login session support in v1)
- It will not scan mobile apps, binaries, or databases
- It will not auto-fix vulnerabilities — report only

---

## 2. Target Users

### Primary User
**The student developer / junior engineer**  
- Building and deploying personal or hackathon projects
- Has basic knowledge of web development but limited security awareness
- Does not use professional security tooling (Burp Suite, Nessus, etc.)
- Wants fast, readable feedback — not raw CVE dumps

### Secondary User
**The CS/IT educator**  
- Wants a live demo tool to show students what real misconfigurations look like
- Could use this in a classroom or workshop setting

---

## 3. Features

### 3.1 Core Features (v1 — Must Have)

| # | Feature | Description |
|---|---------|-------------|
| F1 | URL input | User pastes a target URL into a text field and triggers a scan |
| F2 | GitHub repo input | User pastes a GitHub repo URL; backend clones and scans dependencies |
| F3 | Dependency vulnerability check | Detects outdated packages with known CVEs |
| F4 | HTTP security header analysis | Checks for missing or misconfigured security headers |
| F5 | Basic XSS probe | Sends test payloads to detected input fields and checks for unsafe reflection |
| F6 | Risk classification | Each finding is classified as Low / Medium / High / Critical |
| F7 | Scan report UI | Clean dashboard view showing all findings, grouped by severity |
| F8 | Finding detail | Each finding includes: what it is, why it matters, how to fix it |

### 3.2 Stretch Features (v2 — Nice to Have)

- Shareable scan report via unique URL
- Re-scan button to verify if a fix was applied
- Scan history (requires user account)
- PDF export of report
- Slack/Discord webhook notification on scan complete

---

## 4. User Flow

```
1. User lands on homepage
2. User enters a URL or GitHub repo link
3. User clicks "Scan"
4. Loading state shown — scan in progress
5. Results page renders with:
   - Overall risk score (0–100)
   - Summary bar: X Critical, X High, X Medium, X Low
   - Finding cards grouped by severity
   - Each card: title, description, remediation advice
6. User can expand each finding for more detail
```

---

## 5. Risk Classification System

| Level | Color | Meaning |
|-------|-------|---------|
| Critical | Red | Actively exploitable, immediate action required |
| High | Orange | Serious misconfiguration, fix before deployment |
| Medium | Yellow | Notable weakness, fix when possible |
| Low | Blue/Grey | Minor issue, best practice recommendation |

---

## 6. Constraints

- Free-tier infrastructure only (Render, Railway, or similar)
- No paid third-party security APIs
- Must work without a user account for basic scans
- Scan must complete within 60 seconds for a typical public URL

---

## 7. Success Metrics

- A scan of a test URL with 3 known misconfigurations correctly identifies all 3
- Report renders correctly on desktop and mobile
- End-to-end scan (input → results) completes in under 60 seconds
- Each finding includes a remediation suggestion

---

## 8. Out of Scope for v1

- Authentication / user accounts
- Rate limiting and abuse protection (add in v2)
- Scanning behind login walls
- CI/CD pipeline integration
- OWASP Top 10 full coverage
