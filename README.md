# SiteCheck — Website Security & Privacy Analysis

Built by **Team Obsidian** for the 190-Minute Hackathon.

SiteCheck is an accessible, modern, trustworthy cybersecurity analysis dashboard that inspects websites for security headers, TLS configuration, information disclosure, and privacy hygiene in plain English, complete with copy-paste remediation snippets for Express, Nginx, Django, and Flask.

---

## Features

- **Mandatory Authorization Confirmation**: Validates target HTTP/HTTPS URLs and requires users to confirm the exact normalized hostname before running assessments.
- **Security Score Posture**: Overall radial score gauge (0–100) and category breakdowns across Headers, TLS, Information Exposure, Privacy, and RFC Policies.
- **Severity Summary & Quick Filtering**: Visual badges for High, Medium, and Low severity findings, alongside passed rules.
- **Multi-Framework Remediation**: Instant code fixes for **Express**, **Nginx**, **Django**, and **Flask** with 1-click clipboard copy.
- **Robust Loading & Error Handling**: Duplicate-submission protection, accessible ARIA live regions, and sanitized error cards for invalid URLs, unreachable hosts, rate limits, and server issues.
- **Local Development Server**: Zero external dependencies — runs directly in any browser or served locally on port 3000.

---

## File Structure

```text
├── index.html                   # Semantic HTML5 Application Shell
├── test-runner.html             # Automated In-Browser Verification Test Suite
├── serve.ps1                    # Lightweight Localhost Server (port 3000)
├── README.md                    # Project Documentation
└── src/
    ├── App.js                   # Application Shell & View Orchestrator
    ├── components/
    │   ├── UrlInputForm.js      # URL Validation & Authorization Form
    │   ├── ResultsDashboard.js  # Security Score & Remediation Dashboard
    │   ├── apiClient.js         # Backend Network Integration Client
    │   ├── ErrorNotice.js       # Reusable Cybersecurity Error Cards
    │   └── mockScanData.js      # Illustrative Demo Dataset
    └── styles/
        └── main.css             # Dark Charcoal Cybersecurity Theme
```

---
## How to Run

### Option 1: Unified Fullstack Server (Port 3001)
```powershell
node server/server.js
```
Then navigate to: **[http://localhost:3001](http://localhost:3001)**

### Option 2: Automated Test Suite
Open `test-runner.html` to execute all 63 unit and integration test assertions.

