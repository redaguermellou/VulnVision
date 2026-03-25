# VulnVision — User Guide

> **VulnVision** is an AI-powered web security scanning platform. This guide walks you through everything from creating your first target to leveraging the AI assistant for remediation guidance.

---

## Table of Contents

1. [Getting Started](#1-getting-started)
2. [Adding Targets](#2-adding-targets)
3. [Running Scans](#3-running-scans)
4. [Interpreting Results](#4-interpreting-results)
5. [Using the AI Assistant](#5-using-the-ai-assistant)
6. [Generating Reports](#6-generating-reports)

---

## 1. Getting Started

### 1.1 Logging In

Navigate to `https://your-domain.com` (or `http://localhost:8000` in development).

| Field | Value |
|---|---|
| Email | Your registered email address |
| Password | Your account password |

After logging in you land on the **Dashboard** — a live overview of all your targets, scans, and vulnerability counts.

### 1.2 Dashboard Overview

```
┌─────────────────────────────────────────────────────┐
│  🔴 Critical: 3   🟠 High: 12   🟡 Medium: 28      │
│  Targets: 5       Scans: 14     Open Vulns: 43      │
├─────────────────────────────────────────────────────┤
│  Recent Scans          │  Severity Trend Chart       │
│  ─────────────────     │  ──────────────────────     │
│  • api.example.com ✅  │  [bar chart last 30 days]   │
│  • shop.example.com ⏳ │                             │
└─────────────────────────────────────────────────────┘
```

- **Critical / High badges** link directly to the filtered vulnerability list.
- **Severity Trend Chart** shows how your security posture has changed over time.

### 1.3 Your Profile & API Key

Click your avatar (top-right) → **Profile**.

- **API Key** — copy this to authenticate REST API calls with `X-API-Key: <key>`.
- **Change Password** — recommended after first login.
- **Role** — determines your rate limits (Viewer / Analyst / Admin).

---

## 2. Adding Targets

A **Target** is a host, application, or IP range you want to scan.

### 2.1 Create a Target

1. Click **Targets** in the left sidebar.
2. Click **+ New Target** (top-right).
3. Fill in the form:

| Field | Example | Notes |
|---|---|---|
| Name | `Production API` | Human-friendly label |
| Address | `api.example.com` | Domain, IP, or CIDR |
| Type | `web_application` | web_application / network / api |
| Description | `Main REST API` | Optional |

4. Click **Save Target**.

### 2.2 Target Types

| Type | Suitable For | Recommended Scanners |
|---|---|---|
| `web_application` | Web apps, CMS | Nikto, OWASP ZAP |
| `network` | Servers, devices | Nmap |
| `api` | REST / GraphQL APIs | Nikto, custom |

### 2.3 Managing Targets

| Action | How |
|---|---|
| Edit | Target detail → ✏️ Edit |
| Deactivate | Toggle **Active** switch |
| Delete | Target detail → 🗑️ Delete (removes all scan history) |
| View vulnerabilities | Target detail → **Vulnerabilities** tab |

---

## 3. Running Scans

### 3.1 Scan Types

| Scanner | What It Finds | Typical Duration |
|---|---|---|
| **Nmap** | Open ports, services, OS fingerprints | 1–5 min |
| **Nikto** | Web server misconfigurations, CVEs | 3–15 min |
| **Gobuster** | Hidden directories and files | 2–10 min |
| **OWASP ZAP** | OWASP Top-10 vulnerabilities (active + passive) | 10–60 min |

### 3.2 Starting a Scan

1. Navigate to **Scans** → **+ New Scan**.
2. Select the **Target**.
3. Choose one or more **Scan Types**.
4. Configure optional settings (e.g. Gobuster wordlist, Nmap flags).
5. Click **Start Scan**.

The scan card shows a **live progress bar** and phase label (`Initializing → Nmap → Nikto → Finalizing`).

### 3.3 Scan Status Indicators

| Badge | Meaning |
|---|---|
| 🔵 Pending | Queued, waiting for a Celery worker |
| 🟡 Running | Actively scanning |
| 🟢 Completed | Finished — results ready |
| 🔴 Failed | Error during scan — check logs |
| ⚫ Stopped | Manually stopped |

### 3.4 Stopping a Scan

Click **Stop** on the scan card. Active scanner processes are terminated gracefully.

> **Tip:** Scans run as background tasks. You can safely close the browser — results are saved automatically.

### 3.5 OWASP ZAP Scans

OWASP ZAP scans require the ZAP daemon to be running:

```bash
# Start ZAP headless (Docker)
docker run -d -p 8080:8080 zaproxy/zap-stable \
  zap.sh -daemon -host 0.0.0.0 -port 8080 -config api.key=YOUR_ZAP_KEY
```

Set `ZAP_API_KEY` and `ZAP_BASE_URL` in `.env`, then navigate to **Scans → OWASP → New OWASP Scan**.

---

## 4. Interpreting Results

### 4.1 Severity Levels

| Severity | CVSS Range | Typical Examples | Action |
|---|---|---|---|
| 🔴 **Critical** | 9.0 – 10.0 | RCE, SQL injection, auth bypass | Fix immediately |
| 🟠 **High** | 7.0 – 8.9 | XSS, SSRF, privilege escalation | Fix within 24h |
| 🟡 **Medium** | 4.0 – 6.9 | Information disclosure, weak TLS | Fix within 1 week |
| 🔵 **Low** | 0.1 – 3.9 | Missing headers, minor config issues | Fix in next release |
| ⚪ **Info** | 0.0 | Banners, technology fingerprints | Review |

### 4.2 Vulnerability Detail Panel

Click the 👁️ button on any vulnerability row to open the detail panel:

```
┌──────────────────────────────────────────────┐
│  SQL Injection                    🔴 Critical  │
├──────────────────────────────────────────────┤
│  CVE: CVE-2023-12345    CVSS: 9.8             │
│  CWE: CWE-89            Has Exploit: ⚠️ Yes   │
│  Component: /api/users?id=                    │
│  ─────────────────────────────────────────── │
│  NVD Description: ...                         │
│  Evidence:  ' OR '1'='1                       │
│  ─────────────────────────────────────────── │
│  [NVD ↗] [Exploit-DB ↗] [MITRE ↗]           │
│  [🔄 Refresh NVD]  [🤖 AI Guide]             │
└──────────────────────────────────────────────┘
```

- **Refresh NVD** — fetches the latest CVSS score and exploit data from NVD.
- **AI Guide** — generates a step-by-step remediation guide using Gemini AI.

### 4.3 CVSS Badges

| Badge | Score |
|---|---|
| ![Critical](https://img.shields.io/badge/CVSS-9.8-red) | 9.0 – 10.0 |
| ![High](https://img.shields.io/badge/CVSS-7.5-orange) | 7.0 – 8.9 |
| ![Medium](https://img.shields.io/badge/CVSS-5.3-yellow) | 4.0 – 6.9 |
| ![Low](https://img.shields.io/badge/CVSS-2.1-blue) | 0.1 – 3.9 |

### 4.4 Vulnerability Statuses

| Status | Meaning | How to Change |
|---|---|---|
| **Open** | Not yet addressed | Default |
| **In Progress** | Being worked on | Edit vuln → status |
| **Resolved** | Fixed and verified | Click **Resolve** or `PATCH /api/v1/vulnerabilities/{id}/resolve/` |
| **Accepted Risk** | Consciously accepted | Edit vuln → status |
| **False Positive** | Not a real issue | Edit vuln → status |

### 4.5 OWASP ZAP Alerts

OWASP alerts are grouped by **OWASP Category** (e.g. A01 Broken Access Control). Each alert includes:
- **Risk** (High / Medium / Low / Informational)
- **Affected URL** and **Parameter**
- **Solution** from ZAP's knowledge base
- **CWE / WASC** identifiers

---

## 5. Using the AI Assistant

### 5.1 Chat Interface

Navigate to **AI → Assistant**. The assistant is context-aware:

- Pass `?target_id=N` or `?scan_id=N` in the URL to automatically seed the conversation with your target's scan history.
- The assistant knows about recent vulnerabilities and can answer questions like:
  - *"What are the most critical issues in my last scan?"*
  - *"Explain what SQL injection is and how it affects my app."*
  - *"What should I fix first?"*

### 5.2 Suggested Questions

The chat widget displays **suggested questions** based on your current scan data:

> 🤔 Suggested: *"How do I fix the XSS vulnerability in /search?"*  
> 🤔 Suggested: *"Is CVE-2023-12345 actively exploited in the wild?"*

### 5.3 Rate Limits

| Role | AI Queries Per Day |
|---|---|
| Viewer | 10 |
| Analyst | 20 |
| Admin | 200 |

Remaining quota is shown in the chat header. When exceeded, a 429 response is returned with reset time.

### 5.4 AI Remediation Guides

For any vulnerability or OWASP alert, click **🤖 AI Guide** to generate a full remediation guide:

```
📋 Remediation Guide: SQL Injection
────────────────────────────────────
1. Problem Description
2. Impact Analysis
3. Step-by-Step Fix
   ├── PHP example
   ├── Python example
   └── Configuration
4. Verification Steps
5. Prevention Tips

[🖨️ Print] [📥 Download PDF] [🔄 Regenerate]
```

Guides are **cached in the database** and can be regenerated at any time.

### 5.5 Chat History

Navigate to **AI → Chat History** to see all previous sessions. Sessions can be:
- **Resumed** — continue where you left off.
- **Exported** — download as PDF.
- **Deleted** — removes all messages in the session.

---

## 6. Generating Reports

### 6.1 Quick Report

From any **Scan Detail** page, click **Download Report** to get an instant PDF summary.

### 6.2 Report Builder

Navigate to **Scans → Report Builder** for a customisable report:

| Option | Description |
|---|---|
| **Target** | Filter by specific target |
| **Date Range** | Limit to scans between two dates |
| **Severity Filter** | Include only Critical/High/etc. |
| **Include Charts** | Severity distribution pie, trend line |
| **Format** | PDF (default), JSON (via API) |

### 6.3 Weekly Email Reports

Admins can enable **Weekly Security Reports** sent every Monday at 8 AM:

1. Go to **Admin → Settings** (or set `CELERY_BEAT_SCHEDULE` in `.env`).
2. Ensure `EMAIL_HOST` and related settings are configured.
3. Reports include:
   - Executive summary
   - New vulnerabilities this week
   - Resolution progress
   - Top 5 critical findings

### 6.4 API-Based Export

```bash
# Export scan vulnerabilities as JSON
curl -H "X-API-Key: YOUR_API_KEY" \
     "https://your-domain.com/api/v1/scans/42/vulnerabilities/?format=json" \
     -o scan_42_vulns.json

# Export all open critical vulns
curl -H "X-API-Key: YOUR_API_KEY" \
     "https://your-domain.com/api/v1/vulnerabilities/?severity=critical&status=open" \
     -o critical_open.json
```

---

*Next: [Admin Guide](admin_guide.md) | [API Reference](developer_guide.md#api-reference)*
