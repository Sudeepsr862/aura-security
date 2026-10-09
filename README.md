# AURA — AI Usage Risk & Assurance

AURA is an enterprise-grade AI security and governance platform designed to safeguard organizations against confidential data leaks, shadow AI adoption, and unauthorized usage across 27+ external generative AI platforms.

AURA operates with a **strict privacy-first architecture**: file inspection, prompt parsing, and pattern detection occur entirely in-memory with zero persistence of raw sensitive text, prompt contents, or secret tokens.

---

## Key Features

### 1. Browser AI Guard (Manifest V3 Extension)
- **In-Memory Pre-Transfer Interception:** Intercepts prompt submissions, pastes, and file uploads across ChatGPT, Claude, Gemini, Copilot, Perplexity, DeepSeek, HuggingFace, and 20+ other AI destinations.
- **Client-Side Sensitive Data Inspection:** Detects API keys (AWS, Stripe, OpenAI, GitHub), credentials, PII (SSN, credit cards), and restricted company assets before data leaves the browser.
- **Interactive Warning & Review Dialog:** Provides users with a non-intrusive warning overlay allowing immediate cancellation, redaction, or compliance escalation.
- **Dynamic Proxy Gateway Support:** Configurable API base endpoint via extension options supporting custom forward and reverse proxy setups.

### 2. Data Guard & File Inspector
- **Pre-Transfer File Analysis:** In-memory inspection of source files, documents, and CSVs against defined data-sharing policies.
- **Configurable Data-Sharing Policies:** Flexible rules defining which data classifications (Confidential, Internal, Restricted) are permitted for specific AI destinations.
- **Repeated Attempts Tracking:** Automated tracking and flagging of repeated policy violations per user and service with objective, neutral compliance terminology.
- **Simplified Audit Log:** Streamlined view of inspection history with tamper-evident SHA-256 hash chaining.

### 3. Explainable Risk Intelligence Engine
- **Deterministic Transparent Scoring:** Clear, auditable 0–100 risk scoring model based on:
  - Destination approval status (Approved vs. Unapproved vs. Needs Review).
  - Employee authorization and synthetic identity correlation.
  - Data classification labels and detected sensitive pattern categories.
  - Transfer volume anomaly thresholds (>5 MB).
- **Zero Black Box:** Every risk factor and point contribution is explicitly displayed to security analysts.

### 4. Incident Response & Policy Controls
- **Lifecycle Management:** Triage high and critical risk events through an active workflow (`Open` → `Investigating` → `Resolved` → `False Positive`).
- **Analyst Audit Notes:** Append timestamped investigation findings with analyst attribution.
- **Administrator Policy Settings:** Granular adjustment of risk thresholds, volume triggers, and scoring weights.

### 5. Proxy & Enterprise Compatibility
- **Reverse Proxy Ready:** Express backend configured with `trust proxy` enabled to correctly handle headers (`X-Forwarded-For`, `X-Forwarded-Proto`, `X-Forwarded-Host`) behind Nginx, Envoy, Cloudflare, Traefik, or AWS ALB.
- **Dual-Mode Authentication:** Supports both `HttpOnly` cookies and `Authorization: Bearer <token>` headers, ensuring reliable operation across proxy environments where cookies may be restricted.
- **Extension Proxy Configuration:** Options page allows configuring custom API gateway and proxy endpoints.

---

## Architecture

```
┌────────────────────────────────────────────────────────┐
│                   AURA Security System                 │
├──────────────────────────┬─────────────────────────────┤
│   Browser AI Guard       │   Web Management Console    │
│   (Manifest V3 Ext)      │   (React + TypeScript)      │
│   • Content Script Intercept│• Overview & Real-Time KPIs│
│   • In-Memory Inspection │   • Outbound File Inspector │
│   • Warning/Block Overlay│   • Data-Sharing Policies   │
│   • Proxy Gateway Config │   • Incident Investigation  │
└────────────┬─────────────┴──────────────┬──────────────┘
             │                            │
             ▼                            ▼
┌────────────────────────────────────────────────────────┐
│           AURA Backend API Gateway (Express)           │
│   • Trust Proxy & CORS enabled                         │
│   • Dual-Mode Auth (Cookies & Bearer Tokens)           │
│   • Deterministic Risk Engine                          │
│   • Tamper-Evident SHA-256 Hash Chain                  │
│   • SQLite Enterprise Database                         │
└────────────────────────────────────────────────────────┘
```

---

## Getting Started

### Prerequisites
- Node.js 18+
- npm or yarn

### Installation
```bash
git clone https://github.com/Sudeepsr862/aura-security.git
cd aura-security
npm install
```

### Running Locally
Run both the frontend and backend development servers concurrently:
```bash
# Terminal 1: Backend Server (Port 3001)
npm run server

# Terminal 2: Web Console (Port 5174 / 5173)
npm run dev
```

Visit the application in your browser at `http://localhost:5174/`.

### Running Tests
Execute the comprehensive automated test suite (9 test suites covering scanner, risk engine, incidents, APIs, and extension endpoints):
```bash
npm test
```

### Building for Production
```bash
# Build frontend web bundle
npm run build

# Compile backend TypeScript
npm run build:server
```

---

## Installing the Browser Extension
1. Open Google Chrome or any Chromium-based browser (Edge, Brave).
2. Navigate to `chrome://extensions/`.
3. Enable **Developer mode** in the top-right corner.
4. Click **Load unpacked** and select the [`extension/`](extension) folder from this repository.
5. Click on the extension icon to view active protection status or open **Options** to configure a custom API gateway or proxy URL.

---

## Privacy & Security Guarantees
- **Zero Raw Secret / Prompt Storage:** Raw prompts, pasted text, and confidential file contents are never stored in the database or written to disk.
- **Client & In-Memory Only:** Inspection occurs instantaneously in volatile memory; only high-level metadata (timestamp, detected category, destination domain, risk score) is recorded for auditing.
- **Cryptographic Hash Chaining:** Audit log entries are linked with SHA-256 hashes to ensure tamper-evidence.

---

## License
MIT
