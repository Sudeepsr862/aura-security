# AURA — Browser AI Guard & Extension Setup Guide

## Overview

**AURA — Browser AI Guard** is a Chrome Manifest V3 browser extension and security dashboard designed to protect sensitive organizational data across **multiple configurable browser-based AI tools** — including cloud AI services (OpenAI ChatGPT, Anthropic Claude, Google Gemini, Microsoft Copilot, Cohere, Groq, Mistral, DeepSeek, Hugging Face) and local-model web interfaces (Ollama, LM Studio, vLLM, Text Generation WebUI, LocalAI).

---

## 1. Prerequisites & Starting the Services

### Backend & Dashboard
1. Ensure Node.js (v18+) is installed.
2. From the repository root (`c:\hackthon`), start the backend server and web dashboard:
   ```bash
   # Terminal 1: Start the backend API server (port 3001)
   npm run dev:server

   # Terminal 2: Start the frontend Vite dashboard (port 5174)
   npm run dev
   ```
3. Open your browser and navigate to:
   **Dashboard:** `http://localhost:5174/`  
   **Extension Guard Tab:** `http://localhost:5174/` -> Select **"Browser AI Guard"** from the left navigation.

---

## 2. Reference Datasets Placement

The 5 reference CSV datasets are stored under the read-only directory `sources/`:
- `sources/dataset_a_employees.csv` — Employee records, device trust, approved AI services, policy context.
- `sources/dataset_b_ai_usage_logs.csv` — Historical AI service activity and inspection categories.
- `sources/dataset_c_company_assets.csv` — Data classifications and permitted destinations.
- `sources/dataset_d_network_logs.csv` — Sample network events and traffic volume details.
- `sources/dataset_e_security_incidents.csv` — Historical incident severity, explanation, and outcomes.

> [!NOTE]
> **Setup Note:** If running on a new machine without pre-seeded databases, ensure the 5 CSV files are copied into the `sources/` folder. AURA automatically indexes and joins these files primarily on `employee_id` during server startup. The original CSV files are treated as **read-only reference material** and are never modified or overwritten.

---

## 3. Loading the Chrome Extension (Manifest V3)

1. Open Google Chrome (or any Chromium browser such as Edge, Brave).
2. In the URL address bar, enter: `chrome://extensions/`
3. In the top-right corner, toggle on **"Developer mode"**.
4. In the top-left corner, click the **"Load unpacked"** button.
5. In the file picker dialog, navigate to and select the `c:\hackthon\extension` directory:
   ```
   c:\hackthon\extension
   ```
6. The extension **"AURA — Browser AI Guard" (v1.0.0)** will appear in your extensions list.
7. Click the Extension icon in Chrome's toolbar to open the popup:
   - Displays current domain protection status (Protected / Inactive / Unsupported).
   - Provides quick links to the **AURA Dashboard**, **Extension Options & Catalog**, and the **AI Test Sandbox**.

---

## 4. Supported AI Sites Catalog

AURA includes a pre-configured catalog of popular AI services and local-model web interfaces:

| Service Name | Default Domain | Category | Adapter Type | Status |
| :--- | :--- | :--- | :--- | :--- |
| **OpenAI ChatGPT** | `chatgpt.com` | Cloud | Site Adapter (`chatgpt`) | Protected |
| **OpenAI Legacy** | `chat.openai.com` | Cloud | Site Adapter (`chatgpt`) | Protected |
| **Anthropic Claude** | `claude.ai` | Cloud | Site Adapter (`claude`) | Protected |
| **Google Gemini** | `gemini.google.com` | Cloud | Generic | Protected |
| **Google AI Studio** | `aistudio.google.com` | Cloud | Generic | Protected |
| **Microsoft Copilot** | `copilot.microsoft.com`| Cloud | Generic | Protected |
| **Cohere Coral** | `coral.cohere.com` | Cloud | Generic | Protected |
| **Groq Cloud Console** | `groq.com` | Cloud | Generic | Protected |
| **Mistral Le Chat** | `chat.mistral.ai` | Cloud | Generic | Protected |
| **DeepSeek Chat** | `chat.deepseek.com` | Cloud | Generic | Protected |
| **Hugging Face Chat**| `huggingface.co` | Cloud | Generic | Protected |
| **Ollama Local** | `localhost:11434` | Local | Local WebUI | Protected |
| **LM Studio Local** | `localhost:1234` | Local | Local WebUI | Protected |
| **vLLM Local Server** | `localhost:8000` | Local | Local WebUI | Protected |
| **TextGen WebUI** | `localhost:7860` | Local | Local WebUI | Protected |
| **LocalAI Server** | `localhost:8080` | Local | Local WebUI | Protected |
| **AURA Test Sandbox**| `localhost:5174` | Custom | Generic | Protected |

### Adding Custom AI Domains
Administrators can easily add new internal or cloud AI domains:
- Go to the **AI Service Catalog** tab in the AURA Dashboard (`http://localhost:5174/`).
- Fill in the **Add AI Website Domain** form (Service Name, Domain e.g., `ai.corp.internal`, Category, and Adapter).
- Click **"Add to Catalog"**.

---

## 5. Pre-Transfer Detection & Policy Rules

The extension checks inputs **locally in-memory before sending**:

### Detection Categories:
1. **API Keys & Cloud Tokens:**
   - OpenAI (`sk-[a-zA-Z0-9_-]{20,}`), Anthropic (`sk-ant-[a-zA-Z0-9_-]{20,}`), GitHub (`ghp_[a-zA-Z0-9]{20,}`), AWS Access Keys (`AKIA[0-9A-Z]{16}`), Slack tokens (`xox[baprs]-[0-9a-zA-Z]{10,}`).
2. **Private Cryptographic Keys:**
   - Headers: `-----BEGIN (RSA|EC|OPENSSH|DSA|PRIVATE) KEY-----`.
3. **Database & Connection URIs:**
   - `postgres://...`, `mongodb://...`, `mysql://...`, `redis://...`.
4. **Hardcoded Passwords & Auth Tokens:**
   - Assignments: `password = "..."`, `db_password: "..."`, `api_token = "..."`.
5. **Personal Identifiers & Payment Cards:**
   - Valid 16-digit credit card numbers validated via the **Luhn Algorithm**.
   - Standard SSN patterns (`\b\d{3}-\d{2}-\d{4}\b`).
6. **Confidential Business Data:**
   - Classifications matching Dataset C company assets: `CONFIDENTIAL`, `RESTRICTED`, `STRICTLY CONFIDENTIAL`, `DO NOT DISTRIBUTE`, `PROJECT TITAN`, `Q3-FINANCIAL-FORECAST`.
7. **Infrastructure & Shell Scripts:**
   - Dangerous commands: `curl ... | bash`, `rm -rf /`, `wget ... | sh`.

### File Upload Inspection:
- Detects file selections on file input controls (`<input type="file">`).
- Locally reads text content for `.txt` and `.csv` files via HTML5 `FileReader`.
- Applies the rule engine to file contents **before** upload initiates.

---

## 6. Privacy & Safety Architecture

> [!IMPORTANT]
> **Strict Privacy Guarantee:**
> - Content is inspected **entirely in memory** inside the user's browser tab.
> - **Zero prompt text, zero file contents, and zero secret values** are ever transmitted to the server or written to disk.
> - In-page warning modals explicitly redact sensitive strings (showing category and matched rule, e.g., *"OpenAI Secret Key (sk-...) pattern detected"*).
> - Live telemetry sent to the dashboard contains **metadata only**: timestamp, employee ID, AI service, domain, detected category, matched rule, risk level, and action taken (`blocked` / `warned`).

---

## 7. Interactive Demo Walkthrough

### Test A: Harmless Message (Baseline)
1. Open the **AURA Test Sandbox** tab on `http://localhost:5174/` (or open `chatgpt.com` / `claude.ai` if you have an account).
2. In the message composer, type:
   ```text
   Can you help me summarize our team sprint meeting notes from yesterday?
   ```
3. Press **Enter** or click the **Send** button.
4. **Result:** The message is allowed and submitted normally without interruption.

### Test B: Pre-Transfer Block of Sensitive Secret
1. In the same message composer, enter:
   ```text
   Please debug this database configuration for our production database:
   DATABASE_URL=postgres://prod_admin:superSecretP@ssword2026@db.corp.internal:5432/main
   OPENAI_API_KEY=sk-proj-9A8b7C6d5E4f3G2h1J0kLmNoPqRsTuVwXyZ123456789
   ```
2. Press **Enter** or click **Send**.
3. **Result:** 
   - The submission is **immediately halted**.
   - An in-page warning modal appears:
     > **AURA Data Protection Guard**  
     > **Submission Blocked:** Sensitive Data Detected  
     > **Category:** API Keys & Access Tokens  
     > **Matched Policy Rule:** OpenAI Secret Key (sk-...) pattern detected  
     > **Risk Level:** CRITICAL  
     > *Raw secret values and prompt text are never transmitted or stored.*
   - Buttons provided: **"Cancel & Edit"** or **"Request Policy Review"**.
   - The sensitive text is **not** transmitted to the AI service.

### Test C: Sensitive File Upload Inspection (.txt / .csv)
1. In the AURA Sandbox or supported AI site, click the attachment button.
2. Select a `.txt` or `.csv` file containing sensitive project terms (e.g., containing `CONFIDENTIAL: PROJECT TITAN ARCHITECTURE`).
3. **Result:** The upload is stopped, the file input is reset, and the warning modal explains the violation before the file leaves the device.

### Test D: Review Workflow in the AURA Dashboard
1. Switch to the **AURA Dashboard** (`http://localhost:5174/`) -> **Browser AI Guard**.
2. Notice the event is now recorded under **Live Extension Interception Events**:
   - Tagged with the bright green **LIVE EXTENSION** badge.
   - Shows: Time, Employee ID, AI Service (`OpenAI ChatGPT`), Category (`API Keys`), Matched Rule, Action (`BLOCKED`), Risk (`CRITICAL`).
   - Notice that the **raw secret and prompt text are completely absent**.
3. Click **"Review"** in the table row:
   - Select **"Investigate"**, **"Expected"**, or **"Policy exception"**.
   - Enter an analyst note (e.g., *"Confirmed developer testing against sandbox environment; credentials rotated."*).
   - Click **"Save Review Decision"**.
   - The status updates dynamically in the compliance table.

### Test E: Visual Separation between Live Events and CSV Datasets
1. Click the **"Historical Sample Activity (CSV Datasets)"** tab.
2. Note the clear visual banner and table structure:
   - Every historical row is tagged with a distinct gray **DATASET SAMPLE** badge.
   - Rows are joined on `employee_id` with employee trust, job role, and department context from `dataset_a_employees.csv`.
   - Distinct from the real-time **LIVE EXTENSION** events feed.

---

## 8. Permissions & Scope Boundaries

### Browser Permissions Explained:
- `activeTab`: Used to inspect the active DOM composer when interacting with configured AI tools.
- `storage`: Saves user preferences and catalog status locally in Chrome.
- `optional_host_permissions`: Access is restricted strictly to configured AI site hostnames (`*://*.chatgpt.com/*`, `*://*.claude.ai/*`, `*://localhost/*`, etc.).

### Limitations & Boundaries:
1. **Browser Scope:** This extension operates strictly within supported web browser tabs where permissions are granted. It does **not** inspect desktop native apps, command-line interfaces, or raw network sockets.
2. **Interface Changes:** Each AI site uses unique, frequently updated DOM architectures. If a provider alters their composer DOM classes, the extension marks the site status as `unsupported` or `changed` until the adapter is updated.
3. **File Types:** Prioritizes `.txt` and `.csv` inspection. Complex binary formats (PDF, DOCX) require backend parsing pipelines or client-side web assembly modules.
4. **Explainable Rule Engine:** Operates via transparent, deterministic regex and checksum rules; does not claim universal coverage or guarantee detection of all proprietary text formats.
