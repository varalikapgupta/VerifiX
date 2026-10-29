
# VerifiX 
### Detect. Understand. Patch Safely. Verify.

**VerifiX** is a developer-focused application security prototype designed to connect static vulnerability detection, contextual security analysis, controlled sandbox remediation, runtime testing, and audit logging in one workflow.

Rather than treating a vulnerability finding as the final result, VerifiX aims to help developers move from identifying potentially unsafe code to testing whether a proposed fix works.

---

## 🚀 Key Features

- **Static Security Analysis:** Scans Python source code for supported security patterns.
- **Contextual Vulnerability Triage:** Enriches findings with hypotheses, reasoning, confidence information, and recommended security probes where supported.
- **Developer-Focused UI:** A React-based interface for submitting code and inspecting security findings.
- **Sandbox-Based Patching:** Supports the `PY002` patch rule through a temporary copy of the target file.
- **Syntax Validation:** Checks patched Python source for syntax errors before it is considered ready for further testing.
- **Security Probes:** Includes local probes for testing selected security behaviors.
- **Audit Logging:** Uses an append-only, hash-chained log to help verify the integrity of recorded events.

> **Security principle:** Applying a patch is not the same as verifying remediation. Relevant security probes and regression tests must still be run.

## 🧩 How It Works

```text
        Python Source Code
                |
                v
        Static Security Scan
                |
                v
       Structured Findings
                |
                v
    Contextual Vulnerability Triage
                |
                v
     Recommended Security Probes
                |
                v
       Sandbox-Based Patching
                |
                v
     Syntax + Runtime Validation
                |
                v
         Audit Evidence
```

The workflow illustrates the intended product architecture. Some stages require separate execution or further integration; runtime verification is not implied by a successful static scan or patch operation.

## 🏗️ Technology Stack

| Component | Technology |
|---|---|
| Frontend | React, Vite, JavaScript, CSS |
| Backend API | Python, FastAPI |
| Request validation | Pydantic |
| Static analysis | Python AST-based scanning |
| Security testing | Python probes and pytest |
| Remediation | Custom sandbox patcher |
| Auditability | SHA-256 hash-chained audit log |
| Version control | Git and GitHub |

## 📁 Project Structure

```text
dualbyte-t2-03/
├── backend/
│   ├── main.py
│   ├── static_scanner.py
│   ├── claude_reasoning.py
│   ├── probes.py
│   ├── sandbox_patcher.py
│   ├── audit_logger.py
│   ├── vulnerable_app.py
│   ├── demo_storage/
│   └── tests/
├── frontend/
│   ├── src/
│   │   ├── api/
│   │   ├── components/
│   │   ├── shaders/
│   │   ├── data/
│   │   ├── App.jsx
│   │   ├── index.css
│   │   └── main.jsx
│   ├── index.html
│   ├── package.json
│   └── vite.config.js
├── .gitignore
└── README.md
```

## ⚙️ Getting Started

### Prerequisites

- Python 3.10 or newer, compatible with the project's dependencies
- Node.js and npm
- Git

### 1. Clone the repository

```bash
git clone https://github.com/varalikapgupta/Verifix.git
cd Verifix
```

### 2. Set up the backend

From the repository root, create and activate a virtual environment.

**Windows PowerShell:**

```powershell
python -m venv backend/.venv
.\backend\.venv\Scripts\Activate.ps1
pip install -r backend/requirements.txt
```

If the repository does not contain `backend/requirements.txt`, install the dependencies listed in the project's actual dependency configuration instead.

Start the API:

```powershell
python -m uvicorn backend.main:app --host 127.0.0.1 --port 8000
```

The API documentation is available at:

`http://127.0.0.1:8000/docs`

Health check:

`http://127.0.0.1:8000/health`

### 3. Set up the frontend

Open another terminal:

```powershell
cd frontend
npm install
npm run dev
```

Open the local URL printed by Vite, typically:

`http://localhost:5173`

The frontend API configuration must point to the running backend. Check `frontend/src/api/client.js` and configure the appropriate backend URL for your environment.

### 4. Run the backend tests

From the repository root, after installing the project's test dependencies:

```powershell
python -m pytest -q
```

## 🔬 Security Demonstration

VerifiX includes a deliberately vulnerable local demo application for illustrating path traversal behavior.

The demo exposes file-access functionality through:

```text
GET /files?name=sample.txt
```

A traversal test uses a payload such as:

```text
GET /files?name=../demo_secret.txt
```

In previously observed local testing:

- The original demo returned the isolated demonstration marker for the traversal payload.
- A patched sandbox copy returned `404 File not found` for that payload.
- Normal sample-file access continued to return HTTP 200 in the patched copy.

These observations apply to the specific test payload and demo fixture. They do not prove that every path traversal attack is prevented.

The project also contains demo surfaces for object-level authorization and SQL injection testing. Coverage and remediation support depend on the relevant implementation and tests.

## 🧪 Testing and Validation

A previously observed backend test run reported:

- **247 passed**
- **28 skipped**
- **1 warning**

The frontend production build has also succeeded in a previous run.

These are historical development results and should be rechecked against the latest committed code.

The patch API has required additional debugging. Confirm its current behavior before treating sandbox patching as a fully validated end-to-end workflow.

## 🔌 API Endpoints

| Method | Endpoint | Purpose |
|---|---|---|
| GET | `/` | Project identity and backend status |
| GET | `/health` | Health check |
| POST | `/scan` | Scan the configured target file |
| POST | `/analyze` | Analyze submitted Python source |
| POST | `/patch` | Request an approved sandbox patch |

Request schemas and response details can be inspected through the FastAPI documentation at `/docs` when the backend is running.

## 🔐 Security and Limitations

VerifiX is a security prototype under active development.

- Static findings may include false positives and do not independently establish exploitability.
- Submitted source analysis is designed not to execute the submitted code.
- The patcher currently supports a limited rule set, including `PY002`.
- Runtime probes and regression tests must be performed separately.
- Hash-chained audit logs help detect certain forms of record modification but do not guarantee complete system security.
- Production deployment requires appropriate CORS restrictions, authentication and authorization where needed, secret management, rate limiting, and sandbox isolation.

Use the demo application only in an isolated local environment or another explicitly authorized test environment.

## 🛣️ Roadmap

- [ ] Complete and validate the patch API integration.
- [ ] Expand supported security rules and remediation patterns.
- [ ] Improve automated security-probe integration.
- [ ] Display clear remediation-verification status in the UI.
- [ ] Strengthen regression testing and sandbox cleanup.
- [ ] Improve production deployment and security configuration.
- [ ] Expand reporting and audit evidence.

## 🎯 Project Goal

VerifiX aims to make security findings more actionable by connecting detection, contextual reasoning, controlled remediation, behavioral testing, and auditable evidence.

**A suggested fix is only a candidate fix until testing demonstrates that the vulnerable behavior is blocked and expected functionality still works.**

---

*VerifiX — An application security project developed as part of a hackathon.*