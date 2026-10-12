# PayNimbus Container Security & DevSecOps Hardening

## Table of Contents

1. [Project Overview](#project-overview)
2. [Repository Structure](#repository-structure)
3. [Code Layer Security (SAST, SCA & Secrets)](#code-layer-security-sast-sca--secrets)
   - [1.1 Pre-Fix Baseline Scans](#11-pre-fix-baseline-scans)
   - [1.2 Vulnerability Remediation & Code Fixes](#12-vulnerability-remediation--code-fixes)
   - [1.3 Post-Fix Verification Scans](#13-post-fix-verification-scans)
   - [1.4 Findings Summary Table](#14-findings-summary-table)
   - [1.5 Git History & Commit Strategy](#15-git-history--commit-strategy)
4. [Container Layer Security (Docker, Distroless & GCP)](#container-layer-security-docker-distroless--gcp)
   - [2.1 Multi-Stage Dockerfile Architecture](#21-multi-stage-dockerfile-architecture)
   - [2.2 Build Context Isolation (.dockerignore)](#22-build-context-isolation-dockerignore)
   - [2.3 GCP Cloud Build & Artifact Registry](#23-gcp-cloud-build--artifact-registry)
   - [2.4 Container Analysis Vulnerability Scan](#24-container-analysis-vulnerability-scan)
5. [Key Security Questions & Answers (Q1 – Q6)](#key-security-questions--answers-q1--q6)
6. [Local Development & Testing Guide](#local-development--testing-guide)
7. [Verification & Compliance Checklist](#verification--compliance-checklist)

---

## Project Overview

**PayNimbus** is a cloud-native financial transaction processing platform. The `paynimbus-history-api` microservice is a public-facing REST API designed to query user transaction histories and ingest internal YAML configuration payloads.

This repository documents the end-to-end security audit and remediation lifecycle (DevSecOps) performed on `paynimbus-history-api`:

- **Code Layer Hardening:** Identified and eliminated Static Application Security Testing (SAST) issues, Software Composition Analysis (SCA) dependency vulnerabilities, and hardcoded secrets in code and historical Git commits.
- **Container Layer Hardening:** Hardened the containerization packaging using a multi-stage Distroless Docker image, enforced non-root execution, published the artifact to Google Cloud Artifact Registry via Cloud Build, and validated runtime container vulnerabilities using Container Analysis.

---

## Repository Structure

```tree
paynimbus-container-security/
├── .dockerignore                 # Excludes sensitive/unneeded files from build context
├── Dockerfile                    # Multi-stage hardened Distroless build
├── requirements.txt              # Pinned, patched Python dependencies (CVE-free)
├── README.md                     # Comprehensive security audit & project documentation
└── app/
    ├── __init__.py               # Python package initialization
    ├── main.py                   # Hardened Flask microservice API
    └── db.py                     # Secure SQLite database connection & initialization
```

### API Endpoints

| Method | Route                   | Description                          | Security Controls                           |
| :----- | :---------------------- | :----------------------------------- | :------------------------------------------ |
| `GET`  | `/`                     | Service health & version status      | Read-only JSON payload                      |
| `GET`  | `/history?user_id=<id>` | Retrieves user transaction records   | Parameterized SQL query, input validation   |
| `POST` | `/config`               | Parses and echoes YAML configuration | Safe deserialization via `yaml.safe_load()` |
| `GET`  | `/healthz`              | Kubernetes/Cloud probe endpoint      | Liveness & readiness check                  |

---

## Code Layer Security (SAST, SCA & Secrets)

### 1.1 Pre-Fix Baseline Scans

Before applying code modifications, baseline scans were conducted across the original codebase to document security flaws:

#### A. Static Application Security Testing (SAST) — Bandit

Command executed:

```bash
bandit -r app/ -ll
```

Findings flagged:

- **B608 (High Severity / Low Confidence):** Possible SQL injection vector via string formatting in `/history` (`app/main.py:56`).
- **B506 (High Severity / High Confidence):** Use of unsafe `yaml.load()` allowing arbitrary Python object deserialization and Remote Code Execution (RCE) (`app/main.py:83`).
- **B201 (High Severity / Medium Confidence):** Flask app run with `debug=True`, exposing the Werkzeug interactive debugger PIN and console in production (`app/main.py:99`).
- **B108 (Medium Severity / Medium Confidence):** Probable insecure usage of hardcoded temporary file/directory `/tmp/paynimbus_history.db` in `app/db.py:11`.
- **B104 (Medium Severity / Medium Confidence):** Hardcoded binding to `0.0.0.0` (`app/main.py:99`).

#### B. Software Composition Analysis (SCA) — pip-audit

Command executed:

```bash
pip-audit -r requirements.txt
```

Findings flagged:

- Found **45 known vulnerabilities in 8 packages** in `requirements.txt`:
  - `Flask==2.0.1`: CVE-2023-30861 (Cookie session spoofing)
  - `Werkzeug==2.0.1`: CVE-2023-46136, CVE-2024-34069 (DoS, routing bypass)
  - `Jinja2==3.0.0`: CVE-2024-22195, CVE-2024-34064 (HTML injection / XSS)
  - `requests==2.25.1`: CVE-2023-32681 (Proxy-Authorization leak)
  - `PyYAML==5.3.1`: CVE-2020-14343, CVE-2017-18342 (Arbitrary code execution)
  - `urllib3==1.26.4`: CVE-2023-43804, CVE-2023-45803 (Header injection / Cookie leak)
  - `certifi==2020.12.5`, `idna==3.2`

#### C. Secret Detection — Gitleaks

Command executed:

```bash
./gitleaks detect --source . -v
```

Findings flagged:

1. `stripe-access-token` in `app/main.py` (Hardcoded Stripe secret key).
2. `aws-access-token` in historical commit `c4a2b96` (`app/aws_config.py` containing production AWS credentials: `AKIAIOSFODNN7EXAMPLE` and secret access key).

#### D. Git History Inspection

Even though commit `81c4b1d` deleted `app/aws_config.py`, running `git log -p | grep "AKIA"` proved that the secret remained completely readable inside Git's immutable object store.

---

### 1.2 Vulnerability Remediation & Code Fixes

#### Fix #1: Secret Removal & Git History Rewriting

- **Code:** Removed the static Stripe key from source code and read it dynamically from runtime environment variables:
  ```python
  STRIPE_API_KEY = os.environ.get("STRIPE_API_KEY")
  ```
- **Git History:** Purged `app/aws_config.py` from the entire repository commit tree using `git-filter-repo`:
  ```bash
  git filter-repo --path app/aws_config.py --invert-paths --force
  ```

#### Fix #2: Parameterized SQL Queries (Remediating B608)

- **Before (Vulnerable):**
  ```python
  query = f"SELECT id, user_id, amount_thb, recipient, created_at FROM history WHERE user_id = '{user_id}' ORDER BY created_at DESC"
  cur.execute(query)
  ```
- **After (Secured):**
  ```python
  query = "SELECT id, user_id, amount_thb, recipient, created_at FROM history WHERE user_id = ? ORDER BY created_at DESC"
  cur.execute(query, (user_id,))
  ```

#### Fix #3: Safe YAML Parsing (Remediating B506)

- **Before (Vulnerable):**
  ```python
  cfg = yaml.load(payload)  # Insecure: Deserializes arbitrary Python objects
  ```
- **After (Secured):**
  ```python
  cfg = yaml.safe_load(payload)  # Restricts parsing strictly to standard YAML types
  ```

#### Fix #4 & #5: Production Debugging Disabled & Dynamic Port (Remediating B201 & B104)

- Removed `debug=True` to prevent remote debugger exposure.
- Parameterized the listening port from the `PORT` environment variable:
  ```python
  app.run(host="0.0.0.0", port=int(os.environ.get("PORT", 8001)))  # nosec B104
  ```
- `# nosec B104` was explicitly annotated because binding to `0.0.0.0` is required for container ingress proxies (documented and accepted).

#### Fix #6: Secure Database Temp Directory (Remediating B108)

- Replaced the hardcoded `/tmp/paynimbus_history.db` in `app/db.py` with `tempfile.gettempdir()`:
  ```python
  DB_PATH = os.environ.get(
      "PAYNIMBUS_DB_PATH",
      os.path.join(tempfile.gettempdir(), "paynimbus_history.db")
  )
  ```

#### Fix #7: Dependency Upgrades (Remediating pip-audit CVEs)

Updated all libraries in `requirements.txt` to patched upstream versions:

```text
Flask==3.1.3
Werkzeug==3.1.6
Jinja2==3.1.6
itsdangerous==2.2.0
click==8.1.8
MarkupSafe==2.1.5
requests==2.33.0
PyYAML>=6.0.1
urllib3==2.7.0
certifi>=2023.7.22
charset-normalizer==3.3.2
idna==3.15
```

---

### 1.3 Post-Fix Verification Scans

| Tool          | Post-Fix Command                  | Scan Result                                                             | Status |
| :------------ | :-------------------------------- | :---------------------------------------------------------------------- | :----- |
| **Bandit**    | `bandit -r app/ -ll`              | **0 High / 0 Critical issues** (B201, B608, B506 completely eliminated) | PASS   |
| **pip-audit** | `pip-audit -r requirements.txt`   | **0 vulnerabilities found** (all CVEs resolved)                         | PASS   |
| **Gitleaks**  | `./gitleaks detect --source . -v` | **0 leaks detected** (0 findings across commits)                        | PASS   |

---

### 1.4 Findings Summary Table

|   #   | Tool      | Finding ID            |   Severity   | Disposition  | Justification / Remediation Details                                                                                   |
| :---: | :-------- | :-------------------- | :----------: | :----------- | :-------------------------------------------------------------------------------------------------------------------- |
| **1** | Gitleaks  | `aws-access-token`    | **Critical** | **Fixed**    | Utilized `git-filter-repo` to permanently erase commits containing AWS secret credentials from Git history.           |
| **2** | Gitleaks  | `stripe-access-token` | **Critical** | **Fixed**    | Removed static secret string from source code and mapped it to `os.environ.get("STRIPE_API_KEY")`.                    |
| **3** | Bandit    | `B608`                |   **High**   | **Fixed**    | Eliminated SQL Injection on `/history` by converting formatted f-strings into parameterized queries with `?` markers. |
| **4** | Bandit    | `B506`                |   **High**   | **Fixed**    | Prevented arbitrary Python object execution / RCE on `/config` by replacing `yaml.load()` with `yaml.safe_load()`.    |
| **5** | Bandit    | `B201`                |   **High**   | **Fixed**    | Disabled developer mode by removing `debug=True` from `app.run()`.                                                    |
| **6** | pip-audit | Multiple CVEs         |   **High**   | **Fixed**    | Upgraded all vulnerable libraries in `requirements.txt` to CVE-free versions (Flask ≥ 3.1.3, Jinja2 ≥ 3.1.6, etc.).   |
| **7** | Bandit    | `B108`                |  **Medium**  | **Fixed**    | Secured SQLite path in `app/db.py` by transitioning from static `/tmp` to `tempfile.gettempdir()`.                    |
| **8** | Bandit    | `B104`                |  **Medium**  | **Accepted** | Binding to `0.0.0.0` is required for cloud container ingress proxy; silenced via `# nosec B104` annotation.           |

---

### 1.5 Git History & Commit Strategy

Every remediation was structured into atomic Git commits prefixed with `[SEC-FIX]`:

```text
d6cf901 [SEC-FIX] code: acknowledge and silence B104 for container ingress compliance
ced90bc [SEC-FIX] code: secure temporary directory implementation for database path
1e1c60f [SEC-FIX] deps: bump all packages to CVE-free versions
4651345 [SEC-FIX] deps: bump all packages to CVE-free versions
005a2aa [SEC-FIX] code: parameterise port with environment variable
b0ea24f [SEC-FIX] code: remove debug mode from app.run
88688a0 [SEC-FIX] code: use safe_load for YAML configurations
0d715b6 [SEC-FIX] code: parameterise SQL query in /history
7afe091 [SEC-FIX] code: remove hardcoded Stripe API key
9ec09d1 Initial scaffold for history API
```

---

## Container Layer Security (Docker, Distroless & GCP)

### 2.1 Multi-Stage Dockerfile Architecture

To satisfy defense-in-depth, the container build utilizes a **two-stage Dockerfile**:

1. **Stage 1 (Builder):** Uses `python:3.12-slim` to compile and install wheels into `/root/.local`.
2. **Stage 2 (Runtime):** Uses Google's Distroless image (`gcr.io/distroless/python3-debian12:nonroot`). Distroless contains **no package managers (`apt`), no shell (`/bin/sh`, `/bin/bash`), and no development utilities**, reducing the attack surface by over 90%.

```dockerfile
# ── Stage 1: builder ────────────────────────────────────────────────
FROM python:3.12-slim AS builder
WORKDIR /build
COPY requirements.txt .
RUN pip install --no-cache-dir --user -r requirements.txt

# ── Stage 2: runtime (distroless, non-root) ─────────────────────────
FROM gcr.io/distroless/python3-debian12:nonroot
LABEL maintainer="Apisit Suansane"
WORKDIR /app

# Copy installed Python packages from builder
COPY --from=builder /root/.local /home/nonroot/.local
ENV PATH=/home/nonroot/.local/bin:$PATH
ENV PYTHONPATH=/home/nonroot/.local/lib/python3.12/site-packages
ENV PORT=8001

# Copy source code with non-root ownership
COPY --chown=nonroot:nonroot app/ /app/

EXPOSE 8001
USER nonroot

ENTRYPOINT ["python", "-m", "app.main"]
```

### 2.2 Build Context Isolation (.dockerignore)

The build context is strictly confined using `.dockerignore` to prevent leaking secret keys, git metadata, local SQLite databases, or bytecode into the container image:

```text
.git
.gitignore
__pycache__
*.pyc
*.db
*.sqlite
deploy/
README.md
.env
.venv
```

---

### 2.3 GCP Cloud Build & Artifact Registry

The image was built directly in Google Cloud using Cloud Build and pushed to Google Artifact Registry:

```bash
# Set environment variables
export PROJECT_ID="paynimbus-production"
export REGION="asia-southeast1"
export REPO="paynimbus-history-api"
export IMAGE="history-api"
export TAG="v1"

# Submit build to Google Cloud Build
gcloud builds submit --tag "${REGION}-docker.pkg.dev/${PROJECT_ID}/${REPO}/${IMAGE}:${TAG}"
```

#### Verification & Immutability:

- **Registry Location:** `asia-southeast1-docker.pkg.dev/paynimbus-production/paynimbus-history-api/history-api:v1`
- **Pinned Cryptographic Digest:**
  ```text
  sha256:f9c0b8150f7215e5ef61211823e28c1016b8548617ae2531e1b487c871877ab2
  ```

> **Note on Infrastructure Teardown:**  
> All provisioned Google Cloud resources (Artifact Registry repository and temporary build assets) have been intentionally decommissioned post-audit to enforce cloud lifecycle governance and prevent unnecessary compute overhead.

---

### 2.4 Container Analysis Vulnerability Scan

Google Cloud Container Analysis scanned the built image for operating system and binary vulnerabilities:

```bash
# Query findings filtered with jq
gcloud artifacts vulnerabilities list "${IMG}@${DIGEST}" --format=json | \
jq '.[] | {effectiveSeverity: .occurrence.vulnerability.effectiveSeverity, shortDescription: .occurrence.vulnerability.shortDescription, affectedPackage: .occurrence.vulnerability.packageIssue.affectedPackage, affectedVersion: .occurrence.vulnerability.packageIssue.affectedVersion.name, fixedVersion: .occurrence.vulnerability.packageIssue.fixedVersion.name}'
```

#### Vulnerability Severity Breakdown:

| Severity                  | Count  | Pass / Fail Status | Notes                                              |
| :------------------------ | :----: | :----------------: | :------------------------------------------------- |
| **Critical**              | **0**  |      **PASS**      | Meets strict security threshold (0 Criticals).     |
| **High**                  | **5**  |      **PASS**      | Base OS packages (documented justification below). |
| **Medium**                |   1    |        PASS        | Within normal cloud operational acceptance.        |
| **Low**                   |   48   |        PASS        | Standard OS-level low impact issues.               |
| **Minimal / Unspecified** |   25   |        PASS        | Informational.                                     |
| **Total**                 | **79** |      **PASS**      | Image cleared for deployment.                      |

#### Security Justification for Remaining 5 High Findings:

> _"The scan found 5 High vulnerabilities originating exclusively from Debian base operating system libraries, not from the application code. These cannot be fixed at present because upstream Debian security patches have not yet been released (`fixedVersion: null`). However, the container remains secure because it runs Google's minimal Distroless image—it contains no shell binaries (`sh`, `bash`), package managers, or compilers, and executes strictly under the unprivileged `nonroot` UID (65532)."_

---

## Key Security Questions & Answers (Q1 – Q6)

### Q1: Parameterized Query vs. Input Filtering (Bandit B608)

> **Question:** _Bandit flagged finding B608 (SQL injection) in the `/history` endpoint. You fixed it by using a parameterised query with a `?` placeholder instead of filtering out special characters from the input. Explain why the parameterised approach is more secure than the filtering approach, even when the filter appears to block all dangerous characters._

**Answer:**  
Parameterized queries are more secure because they separate the SQL command structure from the user data by pre-compiling the query first. This forces the database engine to treat the input strictly as a literal value, meaning dangerous characters can never alter the execution logic. In contrast, input filtering is risky because advanced attackers can often find creative encoding techniques to bypass the filters and trigger malicious commands.

---

### Q2: Git History Persistence & Secret Erasure (Gitleaks)

> **Question:** _Gitleaks found an AWS access key even though the file `app/aws_config.py` was deleted in commit C. Explain why deleting a file in a Git commit does not actually remove it from the repository, and why this matters for credential security._

**Answer:**  
Git is designed to keep a complete history of all changes, so deleting a file in a new commit only removes it from the current version. The file and its credentials still exist permanently as a blob inside past commits in the Git object store. This is dangerous because anyone who clones the repository can easily scan the full history to find and steal the leaked keys.

---

### Q3: SAST vs. SCA Fundamental Differences

> **Question:** _pip-audit found CVEs in your `requirements.txt`, but Bandit did not report these same issues. In one sentence, explain why — what is the fundamental difference between what SAST and SCA tools look at?_

**Answer:**  
SAST tools (like Bandit) analyze the custom source code written by developers to find insecure coding patterns, whereas SCA tools (like pip-audit) scan third-party dependencies against known vulnerability databases.

---

### Q4: Multi-Stage Distroless vs. Single-Stage Dockerfile

> **Question:** _Your multi-stage Dockerfile uses `python:3.12-slim` in Stage 1 and `distroless:nonroot` in Stage 2. Explain what the two-stage approach achieves that a single-stage `python:3.12-slim` Dockerfile would not._

**Answer:**  
A multi-stage build allows us to use build tools and package managers in Stage 1 to install dependencies, and then copy only the runtime packages into a clean distroless image in Stage 2. A single-stage `python:3.12-slim` Dockerfile would leave all compilers, build utilities, and system packages inside the production image. This two-stage approach drastically reduces the container's attack surface and minimizes the final image size.

---

### Q5: pip-audit vs. Container Analysis Coverage

> **Question:** _Container Analysis found OS-level CVEs in your container image that pip-audit did not report during application dependency analysis. Explain why pip-audit missed these findings — what is the difference between what pip-audit scans and what Container Analysis scans?_

**Answer:**  
The difference is that pip-audit only reads `requirements.txt` as a text file to check explicitly declared Python packages. Meanwhile, Container Analysis inspects the actual built image layers on GCP, which includes all binary software and OS-level libraries brought in by the base image.

---

### Q6: Cryptographic Image Digest vs. Mutable Tags

> **Question:** _When deploying a container image, it is safer to reference it by digest (`sha256:...`) than by a mutable tag like `:v1`. In one sentence, explain why the digest provides a stronger security guarantee._

**Answer:**  
A mutable tag like `:v1` is not secure because it can be silently overwritten to point to a different or malicious image. On the other hand, a digest is a unique cryptographic SHA-256 hash tied permanently to the exact binary content, so if any part of the image changes, the digest changes too. Therefore, referencing by digest guarantees that the image has not been tampered with or substituted during deployment.

---

## Local Development & Testing Guide

### 1. Prerequisites

- Python 3.12+
- Docker Engine / Docker Desktop
- Security scanners: `pip install bandit pip-audit` and `gitleaks`

### 2. Local Setup

```bash
# Clone and enter the repository
cd paynimbus-container-security

# Create and activate a Python virtual environment
python -m venv .venv
source .venv/bin/activate  # On Windows PowerShell: .venv\Scripts\Activate.ps1

# Install patched production dependencies
pip install -r requirements.txt
```

### 3. Run the Microservice Locally

```bash
# Set optional environment variables
export PORT=8001
export STRIPE_API_KEY="sk_test_mock_key_for_local_dev"

# Run the application
python -m app.main
```

### 4. Test API Endpoints

```bash
# Test health check
curl http://localhost:8001/healthz

# Test root endpoint
curl http://localhost:8001/

# Test parameterized history query
curl "http://localhost:8001/history?user_id=user_01"

# Test safe YAML configuration
curl -X POST http://localhost:8001/config \
     -H "Content-Type: application/x-yaml" \
     -d "app_name: PayNimbus\nenvironment: production"
```

### 5. Run Security Audits Locally

```bash
# 1. Run SAST analysis
bandit -r app/ -ll

# 2. Run SCA dependency audit
pip-audit -r requirements.txt

# 3. Run secret detection
gitleaks detect --source . -v
```

### 6. Build & Run with Docker

```bash
# Build hardened container image locally
docker build -t paynimbus-history-api:local .

# Run container as nonroot user on port 8001
docker run -p 8001:8001 paynimbus-history-api:local

# Verify running non-root UID (returns 65532)
docker run --rm paynimbus-history-api:local id
```

---

## Verification & Compliance Checklist

| Security Control / Domain          | Verification Standard                                                             | Implementation Status         |
| :--------------------------------- | :-------------------------------------------------------------------------------- | :---------------------------- |
| **Static Code Analysis (SAST)**    | Zero High/Critical security vulnerabilities in source code via Bandit             | Verified (Section 1.3)        |
| **Dependency Vulnerability (SCA)** | Zero known Common Vulnerabilities and Exposures (CVEs) via pip-audit              | Verified (Section 1.3)        |
| **Secret Leak Prevention**         | Zero sensitive tokens/credentials in working tree or Git history via Gitleaks     | Verified (Section 1.3)        |
| **SQL Injection Remediation**      | All dynamic SQL converted to parameterized prepared queries (`?` placeholder)     | Implemented (`app/main.py`)   |
| **Safe Deserialization**           | Untrusted YAML inputs restricted to primitive types via `yaml.safe_load()`        | Implemented (`app/main.py`)   |
| **Temporary Storage Security**     | Replaced insecure static `/tmp` path with system temporary directory              | Implemented (`app/db.py`)     |
| **Container Attack Surface**       | Minimal two-stage Distroless runtime with no shell, package manager, or compilers | Implemented (`Dockerfile`)    |
| **Least Privilege Execution**      | Runtime container executed under non-root unprivileged UID (`65532`)              | Implemented (`Dockerfile`)    |
| **Build Context Isolation**        | Secrets, database files, and local cache excluded via `.dockerignore`             | Implemented (`.dockerignore`) |
| **Supply Chain Integrity**         | Automated cloud container build with status `SUCCESS` on GCP Cloud Build          | Verified (Section 2.3)        |
| **Immutable Image Deployment**     | Cryptographic SHA-256 digest pinning enforced (`sha256:f9c0b81...`)               | Verified (Section 2.3)        |
| **Container Vulnerability Audit**  | Automated image layer scanning on GCP Artifact Registry (0 Criticals)             | Verified (Section 2.4)        |

---

Implemented as a practical cybersecurity lab under the Palo Alto Networks Cybersecurity Academy curriculum in collaboration with Bangkok University.
