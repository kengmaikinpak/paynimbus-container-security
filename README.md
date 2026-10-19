# PayNimbus Container Security & DevSecOps Hardening

A comprehensive Cloud Security and DevSecOps engineering case study on auditing, hardening, and securing containerized microservices on Google Cloud Platform (GCP).

---

## Table of Contents

1. [Project Overview & Threat Model Scenario](#project-overview--threat-model-scenario)
   - [1.1 The Fintech Scenario](#11-the-fintech-scenario)
   - [1.2 Kubernetes 4C Security Framework](#12-kubernetes-4c-security-framework)
2. [Repository Structure](#repository-structure)
3. [Legacy Architecture & Technical Debt Audit](#legacy-architecture--technical-debt-audit)
   - [2.1 Legacy Codebase Deficiencies](#21-legacy-codebase-deficiencies)
   - [2.2 Deployment Script Anti-Patterns (deploy-old.sh)](#22-deployment-script-anti-patterns-deploy-oldsh)
4. [Code Layer Security (SAST, SCA & Secrets)](#code-layer-security-sast-sca--secrets)
   - [3.1 Pre-Fix Baseline Scans](#31-pre-fix-baseline-scans)
   - [3.2 Vulnerability Remediation & Code Diffs](#32-vulnerability-remediation--code-diffs)
   - [3.3 Post-Fix Verification Scans](#33-post-fix-verification-scans)
   - [3.4 The 14 Expected Findings Summary Table](#34-the-14-expected-findings-summary-table)
   - [3.5 Git History Scrubbing & Commit Strategy](#35-git-history-scrubbing--commit-strategy)
5. [Container Layer Security (Docker, Distroless & GCP)](#container-layer-security-docker-distroless--gcp)
   - [4.1 Multi-Stage Distroless Dockerfile Architecture](#41-multi-stage-distroless-dockerfile-architecture)
   - [4.2 Build Context Isolation (.dockerignore)](#42-build-context-isolation-dockerignore)
   - [4.3 GCP Cloud Build & Artifact Registry Integration](#43-gcp-cloud-build--artifact-registry-integration)
   - [4.4 Container Analysis Vulnerability Scanning & Justification](#44-container-analysis-vulnerability-scanning--justification)
6. [Key Security Questions & Answers (Q1 – Q6)](#key-security-questions--answers-q1--q6)
7. [Local Development & Verification Guide](#local-development--verification-guide)
8. [Verification & Compliance Checklist](#verification--compliance-checklist)

---

## Project Overview & Threat Model Scenario

### 1.1 The Fintech Scenario

**PayNimbus** is a Bangkok-based fintech startup providing cross-border peer-to-peer (P2P) remittances for migrant workers across Southeast Asia. The platform serves over **180,000 active users** and processes approximately **35 million THB in daily transactions**.

Following a major security breach at a regional competitor—where attackers exploited an unpatched Python dependency in a public container, pivoted into cluster metadata, and exfiltrated 240,000 customer KYC identity records—PayNimbus initiated an urgent security hardening sprint.

This repository documents the complete security remediation and defense-in-depth re-architecture of the platform's most exposed external component: the **Transaction History API (`paynimbus-history-api`)**, transitioning it from an unvetted "it works on my machine" prototype into an auditable, hardened, production-ready microservice running on Google Cloud Platform.

### 1.2 Kubernetes 4C Security Framework

Security in modern cloud-native systems is structured across four concentric layers (**Cloud, Cluster, Container, Code**):

```
       +---------------------------------------------+
       |                  Cloud                      |
       |   +-------------------------------------+   |
       |   |               Cluster               |   |
       |   |   +-----------------------------+   |   |
       |   |   |          Container          |   |   |  <-- Hardened in Task 2
       |   |   |   +---------------------+   |   |   |
       |   |   |   |        Code         |   |   |   |  <-- Hardened in Task 1
       |   |   |   +---------------------+   |   |   |
       |   |   +-----------------------------+   |   |
       |   +-------------------------------------+   |
       +---------------------------------------------+
```

- **Code Layer:** Enforcing secure coding standards, input validation, safe deserialization, dependency hygiene (SCA), and secret eradication.
  - _Industry precedent:_ **2021 Log4Shell (CVE-2021-44228)** demonstrated how a single vulnerable code-level dependency can compromise thousands of enterprise organizations overnight.
- **Container Layer:** Eliminating OS utilities, compilers, and shells; running with least privilege (non-root UID); isolating build contexts; and deploying immutable cryptographic digests.
  - _Industry precedent:_ **2018 Tesla Kubernetes Breach** where unauthenticated container access allowed adversaries to spawn cryptomining payloads inside production infrastructure.

---

## Repository Structure

```tree
paynimbus-container-security/
├── .dockerignore                 # Strict build context isolation rules
├── .gitignore                    # Local environment and cache exclusion
├── Dockerfile                    # Multi-stage hardened Distroless container specification
├── requirements.txt              # Pinned, CVE-free production Python dependencies
├── README.md                     # Comprehensive security audit & engineering documentation
├── app/
│   ├── __init__.py               # Python package namespace definition
│   ├── main.py                   # Hardened Flask REST microservice
│   └── db.py                     # Secure SQLite helper with tempfile isolation & mock seeds
└── deploy/
    └── deploy-old.sh             # Legacy insecure deployment script (Bob's anti-pattern)
```

### API Endpoints

| Method | Route                   | Purpose                              | Security Controls                           |
| :----- | :---------------------- | :----------------------------------- | :------------------------------------------ |
| `GET`  | `/`                     | Microservice health & version banner | Read-only JSON payload                      |
| `GET`  | `/history?user_id=<id>` | Customer transaction history query   | Parameterized prepared query, input check   |
| `POST` | `/config`               | Internal YAML configuration parser   | Safe deserialization via `yaml.safe_load()` |
| `GET`  | `/healthz`              | Container liveness / readiness probe | Unauthenticated 200 OK probe response       |

---

## Legacy Architecture & Technical Debt Audit

### 2.1 Legacy Codebase Deficiencies

The original repository delivered by the previous developer ("Bob") contained critical design and implementation flaws spanning multiple layers:

1. **Hardcoded Secrets in Source (`app/main.py`):** Static production Stripe API key (`STRIPE_API_KEY = "sk_live_..."`) committed directly into code.
2. **SQL Injection Vulnerability (`app/main.py`):** String concatenation via f-string directly formatting untrusted `user_id` query parameters into raw SQL.
3. **Arbitrary Object Deserialization / RCE (`app/main.py`):** Using unsafe `yaml.load()` on unauthenticated HTTP POST payloads, allowing remote attackers to execute arbitrary Python bytecode.
4. **Interactive Debugger in Production (`app/main.py`):** Flask executed with `debug=True`, exposing Werkzeug's interactive console and PIN to the public internet.
5. **Insecure Temp Database (`app/db.py`):** Static SQLite path `/tmp/paynimbus_history.db` allowing local temp file hijacking or race conditions.
6. **Outdated Dependencies (`requirements.txt`):** Pinned outdated libraries containing 45 known CVEs.
7. **Leaked Cloud Credentials in Git History:** AWS credentials committed in `app/aws_config.py` in historical commit `c4a2b96` and remaining in Git blob storage even after file deletion.

### 2.2 Deployment Script Anti-Patterns (deploy-old.sh)

The legacy deployment script [`deploy/deploy-old.sh`](file:///c:/Users/Legion5/Zteelers/Photos/Works/4%20Term%202/CE436%20Computer%20Crime%20and%20Security/Week%2016%20-%20paynimbus/paynimbus-container-security/deploy/deploy-old.sh) demonstrates common high-risk anti-patterns in enterprise deployments:

```bash
# High-Risk Flaw #1: Oversized bloated Debian image with curl, vim, wget, ping, apt
FROM python:3.10

# High-Risk Flaw #2: Running implicitly as root (UID 0)

# High-Risk Flaw #3: Pushing to deprecated public/unscoped gcr.io
docker push "gcr.io/$PROJECT_ID/history-api:latest"

# High-Risk Flaw #4: Unauthenticated deployment on Cloud Run
gcloud run deploy history-api --allow-unauthenticated ...

# High-Risk Flaw #5: Over-permissioned IAM Service Account (roles/editor)
--service-account="deployer@paynimbus-prod.iam.gserviceaccount.com"

# High-Risk Flaw #6: Plaintext secrets injected into CLI flags and revision history
--set-env-vars="STRIPE_API_KEY=sk_live_REALKEY_DONT_LEAK,DB_PASSWORD=hunter2"
```

---

## Code Layer Security (SAST, SCA & Secrets)

### 3.1 Pre-Fix Baseline Scans

Three complementary automated security scanning tools were executed against the codebase:

```bash
# 1. Static Application Security Testing (SAST)
bandit -r app/ -ll

# 2. Software Composition Analysis (SCA)
pip-audit -r requirements.txt

# 3. Secret Detection across entire Git history
./gitleaks detect --source . -v
```

#### Scan Observations:

- **Bandit (SAST):** Identified 5 distinct rule violations:
  - `B608`: SQL injection via formatted query string in `app/main.py:56`.
  - `B506`: Unsafe YAML deserialization via `yaml.load()` in `app/main.py:83`.
  - `B201`: Active developer debug console via `app.run(..., debug=True)`.
  - `B108`: Insecure hardcoded temp directory `/tmp/paynimbus_history.db`.
  - `B104`: Insecure network binding to `0.0.0.0`.
- **pip-audit (SCA):** Identified **45 known vulnerabilities across 8 pinned dependencies** in `requirements.txt` (including Critical remote code execution and session hijacking flaws in Flask, Werkzeug, Jinja2, PyYAML, and requests).
- **Gitleaks (Secrets):** Detected active Stripe test/live tokens in `app/main.py`, as well as active AWS access credentials (`AKIAIOSFODNN7EXAMPLE`) embedded in past commit `c4a2b96`.

---

### 3.2 Vulnerability Remediation & Code Diffs

#### Remediation 1: Secret Extraction to Runtime Environment

```python
# Before (Vulnerable)
STRIPE_API_KEY = "sk_live_abc123FAKEKEYexampleONLY_DO_NOT_USE_IN_PROD_4242"

# After (Hardened)
STRIPE_API_KEY = os.environ.get("STRIPE_API_KEY")
```

#### Remediation 2: Parameterized SQL Prepared Statements (B608)

```python
# Before (Vulnerable to SQL Injection)
query = f"SELECT id, user_id, amount_thb, recipient, created_at FROM history WHERE user_id = '{user_id}' ORDER BY created_at DESC"
cur.execute(query)

# After (Hardened Prepared Statement)
query = "SELECT id, user_id, amount_thb, recipient, created_at FROM history WHERE user_id = ? ORDER BY created_at DESC"
cur.execute(query, (user_id,))
```

#### Remediation 3: Safe YAML Deserialization (B506)

```python
# Before (Arbitrary Python Object Execution / RCE)
cfg = yaml.load(payload)

# After (Restricted Safe Parser)
cfg = yaml.safe_load(payload)
```

#### Remediation 4 & 5: Disable Production Debug Mode & Parameterize Port (B201 & B104)

```python
# Before (Werkzeug Debugger PIN Exploit & Static Port)
app.run(host="0.0.0.0", port=5000, debug=True)

# After (Hardened Server Entry Point)
app.run(host="0.0.0.0", port=int(os.environ.get("PORT", 8001)))  # nosec B104
```

_Note: `# nosec B104` is documented and accepted because cloud container ingress controllers require listening on all interfaces (`0.0.0.0`)._

#### Remediation 6: Secure System Temporary File Resolution (B108)

```python
# Before (Hardcoded /tmp file)
DB_PATH = os.environ.get("PAYNIMBUS_DB_PATH", "/tmp/paynimbus_history.db")

# After (Platform-independent secure temp directory)
DB_PATH = os.environ.get("PAYNIMBUS_DB_PATH", os.path.join(tempfile.gettempdir(), "paynimbus_history.db"))
```

#### Remediation 7: Dependency Upgrades to Patched Releases

All vulnerable packages in `requirements.txt` were bumped to upstream releases where security patches have been verified:

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

### 3.3 Post-Fix Verification Scans

| Security Scanner       | Verification Command              | Post-Fix Result                                              | Status |
| :--------------------- | :-------------------------------- | :----------------------------------------------------------- | :----- |
| **Bandit (SAST)**      | `bandit -r app/ -ll`              | **0 High / 0 Critical issues** (B201, B608, B506 eradicated) | PASS   |
| **pip-audit (SCA)**    | `pip-audit -r requirements.txt`   | **0 vulnerabilities found** (All 45 CVEs resolved)           | PASS   |
| **Gitleaks (Secrets)** | `./gitleaks detect --source . -v` | **0 leaks detected** across commit tree                      | PASS   |

---

### 3.4 The 14 Expected Findings Summary Table

The complete audit reconciliation covers all 14 findings specified in the enterprise security matrix:

|   #    | Tool      | Rule / Finding ID     | Identified Risk & Vulnerability                                 | Severity | Disposition  | Technical Remediation Applied                                                     |
| :----: | :-------- | :-------------------- | :-------------------------------------------------------------- | :------: | :----------: | :-------------------------------------------------------------------------------- |
| **1**  | Bandit    | `B108`                | Hardcoded temporary directory (`/tmp`)                          |  Medium  |  **Fixed**   | Replaced with `os.path.join(tempfile.gettempdir(), "paynimbus_history.db")`.      |
| **2**  | Bandit    | `B104`                | Hardcoded bind to all network interfaces (`0.0.0.0`)            |  Medium  | **Accepted** | Required for container ingress routing; annotated and audited via `# nosec B104`. |
| **3**  | Bandit    | `B608`                | SQL injection via string concatenation in `/history`            |   High   |  **Fixed**   | Migrated to parameterized prepared statement with `?` bind parameter.             |
| **4**  | Bandit    | `B506`                | Arbitrary code execution via unsafe `yaml.load()`               |   High   |  **Fixed**   | Replaced parser with `yaml.safe_load()` to enforce primitive type parsing.        |
| **5**  | Bandit    | `B201`                | Active Flask interactive debugger in production entrypoint      |   High   |  **Fixed**   | Removed `debug=True` parameter completely from `app.run()`.                       |
| **6**  | pip-audit | `PYSEC-2023-62`       | Flask 2.0.1 session cookie manipulation                         |   High   |  **Fixed**   | Upgraded to `Flask==3.1.3`.                                                       |
| **7**  | pip-audit | `CVE-2024-34069` (+9) | Werkzeug 2.0.1 DoS & routing bypass                             |   High   |  **Fixed**   | Upgraded to `Werkzeug==3.1.6`.                                                    |
| **8**  | pip-audit | `CVE-2024-22195` (+4) | Jinja2 3.0.0 HTML attribute injection & XSS                     |   High   |  **Fixed**   | Upgraded to `Jinja2==3.1.6`.                                                      |
| **9**  | pip-audit | `CVE-2024-35195` (+2) | requests 2.25.1 Proxy-Authorization header leak                 |  Medium  |  **Fixed**   | Upgraded to `requests==2.33.0`.                                                   |
| **10** | pip-audit | `CVE-2024-37891` (+4) | urllib3 1.26.4 proxy handling & cookie disclosure               |   High   |  **Fixed**   | Upgraded to `urllib3==2.7.0`.                                                     |
| **11** | pip-audit | `PYSEC-2021-142`      | PyYAML 5.3.1 deserialization vulnerability                      |   High   |  **Fixed**   | Upgraded to `PyYAML>=6.0.1`.                                                      |
| **12** | pip-audit | `PYSEC-2023-135`      | certifi 2020.12.5 untrusted root certificates                   |  Medium  |  **Fixed**   | Upgraded to `certifi>=2023.7.22`.                                                 |
| **13** | Gitleaks  | `aws-access-token`    | Leaked AWS access keys in past Git commit (`app/aws_config.py`) | Critical |  **Fixed**   | Executed `git-filter-repo` to permanently erase blob from Git history.            |
| **14** | Gitleaks  | `stripe-access-token` | Hardcoded Stripe API secret in `app/main.py`                    | Critical |  **Fixed**   | Purged static token and delegated credential resolution to environment variables. |

---

### 3.5 Git History Scrubbing & Commit Strategy

Simply deleting sensitive files (such as `app/aws_config.py`) in a new commit does **not** protect credentials, as past commits retain the files indefinitely in the `.git/objects` blob store.

To purge the credentials permanently, the Git history was scrubbed using `git-filter-repo`:

```bash
# Scrub file permanently from all commit branches and tags
git filter-repo --invert-paths --path app/aws_config.py --force
```

Following the history sanitization, all security patches were structured into clean, atomic commits prefixed with `[SEC-FIX]`:

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

### 4.1 Multi-Stage Distroless Dockerfile Architecture

To implement true defense-in-depth, containerization was refactored from a monolithic 1GB Debian image into a **hardened two-stage Distroless build**:

1. **Stage 1 (Builder):** Uses `python:3.12-slim` to fetch wheels and install packages into a local non-root directory (`/root/.local`).
2. **Stage 2 (Runtime):** Uses Google's Distroless runtime image (`gcr.io/distroless/python3-debian12:nonroot`).
   - Contains **no package managers (`apt`, `dpkg`)**
   - Contains **no interactive shells (`/bin/sh`, `/bin/bash`)**
   - Contains **no development utilities (`curl`, `vim`, `wget`)**
   - Operates strictly under unprivileged UID `65532` (`USER nonroot`)

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

### 4.2 Build Context Isolation (.dockerignore)

A strict [`.dockerignore`](file:///c:/Users/Legion5/Zteelers/Photos/Works/4%20Term%202/CE436%20Computer%20Crime%20and%20Security/Week%2016%20-%20paynimbus/paynimbus-container-security/.dockerignore) file guarantees that Git metadata, test databases, environment secrets, and deployment scripts are never bundled into the image layer:

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

### 4.3 GCP Cloud Build & Artifact Registry Integration

The hardened image was built and published using Google Cloud Build and Google Artifact Registry:

```bash
# Set pipeline parameters
export PROJECT_ID="paynimbus-production"
export REGION="asia-southeast1"
export REPO="paynimbus-history-api"
export IMAGE="history-api"
export TAG="v1"

# Submit remote build to GCP Cloud Build
gcloud builds submit --tag "${REGION}-docker.pkg.dev/${PROJECT_ID}/${REPO}/${IMAGE}:${TAG}"
```

#### Image Immutability & SHA-256 Digest:

Deployments in production should never rely on mutable tags (such as `:v1` or `:latest`), which can be overwritten or poisoned. The image manifest is bound to a cryptographic SHA-256 digest:

```text
Registry Location:
asia-southeast1-docker.pkg.dev/paynimbus-production/paynimbus-history-api/history-api:v1

Pinned Cryptographic Digest:
sha256:f9c0b8150f7215e5ef61211823e28c1016b8548617ae2531e1b487c871877ab2
```

> **Note on Infrastructure Teardown:**  
> All provisioned Google Cloud resources (Artifact Registry repository and temporary build assets) have been intentionally decommissioned post-audit to enforce cloud lifecycle governance and prevent unnecessary compute overhead.

---

### 4.4 Container Analysis Vulnerability Scanning & Justification

Google Cloud Container Analysis automatically scanned all image layers upon push:

```bash
# Extract structured vulnerability findings with jq
gcloud artifacts vulnerabilities list "${IMG}@${DIGEST}" --format=json | \
jq '.[] | {
  effectiveSeverity: .occurrence.vulnerability.effectiveSeverity,
  shortDescription: .occurrence.vulnerability.shortDescription,
  affectedPackage: .occurrence.vulnerability.packageIssue.affectedPackage,
  affectedVersion: .occurrence.vulnerability.packageIssue.affectedVersion.name,
  fixedVersion: .occurrence.vulnerability.packageIssue.fixedVersion.name
}'
```

#### Scan Severity Breakdown:

| Severity Classification   | Count  | Pass / Fail Criteria  | Assessment Status                                          |
| :------------------------ | :----: | :-------------------: | :--------------------------------------------------------- |
| **Critical**              | **0**  | **PASS (Must be 0)**  | Zero Critical findings detected across all layers.         |
| **High**                  | **5**  | **PASS (Documented)** | Residual Debian base OS packages without upstream patches. |
| **Medium**                |   1    |         PASS          | Within accepted cloud risk tolerance.                      |
| **Low**                   |   48   |         PASS          | Informational / Low risk OS libraries.                     |
| **Minimal / Unspecified** |   25   |         PASS          | Minor informational annotations.                           |
| **Total Findings**        | **79** |       **PASS**        | Image approved for production deployment.                  |

#### Risk Assessment & Mitigation for Remaining 5 High Findings:

> _"The 5 High vulnerabilities identified by Container Analysis originate exclusively from Debian Linux base system shared libraries packaged inside the distroless runtime, rather than application code. At the time of scanning, no upstream security fix had been released by Debian maintainers (`fixedVersion: null`)._
>
> _However, the effective exploitability of these findings is fully mitigated by our container architecture: the image contains **no interactive shell (`sh`, `bash`)**, **no package management tools**, and executes strictly under an unprivileged user (`nonroot`, UID `65532`). An attacker cannot leverage these libraries for remote shell spawning, privilege escalation, or lateral movement."_

---

## Key Security Questions & Answers (Q1 – Q6)

### Q1: Parameterized Query vs. Input Filtering (Bandit B608)

> **Question:** _Bandit flagged finding B608 (SQL injection) in the `/history` endpoint. You fixed it by using a parameterised query with a `?` placeholder instead of filtering out special characters from the input. Explain why the parameterised approach is more secure than the filtering approach, even when the filter appears to block all dangerous characters._

**Answer:**  
Parameterized queries are fundamentally more secure because they separate the SQL syntax structure from user-supplied data at the database driver level. The database engine pre-compiles the query statement before the parameter values are bound, forcing the engine to treat input strictly as literal scalar values rather than executable code. In contrast, input filtering (block-listing) is intrinsically fragile: attackers routinely bypass filters using alternative character encodings, Unicode variations, nested tokens, or SQL dialect idiosyncrasies that filter logic fails to anticipate.

---

### Q2: Git History Persistence & Secret Erasure (Gitleaks)

> **Question:** _Gitleaks found an AWS access key even though the file `app/aws_config.py` was deleted in commit C. Explain why deleting a file in a Git commit does not actually remove it from the repository, and why this matters for credential security._

**Answer:**  
Git is an append-only content-addressable directed acyclic graph (DAG) designed to preserve historical fidelity. Creating a new commit that deletes a file merely creates a new tree object in which the file is unlinked from the working tree; the underlying file content continues to exist permanently as an immutable blob in `.git/objects/`. Anyone with read or clone access to the repository can inspect the commit history or run automated scanners to extract the leaked credentials. True credential remediation requires either rewriting the commit graph (e.g., using `git-filter-repo`) or immediately revoking and rotating the exposed keys in the cloud provider.

---

### Q3: SAST vs. SCA Fundamental Differences

> **Question:** _pip-audit found CVEs in your `requirements.txt`, but Bandit did not report these same issues. In one sentence, explain why — what is the fundamental difference between what SAST and SCA tools look at?_

**Answer:**  
SAST tools (such as Bandit) inspect internal, first-party application source code for insecure coding patterns and anti-patterns, whereas SCA tools (such as pip-audit) inspect external, third-party software dependencies by matching declared package versions against known vulnerability databases (such as PyPI Advisory and OSV).

---

### Q4: Multi-Stage Distroless vs. Single-Stage Dockerfile

> **Question:** _Your multi-stage Dockerfile uses `python:3.12-slim` in Stage 1 and `distroless:nonroot` in Stage 2. Explain what the two-stage approach achieves that a single-stage `python:3.12-slim` Dockerfile would not._

**Answer:**  
A multi-stage build cleanly decouples the build environment from the runtime deployment artifact. Stage 1 utilizes build utilities, package managers (`pip`), and compilation toolchains to assemble dependencies, and then selectively copies only the resulting application bytecode and packages into Stage 2. A single-stage `python:3.12-slim` image leaves compilation tools, package managers, and standard shell utilities inside the production image, increasing image size and dramatically expanding the container's attack surface if an attacker achieves arbitrary code execution.

---

### Q5: pip-audit vs. Container Analysis Coverage

> **Question:** _Container Analysis found OS-level CVEs in your container image that pip-audit did not report during application dependency analysis. Explain why pip-audit missed these findings — what is the difference between what pip-audit scans and what Container Analysis scans?_

**Answer:**  
The difference lies in their inspection scope: `pip-audit` operates purely as an application-level scanner that parses `requirements.txt` to check Python libraries against the PyPI Advisory database, completely unaware of underlying operating system packages. Conversely, Google Cloud Container Analysis inspects the built container image layers, scanning all binary packages, system libraries (such as `glibc`, `openssl`, `libpython`), and base OS distributions (such as Debian) against comprehensive OS vulnerability feeds.

---

### Q6: Cryptographic Image Digest vs. Mutable Tags

> **Question:** _When deploying a container image, it is safer to reference it by digest (`sha256:...`) than by a mutable tag like `:v1`. In one sentence, explain why the digest provides a stronger security guarantee._

**Answer:**  
A tag like `:v1` is a mutable pointer that can be silently altered or maliciously overwritten (tag poisoning), whereas a SHA-256 digest is an immutable cryptographic hash tied directly to the exact binary payload of the image manifest, guaranteeing supply chain integrity and ensuring the deployed artifact cannot be substituted or tampered with.

---

## Local Development & Verification Guide

### 1. Prerequisites

- Python 3.12+
- Docker Engine or Docker Desktop
- Security tooling: `bandit`, `pip-audit`, `gitleaks`

### 2. Local Setup

```bash
# Clone the repository
git clone https://github.com/wisarn/paynimbus-history-api.git
cd paynimbus-container-security

# Create and activate an isolated virtual environment
python -m venv .venv
source .venv/bin/activate  # On Windows PowerShell: .venv\Scripts\Activate.ps1

# Install patched production dependencies
pip install -r requirements.txt
```

### 3. Run Application Locally

```bash
# Configure local environment variables
export PORT=8001
export STRIPE_API_KEY="sk_test_local_mock_key_only"

# Start the Flask microservice
python -m app.main
```

### 4. Verify API Endpoints

```bash
# 1. Health check probe
curl http://localhost:8001/healthz
# Output: ok

# 2. Service status
curl http://localhost:8001/
# Output: {"service":"paynimbus-history-api","status":"ok","version":"0.1.0"}

# 3. Query transaction history (User 42 has 3 seeded transactions)
curl "http://localhost:8001/history?user_id=42"
```

Sample JSON response from `/history`:

```json
[
  {
    "amount_thb": 1500.0,
    "created_at": "2026-04-12T09:14:00Z",
    "id": 1,
    "recipient": "Somchai T.",
    "user_id": "42"
  },
  {
    "amount_thb": 840.5,
    "created_at": "2026-04-15T18:02:00Z",
    "id": 2,
    "recipient": "Linh N.",
    "user_id": "42"
  },
  {
    "amount_thb": 2200.0,
    "created_at": "2026-05-01T07:30:00Z",
    "id": 3,
    "recipient": "Aung H.",
    "user_id": "42"
  }
]
```

```bash
# 4. Safe YAML configuration parser
curl -X POST http://localhost:8001/config \
     -H "Content-Type: application/x-yaml" \
     -d "service: paynimbus\nenvironment: production\ntimeout_seconds: 30"
```

### 5. Execute Security Audits Locally

```bash
# 1. Run SAST analysis
bandit -r app/ -ll

# 2. Run SCA dependency audit
pip-audit -r requirements.txt

# 3. Run secret detection across Git commit history
gitleaks detect --source . -v
```

### 6. Build & Test Hardened Container Locally

```bash
# Build multi-stage Distroless image
docker build -t paynimbus-history-api:local .

# Run hardened container (maps container port 8001 to host port 8001)
docker run -p 8001:8001 paynimbus-history-api:local

# Verify non-root execution (returns UID 65532)
docker run --rm paynimbus-history-api:local id
```

---

## Verification & Compliance Checklist

| Security Control / Domain          | Verification Standard                                                             | Implementation Status         |
| :--------------------------------- | :-------------------------------------------------------------------------------- | :---------------------------- |
| **Static Code Analysis (SAST)**    | Zero High/Critical security vulnerabilities in source code via Bandit             | Verified (Section 3.3)        |
| **Dependency Vulnerability (SCA)** | Zero known Common Vulnerabilities and Exposures (CVEs) via pip-audit              | Verified (Section 3.3)        |
| **Secret Leak Prevention**         | Zero sensitive tokens/credentials in working tree or Git history via Gitleaks     | Verified (Section 3.3)        |
| **SQL Injection Remediation**      | All dynamic SQL converted to parameterized prepared queries (`?` placeholder)     | Implemented (`app/main.py`)   |
| **Safe Deserialization**           | Untrusted YAML inputs restricted to primitive types via `yaml.safe_load()`        | Implemented (`app/main.py`)   |
| **Temporary Storage Security**     | Replaced insecure static `/tmp` path with system temporary directory              | Implemented (`app/db.py`)     |
| **Container Attack Surface**       | Minimal two-stage Distroless runtime with no shell, package manager, or compilers | Implemented (`Dockerfile`)    |
| **Least Privilege Execution**      | Runtime container executed under non-root unprivileged UID (`65532`)              | Implemented (`Dockerfile`)    |
| **Build Context Isolation**        | Secrets, database files, and local cache excluded via `.dockerignore`             | Implemented (`.dockerignore`) |
| **Supply Chain Integrity**         | Automated cloud container build with status `SUCCESS` on GCP Cloud Build          | Verified (Section 4.3)        |
| **Immutable Image Deployment**     | Cryptographic SHA-256 digest pinning enforced (`sha256:f9c0b81...`)               | Verified (Section 4.3)        |
| **Container Vulnerability Audit**  | Automated image layer scanning on GCP Artifact Registry (0 Criticals)             | Verified (Section 4.4)        |

---

Implemented as a practical cybersecurity lab under the Palo Alto Networks Cybersecurity Academy curriculum in collaboration with Bangkok University.
