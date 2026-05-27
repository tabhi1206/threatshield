# ThreatShield Backend API

ThreatShield is a production-ready, clean-architecture FastAPI backend designed to perform cybersecurity threat analysis, signature matching (SQLi, XSS, and CMDi), entropy checks, and IP blacklist mitigation.

## 📁 Project Structure

```text
backend/
├── app.py                     # Main entry point (FastAPI initialization & security headers)
├── .env                       # Environment variables (CORS, Secrets, DB configurations)
├── requirements.txt           # Python package dependencies
├── config/
│   ├── __init__.py
│   └── settings.py            # Pydantic Settings configuration loader
├── database/
│   ├── __init__.py
│   ├── connection.py          # SQLAlchemy SQLite connection and session generator
│   └── models.py              # Database ORM models (ThreatAlert, IPBlacklist)
├── models/
│   ├── __init__.py
│   └── threat.py              # Pydantic validation and serialization schemas
├── routes/
│   ├── __init__.py
│   ├── health.py              # System and database health check routes
│   └── threats.py             # Threat scan, alert management, and blacklist routes
├── services/
│   ├── __init__.py
│   └── threat_analyzer.py     # Core threat scoring & regex parsing security engine
└── utils/
    ├── __init__.py
    └── security.py            # IP validators, entropy calculator, & log sanitization helpers
```

---

## 🚀 Getting Started

### 1. Prerequisites
Ensure you have Python 3.10+ installed on your system.

### 2. Environment Setup
From the `backend/` directory, create a Python virtual environment and activate it:

```powershell
# Create virtual environment
python -m venv venv

# Activate virtual environment (Windows Powershell)
.\venv\Scripts\Activate.ps1
```

### 3. Install Dependencies
Install all package requirements defined in `requirements.txt`:

```powershell
pip install -r requirements.txt
```

### 4. Run the API Server
Start the development server using Uvicorn. The server runs with automatic reload enabled to reflect any code edits immediately:

```powershell
uvicorn app:app --reload
```

The service will start on: `http://localhost:8000`

---

## 🛠️ API & Security Endpoints

Once the application is running, you can access the Interactive Swagger documentation at: **`http://localhost:8000/docs`**

### 1. Health Check
* **Endpoint**: `GET /api/v1/health`
* **Purpose**: Tests both API server status and SQLite database connection response times.

### 2. Scan Payload (Enhanced)
* **Endpoint**: `POST /api/v1/threats/scan`
* **Request Payload**:
  ```json
  {
    "source_ip": "192.168.1.1",
    "target_endpoint": "/api/v1/users",
    "payload": "http://secure-login-paypal.verify-user.xyz/signin"
  }
  ```
* **Response**:
  ```json
  {
    "is_malicious": true,
    "threat_score": 85,
    "threat_type": "PHISHING_MALICIOUS_SITE",
    "severity": "DANGEROUS",
    "matched_rules": [
      "SUSPICIOUS_TLD_XYZ",
      "EXCESSIVE_SUBDOMAINS",
      "PHISHING_KEYWORDS_FOUND"
    ],
    "explanations": [
      "Domain is registered under high-risk TLD (.xyz) commonly associated with phishing.",
      "Excessive subdomains (4 subdomains detected), indicating brand-spoofing nesting.",
      "Phishing-related keywords detected inside URL path/domain: ['login', 'verify']."
    ],
    "redirect_history": [
      "http://secure-login-paypal.verify-user.xyz/signin"
    ],
    "expanded_url": "http://secure-login-paypal.verify-user.xyz/signin",
    "homograph_details": {
      "is_idn": false,
      "is_homograph": false,
      "punycode": "secure-login-paypal.verify-user.xyz",
      "suspicious_characters": [],
      "explanation": "Domain uses standard Latin character sets.",
      "score_contribution": 0
    },
    "heuristic_details": {
      "score": 85,
      "rules": ["SUSPICIOUS_TLD_XYZ", "EXCESSIVE_SUBDOMAINS", "PHISHING_KEYWORDS_FOUND"],
      "explanations": [...]
    }
  }
  ```

### 3. Retrieve Scanned Threat Logs
* **Endpoint**: `GET /api/v1/threats/alerts?severity=DANGEROUS`
* **Purpose**: Retrieve historical audit logs of blocked threats from SQLite, including redirect chains and homograph checks.

### 4. Blacklist an IP
* **Endpoint**: `POST /api/v1/threats/blacklist`
* **Request Payload**:
  ```json
  {
    "ip_address": "203.0.113.5",
    "reason": "Repeated brute force attempts"
  }

## 🚢 Production & Deployment Notes

1. Secrets & Environment
  - Copy `.env.example` to `.env` and populate production values. Never commit `.env`.
  - Use a strong `JWT_SECRET_KEY` and store it in your hosting provider's secret manager (Render/GCP/AWS).

2. Docker
  - A sample `Dockerfile` is included for building a production image. It uses `uvicorn` and respects the `PORT` environment variable.
  - Build: `docker build -t threatshield-backend ./`.
  - Run locally: `docker run -e PORT=8000 -p 8000:8000 threatshield-backend`.

3. Database
  - For production, switch `DATABASE_URL` to a managed Postgres instance and run migrations with Alembic (not included by default).

  ```

---

## 🛡️ Built-in Cybersecurity Features

1. **Unicode Homograph Spoofing Detection**: Translates hostnames using Punycode/IDNA and parses characters via Unicode databases to identify mixed-script domain impersonation attacks (e.g. `аррӏе.com`).
2. **URL Heuristics Engine**: Evaluates domain nesting (excessive subdomains), brand keywords (e.g., `paypal`, `login`), excessive hyphens, raw IP routing, and malicious TLD reputation tables.
3. **Redirect Chain Resolution**: Recursively resolves redirection paths (up to 5 hops) with strict private network (RFC 1918) validations to block Server-Side Request Forgery (SSRF) and infinite circular jumps.
4. **URL Shortener Expansion**: Detects and expands obfuscated shortened links (e.g., `bit.ly`, `tinyurl`) to expose target final URLs.
5. **Entropy Calculations**: Applies Shannon entropy calculations to identify obfuscated script payloads (e.g., Base64 encoded scripts) that bypass simple regex matchers.
6. **Log Injection Safeguards (CWE-117)**: Neutralizes carriage-return and line-feed injections before storing client data in application logs.
7. **Security Header Injections**: Forces browser security through headers: HSTS, CSP (`frame-ancestors 'none'`), X-Content-Type-Options (`nosniff`), and X-Frame-Options (`DENY`).
