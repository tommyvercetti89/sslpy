[ Read in English ](README.en.md) | [ Türkçe Oku ](README.md)

---

# sslpy

Comprehensive SSL/TLS Certificate Security and Inspection Tool.

`sslpy` is an enterprise-grade command-line (CLI) utility designed to inspect SSL/TLS certificates, validate certificate trust chains against system root stores, perform live revocation checks (OCSP), audit critical transport security headers (HSTS), and calculate overall cryptographic risk scores.

---

## Key Features

* **Full Trust Chain Verification:** Validates the entire certificate path against operating system trusted Root CAs and verifies hostname matching (`check_hostname`).
* **Deep Certificate Chain Analysis:** Inspects all chain tiers individually (Leaf, Intermediate CAs, and Root Trust Anchor) including public key sizes, algorithms, CA constraints, and remaining lifespans.
* **Live OCSP Revocation Checks:** Dispatches RFC 6960 compliant requests to CA OCSP responders to determine real-time revocation status (`GOOD` / `REVOKED`).
* **HSTS Security Auditing:** Analyzes `Strict-Transport-Security` headers, evaluates `max-age` duration, and checks `includeSubDomains` and `preload` directives.
* **Certificate Transparency (CT) Auditing:** Detects embedded Signed Certificate Timestamps (SCTs) required by modern browsers.
* **Automated Security Grading:** Computes an objective risk score (0-100) and assigns an intuitive letter grade (`A+`, `A`, `B`, `C`, `F`).
* **High-Throughput Parallel Scanning:** Utilizes multi-threading (`ThreadPoolExecutor`) for concurrent multi-domain and batch file auditing.
* **CI/CD-Ready Valid JSON:** Emits single objects or unified JSON arrays for automated security scanning pipelines without broken stream outputs.
* **Resilient Input Parser:** Automatically sanitizes full URLs (`https://`, `http://`), custom ports (`host:8443`), request paths (`domain.com/path`), and IPv6 addresses.

---

## Installation

### Prerequisites
* Python 3.8 or higher
* pip package manager

### Clone Repository and Install Dependencies

```bash
git clone https://github.com/tommyvercetti89/sslpy.git
cd sslpy

# Create a virtual environment (Recommended)
python -m venv venv
# Windows:
venv\Scripts\activate
# Linux/macOS:
source venv/bin/activate

# Install dependencies
pip install -r requirements.txt
```

### Install as a System Command (Optional)
To use `sslpy` globally from any directory:

```bash
pip install -e .
```

---

## Usage Guide

### 1. Single Domain or URL Inspection
```bash
python sslpy.py example.com
# or with full URL:
python sslpy.py https://example.com/
```

### 2. Custom Port Inspection
```bash
python sslpy.py example.com:8443
# or using the -p flag:
python sslpy.py example.com -p 8443
```

### 3. Concurrent Multi-Domain Inspection
```bash
python sslpy.py google.com github.com cloudflare.com
```

### 4. Batch Scanning from File
Inspect multiple domains concurrently using a target list:
```bash
python sslpy.py -f domains.example.txt
```

### 5. JSON Output Mode
Produces a single JSON object for single domains or a valid JSON array for multiple domains:
```bash
python sslpy.py -j example.com
python sslpy.py -j google.com github.com
```

### 6. Export Results to File
```bash
# Export audit report to a JSON file
python sslpy.py -j -f domains.example.txt -o report.json
```

### 7. Skip Certificate Verification (--no-verify)
Allows inspecting self-signed or untrusted certificates in testing environments:
```bash
python sslpy.py -n self-signed.badssl.com
```

### 8. Plain Text / No-Color Mode
Disables ANSI color sequences for automated logging or pipeline redirection:
```bash
python sslpy.py -b example.com
```

---

## CLI Parameter Reference

| Parameter | Flag | Description | Default |
| :--- | :--- | :--- | :--- |
| `domains` | | One or more domains or URLs to inspect | - |
| `--port` | `-p` | Target connection port number | `443` |
| `--file` | `-f` | Path to text file containing target list | - |
| `--json` | `-j` | Output results in valid JSON format | `False` |
| `--output` | `-o` | Save results to specified file path | - |
| `--timeout`| `-t` | Network connection timeout in seconds | `5` |
| `--no-verify` | `-n` | Skip Root CA trust and hostname verification | `False` |
| `--no-color` | `-b` | Disable ANSI terminal color codes | `False` |
| `--no-ocsp` | | Skip live OCSP revocation query | `False` |
| `--no-hsts` | | Skip HSTS transport security audit | `False` |
| `--verbose` | `-v` | Display detailed error outputs | `False` |

---

## Security Grading System

`sslpy` evaluates transport security and certificates against strict industry standards (0-100 scale):

* **[ A+ ] (95-100 Points):** Fully trusted root chain, >= 2048-bit keys, SHA-256+, TLS 1.3/1.2, long-term active HSTS, valid CT records, and clean OCSP status.
* **[ A ] (85-94 Points):** Strong cryptographic foundation with minor hardening recommendations (e.g. missing HSTS).
* **[ B ] (70-84 Points):** Certificate expiring within 30 days or insufficient HSTS max-age.
* **[ C ] (50-69 Points):** Sub-standard key lengths, expiry within 7 days, or multiple configuration flaws.
* **[ F ] (0-49 Points):** Untrusted root chain, expired certificate, revoked certificate, domain mismatch, or insecure legacy protocols (TLS 1.0/1.1).

---

## Sample Terminal Output

```text
╔════════════════════════════════════════════════════════════════════╗
║          sslpy v2.0 - Kapsamli SSL/TLS Denetleme Araci             ║
╚════════════════════════════════════════════════════════════════════╝

Platform: Linux 6.5 | Python: 3.11.8
Verification Mode: Full Trust Chain Verification Active

════════════════════════════════════════════════════════════════════
  sslpy v2.0 - COMPREHENSIVE SSL/TLS SECURITY AND AUDIT REPORT
════════════════════════════════════════════════════════════════════

[+] Target: example.com:443  (IP: 93.184.216.34)
    Scan Time: 0.42 seconds
    Security Grade: [ A+ ] (100/100 Points)
    Trust Status: [OK] TRUSTED (Verified by System Root CA Store)
    Certificate Status: [VALID] (124 days remaining)
    • Not Before: 2026-06-01T00:00:00+00:00
    • Not After:  2027-01-05T23:59:59+00:00

[+] Certificate Trust Chain (3 Certificates):
  ├─► [0] Server / Leaf: example.com
      Issuer: DigiCert Global G2 TLS RSA SHA256 2020 CA1 | Key: RSA 2048-bit | Remaining: 124 days
  ├─► [1] Intermediate CA: DigiCert Global G2 TLS RSA SHA256 2020 CA1
      Issuer: DigiCert Global Root G2 | Key: RSA 2048-bit | Remaining: 2190 days
  └─► [2] Root CA: DigiCert Global Root G2
      Issuer: DigiCert Global Root G2 | Key: RSA 2048-bit | Remaining: 5120 days

[+] Advanced Security Audits:
  • OCSP Revocation Status: [OK] VALID (GOOD) - Certificate is not revoked
  • HSTS Security: [OK] ACTIVE (max-age=31536000 [365.0 days], includeSubDomains, preload)
  • Certificate Transparency (CT): [OK] ACTIVE (2 embedded SCT log records)
  • TLS Protocol: TLSv1.3
  • Cipher Suite: TLS_AES_256_GCM_SHA384 (256-bit)

[+] Certificate & Public Key Details:
  • Serial Number: 0A38B2F891D4C82A4E0011C9902
  • Public Key: RSA 2048-bit
  • Signature Algorithm: sha256WithRSAEncryption
  • SHA-256 Fingerprint: E3B0C44298FC1C149AFBF4C8996FB92427AE41E4649B934CA495991B7852B855
  • SAN DNS (2 domains): example.com, www.example.com

[OK] Excellent: No critical security vulnerabilities or configuration defects detected.
────────────────────────────────────────────────────────────────────
```

---

## CI/CD Pipeline Integration

`sslpy` can be seamlessly embedded into CI/CD workflows for pre-deployment checks or scheduled cron audits.

Example GitHub Actions Workflow:
```yaml
name: SSL Security Audit

on:
  schedule:
    - cron: '0 0 * * 1' # Every Monday
  workflow_dispatch:

jobs:
  ssl-audit:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - name: Set up Python
        uses: actions/setup-python@v5
        with:
          python-version: '3.11'
      - name: Install dependencies
        run: pip install -r requirements.txt
      - name: Run sslpy inspection
        run: python sslpy.py -j example.com -o ssl_audit.json
      - name: Upload audit artifact
        uses: actions/upload-artifact@v4
        with:
          name: ssl-report
          path: ssl_audit.json
```

---

## License

This project is licensed under the [MIT License](LICENSE). Refer to `LICENSE` for details.
