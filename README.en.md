[ Read in English ](README.en.md) | [ Türkçe Oku ](README.md)

---

# sslpy v2.0

Comprehensive SSL/TLS Certificate Security, Cryptographic & Network Auditing Tool.

`sslpy` is an enterprise-grade command-line (CLI) utility designed to perform deep inspection of SSL/TLS certificates, validate entire trust chains against system root stores or custom CA bundles, execute dual-layer revocation checks (OCSP & CRL), verify DNS CAA authorization (RFC 6844), audit modern HTTP transport security headers, and generate interactive HTML dashboards, Excel CSV, Markdown, and JSON reports.

---

## Key Features

* **Full Trust Chain Verification:** Validates the entire certificate path against operating system trusted Root CAs or enterprise custom CA bundles (`--ca-bundle`) and verifies hostname matching (`check_hostname`).
* **Deep Certificate Chain Analysis:** Inspects all chain tiers individually (Leaf, Intermediate CAs, and Root Trust Anchor) including public key algorithms, sizes, CA constraints, and remaining lifespans.
* **Protocol & Handshake Matrix:** Actively tests each TLS protocol version individually (TLS 1.0, TLS 1.1, TLS 1.2, and modern TLS 1.3) via dedicated concurrent handshakes to identify legacy/insecure protocol acceptance.
* **STARTTLS & Non-Web Protocol Support:** Establishes plaintext socket sessions and negotiates TLS upgrades (STARTTLS) for non-HTTPS services (`SMTP`, `IMAP`, `POP3`, `FTP`, `LDAP`) with automatic default port mapping.
* **DNS CAA Record Validation (RFC 6844):** Performs DNS CAA lookups using tree-climbing from the target domain up to parent domains, validating that the issuing CA is explicitly authorized to issue certificates.
* **Dual-Layer Real-Time Revocation Auditing (OCSP & CRL):**
  - **OCSP (RFC 6960):** Dispatches live requests to CA OCSP responders to determine revocation status (`GOOD` / `REVOKED`).
  - **CRL (Certificate Revocation List):** Downloads DER/PEM CRL files directly from Certificate Distribution Points (CDP) and scans for the serial number.
* **Extended Web Security Headers:**
  - HSTS (Strict-Transport-Security, max-age, includeSubDomains, preload)
  - Content-Security-Policy (CSP)
  - X-Frame-Options (Clickjacking protection)
  - X-Content-Type-Options (nosniff)
  - Referrer-Policy & Permissions-Policy (with `--all-headers`)
* **Enterprise Network Flexibility:**
  - **Custom SNI (`--sni`):** Sends custom Server Name Indication values when auditing CDN/WAF fronted sites or direct IP targets.
  - **Custom CA Bundle (`--ca-bundle`):** Allows auditing internal enterprise servers, Intranet portals, or private PKIs with custom Root CAs.
  - **HTTP CONNECT Proxy (`--proxy`):** Supports socket tunneling through corporate forward proxies.
* **Rich Multi-Format Exporters:**
  - **Interactive Dark-Mode HTML Dashboard (`-o report.html`):** Standalone, single-file responsive dashboard with KPI summary cards, search filter, and collapsible detail views.
  - **Excel-Compatible CSV (`-o report.csv`):** Formatted with UTF-8 BOM (`utf-8-sig`) for direct compatibility with spreadsheet software.
  - **GitHub-Flavored Markdown (`-o report.md`):** High-readability tables and callout alert boxes for PR summaries, issues, and wikis.
  - **CI/CD-Ready JSON (`-j` / `-o report.json`):** Unified JSON arrays for automated security scanning pipelines.
* **ALPN & HTTP/2 Detection:** Audits Application-Layer Protocol Negotiation (ALPN) and verifies HTTP/2 (`h2`) protocol support.
* **Cipher Suite Analysis & Perfect Forward Secrecy (PFS):** Breaks down negotiated cipher suites (Key Exchange, Bulk Encryption, MAC) and confirms Perfect Forward Secrecy (PFS) enforcement.
* **Legacy & Weak Cipher Probing:** Tests whether the server accepts non-PFS static RSA (`kRSA`) or legacy CBC-mode cipher suites.
* **Certificate Transparency (CT) Auditing:** Detects embedded Signed Certificate Timestamps (SCTs) required by modern browsers.
* **Automated Security Grading:** Computes an objective risk score (0-100) and assigns an intuitive letter grade (`A+`, `A`, `B`, `C`, `F`).
* **High-Throughput Parallel Scanning:** Utilizes multi-threading (`ThreadPoolExecutor`) for concurrent multi-domain and batch file auditing.

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

### 1. Single Domain or URL Audit
```bash
python sslpy.py example.com
# or with full URL:
python sslpy.py https://example.com/
```

### 2. STARTTLS Mail and Directory Server Inspection
Automatically adapts default ports (e.g., SMTP -> 587, IMAP -> 143):
```bash
# SMTP Server (Default Port: 587)
python sslpy.py smtp.gmail.com --starttls smtp

# IMAP Server (Default Port: 143)
python sslpy.py mail.company.com --starttls imap

# Custom Port with POP3 or LDAP:
python sslpy.py pop.company.com -p 110 --starttls pop3
python sslpy.py ldap.company.local -p 389 --starttls ldap
```

### 3. Custom SNI and Direct IP Audits
Target raw IP addresses behind CDNs or load balancers while sending the expected domain header:
```bash
python sslpy.py 140.82.121.4 --sni github.com
```

### 4. Corporate Proxies and Custom CA Bundles
```bash
# Route audit through corporate HTTP CONNECT proxy
python sslpy.py github.com --proxy http://proxy.corp.local:8080

# Audit internal servers using private root certificates
python sslpy.py intranet.corp.local --ca-bundle /path/to/corporate-ca.pem
```

### 5. Multi-Target Batch Auditing
```bash
python sslpy.py google.com github.com cloudflare.com
# or from a file list:
python sslpy.py -f domains.example.txt
```

### 6. Multi-Format Reporting (HTML, CSV, Markdown, JSON)
Output format is auto-detected based on file extension, or set explicitly via flags:

```bash
# Interactive Dark-Mode HTML Dashboard
python sslpy.py -f domains.example.txt -o audit_report.html

# Excel-Compatible CSV (UTF-8 BOM)
python sslpy.py google.com github.com -o results.csv

# GitHub Markdown Summary Table
python sslpy.py example.com -o summary.md

# Pipeline JSON Output
python sslpy.py -j example.com -o results.json
```

### 7. Fast Scan Mode (--no-matrix)
Skips the exhaustive cipher matrix for sub-second certificate, revocation, CAA, and header validation:
```bash
python sslpy.py example.com --no-matrix
```

### 8. Extended Security Headers Audit
Audits Permissions-Policy and Referrer-Policy alongside CSP, X-Frame-Options, and nosniff:
```bash
python sslpy.py example.com --all-headers
```

### 9. Bypass Verification for Self-Signed Certs
```bash
python sslpy.py -n self-signed.badssl.com
```

---

## Parameter Reference

| Parameter | Short | Description | Default |
| :--- | :--- | :--- | :--- |
| `domains` | | One or more domains / IPs / URLs to inspect | - |
| `--port` | `-p` | Target port number | `443` (or STARTTLS protocol default) |
| `--file` | `-f` | Path to text file containing target list | - |
| `--starttls` | | STARTTLS protocol (`smtp`, `imap`, `pop3`, `ftp`, `ldap`) | - |
| `--sni` | | Custom Server Name Indication (SNI) string | Target domain |
| `--ca-bundle` | | Path to custom CA bundle file in PEM format | System Trust Store |
| `--proxy` | | HTTP CONNECT proxy URL (`http://proxy:8080`) | - |
| `--all-headers`| | Audit extended security headers (CSP, XFO, Referrer, Permissions) | `False` |
| `--no-caa` | | Skip DNS CAA (RFC 6844) authorization lookup | `False` |
| `--no-crl` | | Skip CRL (Certificate Revocation List) download and check | `False` |
| `--no-ocsp` | | Skip real-time OCSP revocation query | `False` |
| `--no-hsts` | | Skip HSTS header audit | `False` |
| `--no-matrix` | | Skip protocol matrix and legacy cipher tests | `False` |
| `--no-verify` | `-n` | Skip Root CA trust chain verification | `False` |
| `--no-color` | `-b` | Disable ANSI color sequences in console output | `False` |
| `--html` | | Save report as an interactive HTML dashboard | `False` |
| `--csv` | | Save report as Excel-compatible CSV (UTF-8 BOM) | `False` |
| `--markdown` | | Save report as GitHub-flavored Markdown | `False` |
| `--json` | `-j` | Output valid JSON to stdout | `False` |
| `--output` | `-o` | Output filepath (auto-detects `.html`, `.csv`, `.md`, `.json`) | - |
| `--timeout` | `-t` | Socket timeout in seconds | `5` |
| `--verbose` | `-v` | Show detailed tracebacks and debug logs | `False` |

---

## Security Grading System

`sslpy` evaluates targets against industry standards (SSL Labs & NIST guidelines) on a 0-100 scale:

* **[ A+ ] (95-100 Points):** Verified root chain, >=2048-bit RSA or >=256-bit EC, SHA-256+, modern TLS 1.3 support, TLS 1.0/1.1 disabled, Perfect Forward Secrecy (PFS), long-duration HSTS, DNS CAA authorized, OCSP/CRL valid, embedded CT logs.
* **[ A ] (85-94 Points):** Valid trust chain, strong ciphers, TLS 1.0/1.1 disabled, missing HSTS or minor header recommendations.
* **[ B ] (70-84 Points):** Certificate expiring in <30 days, short HSTS duration, DNS CAA mismatch, or missing modern TLS 1.3 support.
* **[ C ] (50-69 Points):** Sub-optimal key lengths, <7 days remaining, legacy cipher acceptance, or multiple configuration omissions.
* **[ F ] (0-49 Points):** Obsolete TLS protocols enabled (TLS 1.0 / TLS 1.1), untrusted/invalid Root CA, expired/revoked certificate, hostname mismatch, or broken cryptography.

---

## Sample Terminal Output

```text
╔════════════════════════════════════════════════════════════════════╗
║          sslpy v2.0 - Kapsamlı SSL/TLS Denetleme Aracı             ║
╚════════════════════════════════════════════════════════════════════╝

Platform: Windows 10 | Python: 3.13.7
Doğrulama Modu: Tam Güven Zinciri Doğrulaması Aktif
Protokol Matrisi: Aktif (TLS 1.0 - 1.3 & Şifreleme Analizi)

════════════════════════════════════════════════════════════════════
  sslpy v2.0 - KAPSAMLI SSL/TLS GÜVENLİK VE DENETİM RAPORU
════════════════════════════════════════════════════════════════════

[+] Hedef: github.com:443  (IP: 140.82.121.4)
    Tarama Süresi: 2.15 saniye
    Güvenlik Derecesi: [ A+ ] (100/100 Puan)
    Doğrulama Durumu: [OK] GÜVENİLİR (Sistem Kök Sertifika Zinciri Doğrulandı)
    Sertifika Durumu: [GEÇERLİ] (83 gün kaldı)
    • Başlangıç: 2026-09-01T00:00:00+00:00
    • Bitiş:     2026-11-29T23:59:59+00:00

[+] Sertifika Güven Zinciri (3 Sertifika):
  ├─► [0] Sunucu / Yaprak (Leaf): github.com
      İmzalayan: Sectigo Public Server Authentication CA DV E36 | Anahtar: EC 256-bit | Kalan: 83 gün
  ├─► [1] Ara Sertifika Otoritesi (Intermediate CA): Sectigo Public Server Authentication CA DV E36
      İmzalayan: Sectigo Public Server Authentication Root E46 | Anahtar: EC 256-bit | Kalan: 3483 gün
  └─► [2] Kök Sertifika Otoritesi (Root CA): Sectigo Public Server Authentication Root E46
      İmzalayan: Sectigo Public Server Authentication Root E46 | Anahtar: EC 384-bit | Kalan: 7135 gün

[+] Protokol ve Şifreleme Matrisi (Handshake Matrix):
  • TLS Protokol Desteği:
    ├─► TLS 1.0: [KAPALI - GÜVENLİ]
    ├─► TLS 1.1: [KAPALI - GÜVENLİ]
    ├─► TLS 1.2: [AÇIK] (ECDHE-ECDSA-AES128-GCM-SHA256)
    └─► TLS 1.3: [AÇIK - EN YÜKSEK GÜVENLİK] (TLS_AES_128_GCM_SHA256)
  • ALPN Protokolü: [OK] HTTP/2 (h2) Aktif
  • Perfect Forward Secrecy (PFS): [OK] AKTİF (ECDHE / DHE (TLS 1.3 Ephemeral))
  • Aktif Şifreleme Kümesi: TLS_AES_128_GCM_SHA256 (128-bit)
    Anahtar Değişimi: ECDHE / DHE (TLS 1.3 Ephemeral) | Simetrik: AES-GCM (128-bit) | MAC: AEAD (Authenticated Encryption)

[+] İleri Düzey Güvenlik Denetimleri:
  • OCSP İptal Durumu: [OK] GEÇERLİ (GOOD) - Sertifika iptal edilmemiş
  • CRL İptal Listesi: [INFO] Sertifikada CRL adresi tanımlı değil
  • DNS CAA Kayıtları: [OK] Aktif (7 kayıt) - Düzenleyici CA (Sectigo Limited) onaylı
  • HSTS Güvenliği: [OK] AKTİF (max-age=31536000 [365.0 gün], includeSubDomains, preload)
  • Web Güvenlik Başlıkları:
    ├─► Content-Security-Policy (CSP): [OK] AKTİF
    ├─► X-Frame-Options (Clickjacking): [OK] DENY
    └─► X-Content-Type-Options:         [OK] nosniff
  • Certificate Transparency (CT): [OK] AKTİF (2 adet gömülü SCT kaydı)

[+] Sertifika ve Anahtar Detayları:
  • Seri No: A59EBDB596751DB7F5C095079613953C
  • Açık Anahtar: EC 256-bit
  • İmza Algoritması: ecdsa-with-SHA256
  • SHA-256 Parmak İzi: 46B601EE08B418CF8A3A1EBFE670BA5CE43BB05A917FA8B2DD087A30471CFC63
  • SAN DNS (2 adet): github.com, www.github.com

[!] Güvenlik Bulguları ve İyileştirmeler:
  [BİLGİ] DNS CAA Güvenliği: CAA kaydı mevcut (7 kayıt) ve aktif CA ile eşleşiyor.
────────────────────────────────────────────────────────────────────
```

---

## CI/CD Pipeline Integration

```yaml
name: SSL Security Audit

on:
  schedule:
    - cron: '0 0 * * 1' # Every Monday
  workflow_dispatch:

jobs:
  ssl-check:
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
        run: |
          python sslpy.py -f domains.example.txt -o audit_report.html
          python sslpy.py -f domains.example.txt -j -o audit_report.json
      - name: Archive audit reports
        uses: actions/upload-artifact@v4
        with:
          name: ssl-reports
          path: |
            audit_report.html
            audit_report.json
```

---

## License

This project is licensed under the [MIT License](LICENSE). Refer to `LICENSE` for terms.
