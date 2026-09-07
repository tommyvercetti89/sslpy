[ Read in English ](README.en.md) | [ Türkçe Oku ](README.md)

---

# sslpy v2.0

Kapsamlı SSL/TLS Sertifika Güvenlik, Kriptografi ve Ağ Denetim Aracı.

`sslpy`, hedef web sunucularının ve e-posta/dizin servislerinin SSL/TLS sertifikalarını, tam güven zincirlerini, kriptografik yapılarını, DNS CAA kayıtlarını, CRL/OCSP iptal durumlarını ve web güvenlik başlıklarını derinlemesine analiz eden, CA (Certificate Authority) doğrulamasını gerçekleştiren ve sonuçları modern HTML, CSV, Markdown ve JSON formatlarında raporlayan güçlü bir komut satırı (CLI) aracıdır.

---

## Temel Özellikler

* **Tam Güven Zinciri Doğrulaması:** Sunucunun sağladığı sertifikanın işletim sistemi kök deposundaki güvenilir Kök Otoriteler (Root CA) veya özel CA paketi (`--ca-bundle`) tarafından imzalanıp imzalanmadığını ve alan adı eşleşmesini (`check_hostname`) denetler.
* **Ayrıntılı Zincir Analizi (Chain Inspection):** Yaprak sertifikadan (Leaf), Ara Sertifika Otoritelerine (Intermediate CA) ve Kök Sertifikaya (Root CA) kadar tüm basamakları (Anahtar tipi, boyutu, kalan gün, imzalayan) hiyerarşik olarak listeler.
* **Protokol ve El Sıkışma Matrisi (Handshake Matrix):** TLS 1.0, TLS 1.1, TLS 1.2 ve modern TLS 1.3 sürümlerini hedef sunucuyla bağımsız el sıkışmalar yaparak tek tek test eder; güvensiz sürümleri anında tespit eder.
* **STARTTLS ve Web Dışı Protokol Desteği:** HTTPS dışındaki kritik servisler için (`SMTP`, `IMAP`, `POP3`, `FTP`, `LDAP`) şifrelenmemiş soket üzerinde protokol el sıkışması başlatarak TLS katmanına geçişi (STARTTLS) ve port otomatik uyarlamasını sağlar.
* **DNS CAA Kayıt Doğrulaması (RFC 6844):** Domain ve üst domainler üzerinde DNS CAA kayıtlarını ağaç tırmanışı (tree-climbing) ile sorgular; sertifikayı imzalayan CA'nın (Issuer) yetkili listede bulunup bulunmadığını denetler.
* **Çift Katmanlı Canlı İptal Denetimi (OCSP & CRL):**
  - **OCSP (Online Certificate Status Protocol):** CA sunucusuna anlık sorgu göndererek iptal durumunu kontrol eder.
  - **CRL (Certificate Revocation List):** Sertifikadaki CRL Dağıtım Noktalarından (CDP) DER/PEM iptal listesini indirip sertifika seri numarasının iptal edilip edilmediğini doğrular.
* **Kapsamlı Web Güvenlik Başlıkları:**
  - HSTS (Strict-Transport-Security, max-age, includeSubDomains, preload)
  - Content-Security-Policy (CSP)
  - X-Frame-Options (Clickjacking koruması)
  - X-Content-Type-Options (nosniff)
  - Referrer-Policy & Permissions-Policy (`--all-headers` ile)
* **Kurumsal Ağ ve Ağ Esnekliği:**
  - **Özel SNI (`--sni`):** CDN, WAF, Cloudflare arkasındaki veya doğrudan IP adresli hedeflere özel Server Name Indication başlığı gönderir.
  - **Özel CA Paketi (`--ca-bundle`):** Kurumsal iç ağlarda (Intranet) veya özel PKI/AD CS mimarilerinde dahili kök sertifika doğrulaması sağlar.
  - **HTTP CONNECT Proxy (`--proxy`):** Kurumsal proxy veya tünel arkasından SSL/TLS soket tünellemesi yapar.
* **Zengin Çoklu Format Raporlama:**
  - **İnteraktif Dark-Mode HTML Paneli (`-o rapor.html`):** Filtrelenebilir, canlı arama destekli, tek dosyada çalışan şık dashboard.
  - **Excel Uyumlu CSV (`-o rapor.csv`):** UTF-8 BOM destekli, Türkçe karakterleri bozmayan tablo çıktısı.
  - **GitHub Uyumlu Markdown (`-o rapor.md`):** Dokümantasyonlar, PR özetleri ve issue bildirimleri için zengin tablolar ve GitHub Alert kutuları.
  - **Makine Okunabilir JSON (`-j` / `-o rapor.json`):** CI/CD boru hatları ve SIEM entegrasyonu için.
* **ALPN & HTTP/2 Desteği:** Sunucunun Application-Layer Protocol Negotiation desteğini ve HTTP/2 (`h2`) protokolünü doğrular.
* **Cipher Analizi & Perfect Forward Secrecy (PFS):** Aktif şifreleme kümesini (Key Exchange, Bulk Encryption, MAC) analiz eder ve Forward Secrecy (PFS) durumunu doğrular.
* **Eski/Zayıf Şifreleme Probları:** Sunucunun PFS desteği bulunmayan statik RSA (`kRSA`) veya CBC modu şifreleme kümelerini kabul edip etmediğini denetler.
* **Certificate Transparency (CT) Tespiti:** Sertifikaya gömülü SCT (Signed Certificate Timestamp) log kayıtlarını denetler.
* **Zafiyet ve Risk Skoru:** 0-100 puan aralığında puanlama yaparak sunucuya A+, A, B, C veya F harf notu verir.
* **Paralel Tarama:** Çoklu domain veya dosya taramalarında iş parçacıkları (`ThreadPoolExecutor`) ile yüksek hızda asenkron çalışır.

---

## Kurulum

### Gereksinimler
* Python 3.8 veya üzeri
* pip paket yöneticisi

### Depoyu Klonlama ve Bağımlılıkları Yükleme

```bash
git clone https://github.com/tommyvercetti89/sslpy.git
cd sslpy

# Sanal ortam oluşturma (Önerilen)
python -m venv venv
# Windows:
venv\Scripts\activate
# Linux/macOS:
source venv/bin/activate

# Bağımlılıkların yüklenmesi
pip install -r requirements.txt
```

### Projeyi Komut Olarak Yükleme (Opsiyonel)
Projeyi sistem genelinde doğrudan `sslpy` komutuyla çalıştırmak için:

```bash
pip install -e .
```

---

## Kullanım Rehberi

### 1. Tekil Domain veya URL Analizi
```bash
python sslpy.py example.com
# veya tam URL ile:
python sslpy.py https://example.com/
```

### 2. STARTTLS ile E-Posta ve Dizin Sunucularını Tarama
Belirtilen protokole uygun başlangıç portu otomatik seçilir (örn. SMTP için 587, IMAP için 143):
```bash
# SMTP Sunucusu (Varsayılan Port: 587)
python sslpy.py smtp.gmail.com --starttls smtp

# IMAP Sunucusu (Varsayılan Port: 143)
python sslpy.py mail.kurum.com --starttls imap

# Özel port ile POP3 veya LDAP:
python sslpy.py pop.kurum.com -p 110 --starttls pop3
python sslpy.py ldap.kurum.local -p 389 --starttls ldap
```

### 3. Özel SNI ve Doğrudan IP Taraması
CDN/WAF arkasındaki sunucuları veya IP adreslerini hedeflerken doğru sertifikanın sunulmasını sağlayın:
```bash
python sslpy.py 140.82.121.4 --sni github.com
```

### 4. Kurumsal Ağ ve Proxy / Özel CA Kullanımı
```bash
# Kurumsal HTTP CONNECT Proxy üzerinden tarama
python sslpy.py github.com --proxy http://proxy.sirket.local:8080

# Kurumsal Dahili Kök CA Paketi ile doğrulama
python sslpy.py intranet.sirket.local --ca-bundle /path/to/corporate-ca.pem
```

### 5. Birden Fazla Hedefi Toplu Tarama
```bash
python sslpy.py google.com github.com cloudflare.com
# veya dosyadan toplu liste:
python sslpy.py -f domains.example.txt
```

### 6. Çoklu Format Raporlama (HTML, CSV, Markdown, JSON)
Dosya uzantısına göre format otomatik algılanır veya açık parametre kullanılabilir:

```bash
# İnteraktif Dark-Mode HTML Dashboard üret
python sslpy.py -f domains.example.txt -o denetim_raporu.html

# Excel Uyumlu CSV (UTF-8 BOM) üret
python sslpy.py google.com github.com -o sonuc.csv

# GitHub Uyumlu Markdown Tablo ve Uyarı Raporu üret
python sslpy.py example.com -o ozet.md

# Otomasyonlar için JSON Çıktısı
python sslpy.py -j example.com -o sonuc.json
```

### 7. Hızlı Tarama Modu (--no-matrix)
Protokol matrisi ve cipher testlerini atlayarak sertifika, zincir, OCSP/CRL, DNS CAA ve HSTS kontrollerini 1 saniyenin altında tamamlar:
```bash
python sslpy.py example.com --no-matrix
```

### 8. Gelişmiş Web Güvenlik Başlıkları Analizi
Standart başlıklara ek olarak Referrer-Policy ve Permissions-Policy denetimini de rapora dahil etmek için:
```bash
python sslpy.py example.com --all-headers
```

### 9. Sertifika Doğrulamasını Atlatma (--no-verify)
Test ortamlarında veya kendinden imzalı (self-signed) sertifikaları incelemek için:
```bash
python sslpy.py -n self-signed.badssl.com
```

---

## Parametre Referansı

| Parametre | Kısa Yol | Açıklama | Varsayılan |
| :--- | :--- | :--- | :--- |
| `domains` | | Taranacak bir veya birden fazla alan adı / IP / URL | - |
| `--port` | `-p` | Hedef bağlantı port numarası | `443` (STARTTLS varsa protokole özel) |
| `--file` | `-f` | Hedef listesi içeren metin dosyası yolu | - |
| `--starttls` | | STARTTLS el sıkışması (`smtp`, `imap`, `pop3`, `ftp`, `ldap`) | - |
| `--sni` | | TLS el sıkışmasında gönderilecek özel Server Name Indication (SNI) | Hedef domain |
| `--ca-bundle` | | Özel/kurumsal Kök CA sertifika paketi yolu (PEM) | Sistem Kök Deposu |
| `--proxy` | | HTTP CONNECT vekilleri için proxy URL (`http://proxy:8080`) | - |
| `--all-headers`| | Tüm güvenlik başlıklarını denetle (CSP, XFO, Referrer, Permissions) | `False` |
| `--no-caa` | | DNS CAA (RFC 6844) kayıt doğrulamasını atla | `False` |
| `--no-crl` | | CRL (Certificate Revocation List) iptal denetimini atla | `False` |
| `--no-ocsp` | | Canlı OCSP iptal sorgusunu atla | `False` |
| `--no-hsts` | | HSTS başlık denetimini atla | `False` |
| `--no-matrix` | | Protokol matrisi ve zayıf şifreleme testlerini atla | `False` |
| `--no-verify` | `-n` | Kök CA güven doğrulamasını atla | `False` |
| `--no-color` | `-b` | Renkli terminal çıktısını devre dışı bırak | `False` |
| `--html` | | Çıktıyı modern interaktif HTML dashboard formatında kaydet | `False` |
| `--csv` | | Çıktıyı Excel uyumlu CSV (UTF-8 BOM) formatında kaydet | `False` |
| `--markdown` | | Çıktıyı GitHub uyumlu Markdown formatında kaydet | `False` |
| `--json` | `-j` | Geçerli JSON formatında çıktı üret | `False` |
| `--output` | `-o` | Sonuçların yazılacağı dosya yolu (uzantıdan formatı otomatik tanır) | - |
| `--timeout` | `-t` | Bağlantı zaman aşımı süresi (saniye) | `5` |
| `--verbose` | `-v` | Ayrıntılı hata kayıtlarını göster | `False` |

---

## Güvenlik Derecelendirme Sistemi (Grading)

`sslpy`, sertifikayı ve bağlantıyı endüstri standartlarına (SSL Labs & NIST ilkeleri) göre puanlar (0-100 aralığı):

* **[ A+ ] (95-100 Puan):** Tam güvenilir kök zinciri, en az 2048-bit RSA veya 256-bit EC anahtar, SHA-256+, modern TLS 1.3 desteği, TLS 1.0/1.1'in tamamen kapalı olması, Perfect Forward Secrecy (PFS) aktifliği, HSTS aktif ve uzun süreli, DNS CAA onaylı, OCSP/CRL geçerli, CT logları mevcut.
* **[ A ] (85-94 Puan):** Güvenilir zincir ve güçlü şifreleme, TLS 1.0/1.1 kapalı, HSTS eksikliği veya küçük başlık yapılandırma eksiklikleri.
* **[ B ] (70-84 Puan):** Sertifika süresinin dolmasına 30 günden az kalması, kısa HSTS süresi, DNS CAA uyuşmazlığı veya modern TLS 1.3 desteğinin olmaması.
* **[ C ] (50-69 Puan):** Zayıf anahtar boyutu, 7 günden az kalan süre, eski cipher desteği veya birden fazla güvenlik yapılandırma eksikliği.
* **[ F ] (0-49 Puan):** Kullanımdan kaldırılmış güvensiz TLS sürümlerinin açık olması (TLS 1.0 / TLS 1.1), geçersiz/güvensiz kök CA, süresi dolmuş veya iptal edilmiş (Revoked) sertifika, alan adı uyumsuzluğu veya kırılmış şifreleme.

---

## Örnek Terminal Rapor Çıktısı

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

## CI/CD Pipeline Entegrasyonu

`sslpy`, CI/CD süreçlerinde deployment öncesi veya periyodik cron kontrollerinde sertifika ve ağ güvenliğini denetlemek için kullanılabilir.

Örnek GitHub Actions Adımı:
```yaml
name: SSL Security Audit

on:
  schedule:
    - cron: '0 0 * * 1' # Her pazartesi
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

## Lisans

Bu proje [MIT Lisansı](LICENSE) ile lisanslanmıştır. Ayrıntılar için `LICENSE` dosyasına başvurunuz.
