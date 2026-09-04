# sslpy

Kapsamlı SSL/TLS Sertifika Güvenlik ve Denetim Aracı.

`sslpy`, hedef web sunucularının SSL/TLS sertifikalarını, güven zincirlerini, kriptografik yapılarını ve güvenlik başlıklarını analiz eden, CA (Certificate Authority) doğrulamasını gerçekleştiren ve sonuçları kurumsal standartlarda raporlayan bir komut satırı (CLI) aracıdır.

---

## Temel Özellikler

* **Tam Güven Zinciri Doğrulaması:** Sunucunun sağladığı sertifikanın işletim sistemi kök deposundaki güvenilir Kök Otoriteler (Root CA) tarafından imzalanıp imzalanmadığını ve alan adı eşleşmesini (`check_hostname`) denetler.
* **Ayrıntılı Zincir Analizi (Chain Inspection):** Yaprak sertifikadan (Leaf), Ara Sertifika Otoritelerine (Intermediate CA) ve Kök Sertifikaya (Root CA) kadar tüm basamakları ayrıştırır.
* **OCSP İptal Denetimi:** Sertifika Otoritesine (CA) canlı OCSP sorgusu göndererek sertifikanın iptal edilip edilmediğini (Revocation Status: GOOD / REVOKED) anlık denetler.
* **HSTS Güvenlik Analizi:** HTTP Strict Transport Security başlığını, `max-age` süresini, `includeSubDomains` ve `preload` direktiflerini kontrol eder.
* **Certificate Transparency (CT) Tespiti:** Sertifikaya gömülü SCT (Signed Certificate Timestamp) log kayıtlarını denetler.
* **Zafiyet ve Risk Skoru:** 0-100 puan aralığında puanlama yaparak sunucuya A+, A, B, C veya F harf notu verir.
* **Paralel Tarama:** Çoklu domain veya dosya taramalarında iş parçacıkları (ThreadPoolExecutor) ile yüksek hızda asenkron çalışır.
* **CI/CD Uyumlu JSON Modu:** Otomasyonlar ve güvenlik boru hatları (pipeline) için tekil veya dizi formatında geçerli JSON çıktısı üretir.
* **Esnek Girdi Ayrıştırıcı:** `https://`, `http://`, portlu ifadeler (`host:8443`), alt dizinler (`domain.com/path`) ve IPv6 adreslerini otomatik temizler.

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

### 2. Özel Port Belirterek Tarama
```bash
python sslpy.py example.com:8443
# veya -p parametresi ile:
python sslpy.py example.com -p 8443
```

### 3. Birden Fazla Hedefi Aynı Anda Tarama
```bash
python sslpy.py google.com github.com cloudflare.com
```

### 4. Dosyadan Toplu Tarama
`domains.txt` dosyası içerisindeki alan adlarını paralel olarak denetler:
```bash
python sslpy.py -f domains.example.txt
```

### 5. JSON Formatında Çıktı Alma
Tekil domain için JSON nesnesi, çoklu domain için standart JSON dizisi üretir:
```bash
python sslpy.py -j example.com
python sslpy.py -j google.com github.com
```

### 6. Sonuçları Dosyaya Kaydetme
```bash
# JSON raporunu dosyaya kaydet
python sslpy.py -j -f domains.example.txt -o rapor.json
```

### 7. Sertifika Doğrulamasını Atlatma (--no-verify)
Test ortamlarında veya kendinden imzalı (self-signed) sertifikaları incelemek için:
```bash
python sslpy.py -n self-signed.badssl.com
```

### 8. Renksiz Çıktı Modu
Otomasyon veya log dosyalarına aktarımda ANSI renk kodlarını kapatmak için:
```bash
python sslpy.py -b example.com
```

---

## Parametre Referansı

| Parametre | Kısa Yol | Açıklama | Varsayılan |
| :--- | :--- | :--- | :--- |
| `domains` | | Taranacak bir veya birden fazla alan adı / URL | - |
| `--port` | `-p` | Hedef bağlantı port numarası | `443` |
| `--file` | `-f` | Hedef listesi içeren dosya yolu | - |
| `--json` | `-j` | Geçerli JSON formatında çıktı üret | `False` |
| `--output` | `-o` | Sonuçların yazılacağı çıktı dosyası | - |
| `--timeout`| `-t` | Bağlantı zaman aşımı süresi (saniye) | `5` |
| `--no-verify` | `-n` | Kök CA güven doğrulamasını atla | `False` |
| `--no-color` | `-b` | Renkli terminal çıktısını devre dışı bırak | `False` |
| `--no-ocsp` | | Canlı OCSP iptal sorgusunu atla | `False` |
| `--no-hsts` | | HSTS başlık denetimini atla | `False` |
| `--verbose` | `-v` | Ayrıntılı hata kayıtlarını göster | `False` |

---

## Güvenlik Derecelendirme Sistemi (Grading)

`sslpy`, sertifikayı ve bağlantıyı endüstri standartlarına göre puanlar (0-100 aralığı):

* **[ A+ ] (95-100 Puan):** Tam güvenilir kök zinciri, en az 2048-bit anahtar, SHA-256+, TLS 1.3/1.2, HSTS aktif ve uzun süreli, CT logları mevcut, OCSP durumu temiz.
* **[ A ] (85-94 Puan):** Güvenilir zincir ve güçlü şifreleme, HSTS eksikliği veya küçük iyileştirme alanları.
* **[ B ] (70-84 Puan):** Sertifika süresinin dolmasına 30 günden az kalması veya kısa HSTS süresi.
* **[ C ] (50-69 Puan):** Zayıf anahtar boyutu, 7 günden az kalan süre veya birden fazla yapılandırma eksikliği.
* **[ F ] (0-49 Puan):** Geçersiz/Güvensiz kök CA, süresi dolmuş sertifika, iptal edilmiş (Revoked) sertifika, alan adı uyumsuzluğu veya güvensiz TLS sürümü (TLS 1.0/1.1).

---

## Örnek Terminal Rapor Çıktısı

```text
╔════════════════════════════════════════════════════════════════════╗
║          sslpy v2.0 - Kapsamlı SSL/TLS Denetleme Aracı             ║
╚════════════════════════════════════════════════════════════════════╝

Platform: Linux 6.5 | Python: 3.11.8
Doğrulama Modu: Tam Güven Zinciri Doğrulaması Aktif

════════════════════════════════════════════════════════════════════
  sslpy v2.0 - KAPSAMLI SSL/TLS GÜVENLİK VE DENETİM RAPORU
════════════════════════════════════════════════════════════════════

[+] Hedef: example.com:443  (IP: 93.184.216.34)
    Tarama Süresi: 0.42 saniye
    Güvenlik Derecesi: [ A+ ] (100/100 Puan)
    Doğrulama Durumu: [OK] GÜVENİLİR (Sistem Kök Sertifika Zinciri Doğrulandı)
    Sertifika Durumu: [GEÇERLİ] (124 gün kaldı)
    • Başlangıç: 2026-06-01T00:00:00+00:00
    • Bitiş:     2027-01-05T23:59:59+00:00

[+] Sertifika Güven Zinciri (3 Sertifika):
  ├─► [0] Sunucu / Yaprak (Leaf): example.com
      İmzalayan: DigiCert Global G2 TLS RSA SHA256 2020 CA1 | Anahtar: RSA 2048-bit | Kalan: 124 gün
  ├─► [1] Ara Sertifika Otoritesi (Intermediate CA): DigiCert Global G2 TLS RSA SHA256 2020 CA1
      İmzalayan: DigiCert Global Root G2 | Anahtar: RSA 2048-bit | Kalan: 2190 gün
  └─► [2] Kök Sertifika Otoritesi (Root CA): DigiCert Global Root G2
      İmzalayan: DigiCert Global Root G2 | Anahtar: RSA 2048-bit | Kalan: 5120 gün

[+] İleri Düzey Güvenlik Denetimleri:
  • OCSP İptal Durumu: [OK] GEÇERLİ (GOOD) - Sertifika iptal edilmemiş
  • HSTS Güvenliği: [OK] AKTİF (max-age=31536000 [365.0 gün], includeSubDomains, preload)
  • Certificate Transparency (CT): [OK] AKTİF (2 adet gömülü SCT kaydı)
  • TLS Protokolü: TLSv1.3
  • Cipher Suite: TLS_AES_256_GCM_SHA384 (256-bit)

[+] Sertifika ve Anahtar Detayları:
  • Seri No: 0A38B2F891D4C82A4E0011C9902
  • Açık Anahtar: RSA 2048-bit
  • İmza Algoritması: sha256WithRSAEncryption
  • SHA-256 Parmak İzi: E3B0C44298FC1C149AFBF4C8996FB92427AE41E4649B934CA495991B7852B855
  • SAN DNS (2 adet): example.com, www.example.com

[OK] Mükemmel: Kritik bir güvenlik açığı veya konfigürasyon hatası tespit edilmedi.
────────────────────────────────────────────────────────────────────
```

---

## CI/CD Pipeline Entegrasyonu

`sslpy`, CI/CD süreçlerinde deployment öncesi veya periyodik cron kontrollerinde sertifika sağlığını denetlemek için kullanılabilir.

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
        run: python sslpy.py -j example.com -o ssl_audit.json
      - name: Archive audit report
        uses: actions/upload-artifact@v4
        with:
          name: ssl-report
          path: ssl_audit.json
```

---

## Lisans

Bu proje [MIT Lisansı](LICENSE) ile lisanslanmıştır. Ayrıntılar için `LICENSE` dosyasına başvurunuz.
