# sslpy

Kapsamli SSL/TLS Sertifika Guvenlik ve Denetim Araci.

`sslpy`, hedef web sunucularinin SSL/TLS sertifikalarini, guven zincirlerini, kriptografik yapilarini ve guvenlik basliklarini analiz eden, CAP (Certificate Authority) dogrulamasi gerceklestiren ve sonuclari kurumsal standartlarda raporlayan bir komut satiri (CLI) aracidir.

---

## Temel Ozellikler

* **Tam Guven Zinciri Dogrulamasi:** Sunucunun sagladigi sertifikanin isletim sistemi kok deposundaki guvenilir Kok Otoriteler (Root CA) tarafindan imzalanip imzalanmadigini ve alan adi eslesmesini (`check_hostname`) denetler.
* **Ayrintili Zincir Analizi (Chain Inspection):** Yaprak sertifikadan (Leaf), Ara Sertifika Otoritelerine (Intermediate CA) ve Kok Sertifikaya (Root CA) kadar tum basamaklari ayristirir.
* **OCSP Iptal Denetimi:** Sertifika Otoritesine (CA) canli OCSP sorgusu gondererek sertifikanin iptal edilip edilmedigini (Revocation Status: GOOD / REVOKED) anlik denetler.
* **HSTS Guvenlik Analizi:** HTTP Strict Transport Security basligini, `max-age` suresini, `includeSubDomains` ve `preload` direktiflerini kontrol eder.
* **Certificate Transparency (CT) Tespiti:** Sertifikaya gomulu SCT (Signed Certificate Timestamp) log kayitlarini denetler.
* **Zafiyet ve Risk Skoru:** 0-100 puan araliginda puanlama yaparak sunucuya A+, A, B, C veya F harf notu verir.
* **Paralel Tarama:** Coklu domain veya dosya taramalarinda is parcaciklari (ThreadPoolExecutor) ile yuksek hizda asenkron calisir.
* **CI/CD Uyumlu JSON Modu:** Otomasyonlar ve guvenlik boru hatlari (pipeline) icin tekil veya dizi formatinda gecerli JSON ciktisi uretir.
* **Esnek Girdi Ayristirici:** `https://`, `http://`, portlu ifadeler (`host:8443`), alt dizinler (`domain.com/path`) ve IPv6 adreslerini otomatik temizler.

---

## Kurulum

### Gereksinimler
* Python 3.8 veya uzeri
* pip paket yoneticisi

### Depoyu Klonlama ve Bagimliliklari Yukleme

```bash
git clone https://github.com/kullanici-adi/sslpy.git
cd sslpy

# Sanal ortam olusturma (Onerilen)
python -m venv venv
# Windows:
venv\Scripts\activate
# Linux/macOS:
source venv/bin/activate

# Bagimliliklarin yuklenmesi
pip install -r requirements.txt
```

### Projeyi Komut Olarak Yukleme (Opsiyonel)
Projeyi sistem genelinde dogrudan `sslpy` komutuyla calistirmak icin:

```bash
pip install -e .
```

---

## Kullanim Rehberi

### 1. Tekil Domain veya URL Analizi
```bash
python sslpy.py example.com
# veya tam URL ile:
python sslpy.py https://example.com/
```

### 2. Ozel Port Belirterek Tarama
```bash
python sslpy.py example.com:8443
# veya -p parametresi ile:
python sslpy.py example.com -p 8443
```

### 3. Birden Fazla Hedefi Ayni Anda Tarama
```bash
python sslpy.py google.com github.com cloudflare.com
```

### 4. Dosyadan Toplu Tarama
`domains.txt` dosyasi icerisindeki alan adlarini paralel olarak denetler:
```bash
python sslpy.py -f domains.example.txt
```

### 5. JSON Formatinda Cikti Alma
Tekil domain icin JSON nesnesi, coklu domain icin standart JSON dizisi uretir:
```bash
python sslpy.py -j example.com
python sslpy.py -j google.com github.com
```

### 6. Sonuclari Dosyaya Kaydetme
```bash
# JSON raporunu dosyaya kaydet
python sslpy.py -j -f domains.example.txt -o rapor.json
```

### 7. Sertifika Dogrulamasini Atlatma (--no-verify)
Test ortamlarinda veya kendinden imzali (self-signed) sertifikalari incelemek icin:
```bash
python sslpy.py -n self-signed.badssl.com
```

### 8. Renksiz Cikti Modu
Otomasyon veya log dosyalarina aktarimda ANSI renk kodlarini kapatmak icin:
```bash
python sslpy.py -b example.com
```

---

## Parametre Referansi

| Parametre | Kisa Yol | Aciklama | Varsayilan |
| :--- | :--- | :--- | :--- |
| `domains` | | Taranacak bir veya birden fazla alan adi / URL | - |
| `--port` | `-p` | Hedef baglanti port numarasi | `443` |
| `--file` | `-f` | Hedef listesi iceren dosya yolu | - |
| `--json` | `-j` | Gecerli JSON formatinda cikti uret | `False` |
| `--output` | `-o` | Sonuclarin yazilacagi cikti dosyasi | - |
| `--timeout`| `-t` | Baglanti zaman asimi suresi (saniye) | `5` |
| `--no-verify` | `-n` | Kok CA guven dogrulamasini atla | `False` |
| `--no-color` | `-b` | Renkli terminal ciktisini devre disi birak | `False` |
| `--no-ocsp` | | Canli OCSP iptal sorgusunu atla | `False` |
| `--no-hsts` | | HSTS baslik denetimini atla | `False` |
| `--verbose` | `-v` | Ayrintili hata kayitlarini goster | `False` |

---

## Guvenlik Derecelendirme Sistemi (Grading)

`sslpy`, sertifikayi ve baglantiyi endustri standartlarina gore puanlar (0-100 araligi):

* **[ A+ ] (95-100 Puan):** Tam guvenilir kok zinciri, en az 2048-bit anahtar, SHA-256+, TLS 1.3/1.2, HSTS aktif ve uzun sureli, CT loglari mevcut, OCSP durumu temiz.
* **[ A ] (85-94 Puan):** Guvenilir zincir ve guclu sifreleme, HSTS eksikligi veya kucuk iyilestirme alanlari.
* **[ B ] (70-84 Puan):** Sertifika suresinin dolmasina 30 gunden az kalmasi veya kisa HSTS suresi.
* **[ C ] (50-69 Puan):** Zayif anahtar boyutu, 7 gunden az kalan sure veya birden fazla yapilandirma eksikligi.
* **[ F ] (0-49 Puan):** Gecersiz/Guvensiz kok CA, suresi dolmus sertifika, iptal edilmis (Revoked) sertifika, alan adi uyumsuzlugu veya guvensiz TLS surumu (TLS 1.0/1.1).

---

## Ornek Terminal Rapor Ciktisi

```text
╔════════════════════════════════════════════════════════════════════╗
║          sslpy v2.0 - Kapsamli SSL/TLS Denetleme Araci             ║
╚════════════════════════════════════════════════════════════════════╝

Platform: Linux 6.5 | Python: 3.11.8
Dogrulama Modu: Tam Guven Zinciri Dogrulamasi Aktif

════════════════════════════════════════════════════════════════════
  sslpy v2.0 - KAPSAMLI SSL/TLS GUVENLIK VE DENETIM RAPORU
════════════════════════════════════════════════════════════════════

[+] Hedef: example.com:443  (IP: 93.184.216.34)
    Tarama Suresi: 0.42 saniye
    Guvenlik Derecesi: [ A+ ] (100/100 Puan)
    Dogrulama Durumu: [OK] GUVENILIR (Sistem Kok Sertifika Zinciri Dogrulandi)
    Sertifika Durumu: [GECERLI] (124 gun kaldi)
    • Baslangic: 2026-06-01T00:00:00+00:00
    • Bitis:     2027-01-05T23:59:59+00:00

[+] Sertifika Guven Zinciri (3 Sertifika):
  ├─► [0] Sunucu / Yaprak (Leaf): example.com
      Imzalayan: DigiCert Global G2 TLS RSA SHA256 2020 CA1 | Anahtar: RSA 2048-bit | Kalan: 124 gun
  ├─► [1] Ara Sertifika Otoritesi (Intermediate CA): DigiCert Global G2 TLS RSA SHA256 2020 CA1
      Imzalayan: DigiCert Global Root G2 | Anahtar: RSA 2048-bit | Kalan: 2190 gun
  └─► [2] Kok Sertifika Otoritesi (Root CA): DigiCert Global Root G2
      Imzalayan: DigiCert Global Root G2 | Anahtar: RSA 2048-bit | Kalan: 5120 gun

[+] Ileri Duzey Guvenlik Denetimleri:
  • OCSP Iptal Durumu: [OK] GECERLI (GOOD) - Sertifika iptal edilmemis
  • HSTS Guvenligi: [OK] AKTIF (max-age=31536000 [365.0 gun], includeSubDomains, preload)
  • Certificate Transparency (CT): [OK] AKTIF (2 adet gomulu SCT kaydi)
  • TLS Protokolu: TLSv1.3
  • Cipher Suite: TLS_AES_256_GCM_SHA384 (256-bit)

[+] Sertifika ve Anahtar Detaylari:
  • Seri No: 0A38B2F891D4C82A4E0011C9902
  • Acik Anahtar: RSA 2048-bit
  • Imza Algoritmasi: sha256WithRSAEncryption
  • SHA-256 Parmak Izi: E3B0C44298FC1C149AFBF4C8996FB92427AE41E4649B934CA495991B7852B855
  • SAN DNS (2 adet): example.com, www.example.com

[OK] Mukemmel: Kritik bir guvenlik acigi veya konfigurasyon hatasi tespit edilmedi.
────────────────────────────────────────────────────────────────────
```

---

## CI/CD Pipeline Entegrasyonu

`sslpy`, CI/CD sureclerinde deployment oncesi veya periyodik cron kontrollerinde sertifika sagligini denetlemek icin kullanilabilir.

Ornek GitHub Actions Adimi:
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

Bu proje [MIT Lisansi](LICENSE) ile lisanslanmistir. Ayrintilar icin `LICENSE` dosyasina basvurunuz.
