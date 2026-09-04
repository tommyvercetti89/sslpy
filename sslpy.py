#!/usr/bin/env python3
"""
sslpy - Kapsamlı SSL/TLS Sertifika Güvenlik ve Denetim Aracı
Advanced Cross-Platform SSL/TLS Certificate Security Inspector
"""

import socket
import ssl
import sys
import os
import json
import argparse
import datetime
import urllib.request
import urllib.parse
from typing import Dict, Any, Optional, Tuple, List
import concurrent.futures
import platform
import time

from cryptography import x509
from cryptography.x509 import ocsp
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.x509.oid import NameOID, ExtensionOID
import idna

# Windows cp1254 ve diğer terminallerde Unicode/Emoji desteği için UTF-8 reconfigure
try:
    if hasattr(sys.stdout, 'reconfigure'):
        sys.stdout.reconfigure(encoding='utf-8', errors='replace')
        sys.stderr.reconfigure(encoding='utf-8', errors='replace')
except Exception:
    pass


class Colors:
    """Terminal renk kodları (ANSI)"""
    RESET = "\033[0m"
    RED = "\033[91m"
    GREEN = "\033[92m"
    YELLOW = "\033[93m"
    BLUE = "\033[94m"
    MAGENTA = "\033[95m"
    CYAN = "\033[96m"
    WHITE = "\033[97m"
    BOLD = "\033[1m"
    DIM = "\033[2m"
    BG_RED = "\033[41m"
    BG_GREEN = "\033[42m"
    BG_YELLOW = "\033[43m"
    BG_BLUE = "\033[44m"

    @classmethod
    def disable(cls):
        """Renkleri devre dışı bırak"""
        for attr in dir(cls):
            if not attr.startswith('_') and isinstance(getattr(cls, attr), str):
                setattr(cls, attr, "")


def setup_terminal_colors(no_color: bool = False):
    """Windows ve POSIX sistemlerde renkleri etkinleştirir veya kapatır"""
    if no_color or os.environ.get("NO_COLOR"):
        Colors.disable()
        return

    if platform.system() == 'Windows':
        try:
            import ctypes
            kernel32 = ctypes.windll.kernel32
            h_stdout = kernel32.GetStdHandle(-11)  # STD_OUTPUT_HANDLE
            mode = ctypes.c_ulong()
            if kernel32.GetConsoleMode(h_stdout, ctypes.byref(mode)):
                ENABLE_VIRTUAL_TERMINAL_PROCESSING = 0x0004
                kernel32.SetConsoleMode(h_stdout, mode.value | ENABLE_VIRTUAL_TERMINAL_PROCESSING)
        except Exception:
            Colors.disable()


class SSLCertInspector:
    """Gelişmiş SSL/TLS Sertifika ve Güvenlik Denetleyicisi"""

    def __init__(self, timeout: int = 5):
        self.timeout = timeout
        self.backend = default_backend()

    def inspect(
        self,
        hostname: str,
        port: int = 443,
        no_verify: bool = False,
        check_ocsp: bool = True,
        check_hsts: bool = True
    ) -> Tuple[Dict[str, Any], Optional[str]]:
        """
        Belirtilen domain için SSL/TLS sertifikasını, sertifika güven zincirini,
        OCSP iptal durumunu, HSTS ve CT kayıtlarını denetler.
        """
        # IP Çözümleme
        ip_address = None
        try:
            ip_address = socket.gethostbyname(hostname)
        except socket.gaierror:
            return {}, f"DNS çözümleme hatası: '{hostname}' adresi bulunamadı"
        except Exception as e:
            return {}, f"Ağ hatası: {str(e)}"

        # Sertifika ve Zincir Çekme
        is_trusted = True
        trust_error = None
        chain_ders: List[bytes] = []
        cipher_info = None
        ssl_version = None

        if no_verify:
            is_trusted = None
            trust_error = "Doğrulama kullanıcı tarafından atlandı (--no-verify)"
            unverified_ctx = ssl.create_default_context()
            unverified_ctx.check_hostname = False
            unverified_ctx.verify_mode = ssl.CERT_NONE
            try:
                with socket.create_connection((hostname, port), timeout=self.timeout) as sock:
                    with unverified_ctx.wrap_socket(sock, server_hostname=hostname) as ssock:
                        chain_ders = ssock.get_unverified_chain()
                        cipher_info = ssock.cipher()
                        ssl_version = ssock.version()
            except socket.timeout:
                return {}, "Bağlantı zaman aşımı (Port 443 veya belirtilen port yanıt vermedi)"
            except ConnectionRefusedError:
                return {}, f"Bağlantı reddedildi ({hostname}:{port})"
            except Exception as e:
                return {}, f"SSL/TLS bağlantı hatası: {str(e)}"
        else:
            # Standart güven doğrulamalı bağlantı (Kök CA ve Hostname kontrolü)
            verified_ctx = ssl.create_default_context()
            try:
                with socket.create_connection((hostname, port), timeout=self.timeout) as sock:
                    with verified_ctx.wrap_socket(sock, server_hostname=hostname) as ssock:
                        chain_ders = ssock.get_verified_chain()
                        cipher_info = ssock.cipher()
                        ssl_version = ssock.version()
            except ssl.SSLCertVerificationError as e:
                is_trusted = False
                trust_error = e.verify_message or str(e)
                # Güven doğrulaması başarısız olduysa sertifika detaylarını analiz etmek için CERT_NONE ile bağlan
                fallback_ctx = ssl.create_default_context()
                fallback_ctx.check_hostname = False
                fallback_ctx.verify_mode = ssl.CERT_NONE
                try:
                    with socket.create_connection((hostname, port), timeout=self.timeout) as sock:
                        with fallback_ctx.wrap_socket(sock, server_hostname=hostname) as ssock:
                            chain_ders = ssock.get_unverified_chain()
                            cipher_info = ssock.cipher()
                            ssl_version = ssock.version()
                except Exception as fb_err:
                    return {}, f"Sertifika doğrulanamadı ve detaylar alınamadı: {str(fb_err)}"
            except socket.timeout:
                return {}, "Bağlantı zaman aşımı"
            except ConnectionRefusedError:
                return {}, f"Bağlantı reddedildi ({hostname}:{port})"
            except ssl.SSLError as e:
                return {}, f"SSL protokol hatası: {str(e)}"
            except Exception as e:
                return {}, f"Beklenmeyen hata: {str(e)}"

        if not chain_ders:
            return {}, "Sunucu hiçbir SSL/TLS sertifikası sağlamadı"

        # Sertifikaları parse et
        chain_certs: List[x509.Certificate] = []
        for c_der in chain_ders:
            try:
                chain_certs.append(x509.load_der_x509_certificate(c_der, self.backend))
            except Exception as e:
                pass

        if not chain_certs:
            return {}, "Sertifikalar okunamadı veya bozuk"

        leaf_cert = chain_certs[0]
        leaf_der = chain_ders[0]
        issuer_cert = chain_certs[1] if len(chain_certs) > 1 else (leaf_cert if leaf_cert.subject == leaf_cert.issuer else None)

        # 1. Temel Sertifika Detayları
        cert_info = self._extract_leaf_info(leaf_cert, leaf_der)
        cert_info['domain'] = hostname
        cert_info['port'] = port
        cert_info['ip_address'] = ip_address
        cert_info['ssl_version'] = ssl_version
        cert_info['cipher'] = {
            'name': cipher_info[0] if cipher_info else 'N/A',
            'protocol': cipher_info[1] if cipher_info else 'N/A',
            'bits': cipher_info[2] if cipher_info else 0
        }

        # 2. Güven ve Doğrulama Durumu
        cert_info['trust'] = {
            'is_trusted': is_trusted,
            'status_text': "GÜVENİLİR" if is_trusted is True else ("DOĞRULANAMADI / GÜVENSİZ" if is_trusted is False else "DOĞRULAMA ATLANDI"),
            'error': trust_error
        }

        # 3. Sertifika Zinciri Analizi (Chain Analysis)
        cert_info['chain'] = self._extract_chain_info(chain_certs)

        # 4. Certificate Transparency (CT) Denetimi
        cert_info['certificate_transparency'] = self._check_certificate_transparency(leaf_cert)

        # 5. OCSP İptal Durumu Denetimi
        if check_ocsp:
            cert_info['ocsp'] = self._check_ocsp(leaf_cert, issuer_cert)
        else:
            cert_info['ocsp'] = {'status': 'SKIPPED', 'message': 'OCSP kontrolü atlandı'}

        # 6. HSTS Denetimi
        if check_hsts:
            cert_info['hsts'] = self._check_hsts(hostname, port, verify=(is_trusted is True))
        else:
            cert_info['hsts'] = {'enabled': False, 'status': 'HSTS kontrolü atlandı'}

        # 7. Güvenlik Değerlendirmesi ve Skorlama (Grade Calculation)
        score, grade, findings = self._evaluate_security(cert_info)
        cert_info['security_evaluation'] = {
            'score': score,
            'grade': grade,
            'findings': findings
        }

        return cert_info, None

    def _extract_leaf_info(self, cert: x509.Certificate, cert_der: bytes) -> Dict[str, Any]:
        """Yaprak (Sunucu) sertifikasından ayrıntılı bilgileri çıkarır"""
        info: Dict[str, Any] = {}

        info['serial_number'] = format(cert.serial_number, 'x').upper()
        info['version'] = cert.version.name if hasattr(cert.version, 'name') else str(cert.version.value)
        info['fingerprint_sha256'] = cert.fingerprint(hashes.SHA256()).hex().upper()
        info['fingerprint_sha1'] = cert.fingerprint(hashes.SHA1()).hex().upper()
        info['signature_algorithm'] = cert.signature_algorithm_oid._name

        # Geçerlilik tarihleri
        now_utc = datetime.datetime.now(datetime.timezone.utc)
        info['not_before'] = cert.not_valid_before_utc.isoformat()
        info['not_after'] = cert.not_valid_after_utc.isoformat()
        info['days_remaining'] = (cert.not_valid_after_utc - now_utc).days
        info['is_expired'] = info['days_remaining'] < 0
        info['is_expiring_soon'] = 0 <= info['days_remaining'] <= 30

        # Subject ve Issuer
        info['subject'] = self._get_name_attributes(cert.subject)
        info['issuer'] = self._get_name_attributes(cert.issuer)

        # Subject Alternative Names (SAN)
        info['san'] = self._get_san(cert)

        # Anahtar Bilgileri
        public_key = cert.public_key()
        info['public_key_type'] = public_key.__class__.__name__.replace('_', '').replace('PublicKey', '')
        info['public_key_size'] = getattr(public_key, 'key_size', 'N/A')

        # Key Usage & EKU
        try:
            ku = cert.extensions.get_extension_for_oid(ExtensionOID.KEY_USAGE).value
            info['key_usage'] = self._get_key_usage(ku)
        except Exception:
            info['key_usage'] = []

        try:
            eku = cert.extensions.get_extension_for_oid(ExtensionOID.EXTENDED_KEY_USAGE).value
            info['extended_key_usage'] = [oid._name for oid in eku]
        except Exception:
            info['extended_key_usage'] = []

        return info

    def _extract_chain_info(self, chain_certs: List[x509.Certificate]) -> List[Dict[str, Any]]:
        """Sertifika güven zincirindeki her bir sertifikayı ayrıntılı analiz eder"""
        chain_info = []
        total = len(chain_certs)
        now_utc = datetime.datetime.now(datetime.timezone.utc)

        for idx, cert in enumerate(chain_certs):
            is_self_signed = (cert.subject == cert.issuer)
            is_ca = False
            path_len = None

            try:
                bc = cert.extensions.get_extension_for_oid(ExtensionOID.BASIC_CONSTRAINTS).value
                is_ca = bc.ca
                path_len = bc.path_length
            except Exception:
                pass

            if idx == 0:
                role = "Sunucu / Yaprak (Leaf)"
            elif idx == total - 1 and is_self_signed:
                role = "Kök Sertifika Otoritesi (Root CA)"
            else:
                role = "Ara Sertifika Otoritesi (Intermediate CA)"

            pub_key = cert.public_key()
            days_left = (cert.not_valid_after_utc - now_utc).days

            chain_info.append({
                'index': idx,
                'role': role,
                'is_ca': is_ca,
                'path_length': path_len,
                'is_self_signed': is_self_signed,
                'subject': self._get_name_attributes(cert.subject),
                'issuer': self._get_name_attributes(cert.issuer),
                'serial_number': format(cert.serial_number, 'x').upper(),
                'signature_algorithm': cert.signature_algorithm_oid._name,
                'public_key_type': pub_key.__class__.__name__.replace('_', '').replace('PublicKey', ''),
                'public_key_size': getattr(pub_key, 'key_size', 'N/A'),
                'not_before': cert.not_valid_before_utc.isoformat(),
                'not_after': cert.not_valid_after_utc.isoformat(),
                'days_remaining': days_left,
                'is_expired': days_left < 0,
                'fingerprint_sha256': cert.fingerprint(hashes.SHA256()).hex().upper()
            })

        return chain_info

    def _check_ocsp(self, leaf_cert: x509.Certificate, issuer_cert: Optional[x509.Certificate]) -> Dict[str, Any]:
        """OCSP (Online Certificate Status Protocol) ile iptal durumunu sorgular"""
        # CRL Dağıtım Noktalarını Çek
        crl_urls: List[str] = []
        try:
            crl_ext = leaf_cert.extensions.get_extension_for_oid(ExtensionOID.CRL_DISTRIBUTION_POINTS).value
            for dp in crl_ext:
                if dp.full_name:
                    for fn in dp.full_name:
                        crl_urls.append(str(fn.value))
        except Exception:
            pass

        # AIA Uzantısından OCSP URL'lerini Bul
        ocsp_urls: List[str] = []
        try:
            aia = leaf_cert.extensions.get_extension_for_oid(ExtensionOID.AUTHORITY_INFORMATION_ACCESS).value
            ocsp_urls = [
                desc.access_location.value for desc in aia
                if desc.access_method == x509.AuthorityInformationAccessOID.OCSP
            ]
        except Exception:
            pass

        if not ocsp_urls:
            return {
                'status': 'NO_OCSP_RESPONDER',
                'revocation_status': 'OCSP Yok (CRL Mevcut)' if crl_urls else 'Bilinmiyor',
                'message': 'Sertifikada OCSP Responder adresi bulunmuyor (Modern CA politikası gereği CRL kullanılmaktadır)',
                'responder_url': None,
                'crl_urls': crl_urls
            }

        if not issuer_cert:
            return {
                'status': 'NO_ISSUER',
                'revocation_status': 'Kontrol Edilemedi',
                'message': 'Ara sertifika (Issuer) zincirde yer almadığı için OCSP isteği oluşturulamadı',
                'responder_url': ocsp_urls[0],
                'crl_urls': crl_urls
            }

        responder_url = ocsp_urls[0]

        try:
            builder = ocsp.OCSPRequestBuilder()
            # RFC 6960 uyarınca CA'lar çoğunlukla SHA-1 CertID kullanır
            builder = builder.add_certificate(leaf_cert, issuer_cert, hashes.SHA1())
            ocsp_req = builder.build()
            req_data = ocsp_req.public_bytes(serialization.Encoding.DER)

            http_req = urllib.request.Request(
                responder_url,
                data=req_data,
                headers={
                    'Content-Type': 'application/ocsp-request',
                    'User-Agent': 'sslpy/2.0',
                    'Accept': 'application/ocsp-response'
                }
            )

            with urllib.request.urlopen(http_req, timeout=self.timeout) as resp:
                resp_data = resp.read()
                ocsp_resp = ocsp.load_der_ocsp_response(resp_data)

                if ocsp_resp.response_status != ocsp.OCSPResponseStatus.SUCCESSFUL:
                    return {
                        'status': 'OCSP_ERROR',
                        'revocation_status': 'Yanıt Hatası',
                        'message': f"OCSP Responder yanıt durumu: {ocsp_resp.response_status.name}",
                        'responder_url': responder_url,
                        'crl_urls': crl_urls
                    }

                cert_status = ocsp_resp.certificate_status
                if cert_status == ocsp.OCSPCertStatus.GOOD:
                    return {
                        'status': 'GOOD',
                        'revocation_status': 'GEÇERLİ (GOOD)',
                        'message': 'Sertifika iptal edilmemiş, aktif ve güvenli',
                        'responder_url': responder_url,
                        'this_update': ocsp_resp.this_update_utc.isoformat() if ocsp_resp.this_update_utc else None,
                        'next_update': ocsp_resp.next_update_utc.isoformat() if ocsp_resp.next_update_utc else None,
                        'crl_urls': crl_urls
                    }
                elif cert_status == ocsp.OCSPCertStatus.REVOKED:
                    return {
                        'status': 'REVOKED',
                        'revocation_status': 'İPTAL EDİLMİŞ (REVOKED!)',
                        'message': 'UYARI: Bu sertifika sertifika otoritesi (CA) tarafından İPTAL EDİLMİŞTİR!',
                        'responder_url': responder_url,
                        'revocation_time': ocsp_resp.revocation_time_utc.isoformat() if ocsp_resp.revocation_time_utc else None,
                        'revocation_reason': str(ocsp_resp.revocation_reason),
                        'crl_urls': crl_urls
                    }
                else:
                    return {
                        'status': 'UNKNOWN',
                        'revocation_status': 'BİLİNMİYOR (UNKNOWN)',
                        'message': 'Sertifikanın iptal durumu belirlenemedi',
                        'responder_url': responder_url,
                        'crl_urls': crl_urls
                    }
        except Exception as e:
            return {
                'status': 'QUERY_FAILED',
                'revocation_status': 'Sorgu Başarısız',
                'message': f"OCSP sunucusuna erişilemedi: {str(e)}",
                'responder_url': responder_url,
                'crl_urls': crl_urls
            }

    def _check_hsts(self, hostname: str, port: int = 443, verify: bool = True) -> Dict[str, Any]:
        """HTTP Strict Transport Security (HSTS) başlığını denetler"""
        url = f"https://{hostname}:{port}" if port != 443 else f"https://{hostname}"
        ctx = ssl.create_default_context()
        if not verify:
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE

        req = urllib.request.Request(
            url,
            headers={'User-Agent': 'sslpy/2.0 (Security Inspector)'}
        )

        try:
            with urllib.request.urlopen(req, timeout=self.timeout, context=ctx) as resp:
                hsts_header = resp.headers.get('Strict-Transport-Security')
                if not hsts_header:
                    return {
                        'enabled': False,
                        'header': None,
                        'status': 'Eksik (HSTS başlığı gönderilmiyor)'
                    }

                max_age = None
                include_subdomains = False
                preload = False

                for part in hsts_header.split(';'):
                    clean_part = part.strip()
                    if clean_part.lower().startswith('max-age='):
                        try:
                            max_age = int(clean_part.split('=')[1])
                        except ValueError:
                            pass
                    elif clean_part.lower() == 'includesubdomains':
                        include_subdomains = True
                    elif clean_part.lower() == 'preload':
                        preload = True

                days = round(max_age / 86400, 1) if max_age is not None else None

                return {
                    'enabled': True,
                    'header': hsts_header,
                    'max_age': max_age,
                    'max_age_days': days,
                    'include_subdomains': include_subdomains,
                    'preload': preload,
                    'status': 'Aktif ve Güvenli' if (max_age and max_age >= 15768000) else 'Aktif (Kısa Süreli max-age)'
                }
        except Exception as e:
            return {
                'enabled': False,
                'header': None,
                'status': f'Kontrol edilemedi ({str(e)})'
            }

    def _check_certificate_transparency(self, cert: x509.Certificate) -> Dict[str, Any]:
        """Sertifika Şeffaflığı (Certificate Transparency - SCT) kayıtlarını denetler"""
        sct_oid = x509.ObjectIdentifier("1.3.6.1.4.1.11129.2.4.2")
        try:
            ext = cert.extensions.get_extension_for_oid(sct_oid)
            scts = []
            for sct in ext.value:
                scts.append({
                    'version': str(sct.version.name) if hasattr(sct.version, 'name') else str(sct.version),
                    'log_id': sct.log_id.hex(),
                    'timestamp': sct.timestamp.isoformat() if hasattr(sct.timestamp, 'isoformat') else str(sct.timestamp)
                })
            return {
                'supported': True,
                'count': len(scts),
                'scts': scts,
                'status': f"Aktif ({len(scts)} adet gömülü SCT log kaydı)"
            }
        except Exception:
            return {
                'supported': False,
                'count': 0,
                'scts': [],
                'status': 'Gömülü SCT kaydı bulunamadı'
            }

    def _evaluate_security(self, cert_info: Dict[str, Any]) -> Tuple[int, str, List[Dict[str, str]]]:
        """Kapsamlı güvenlik puanı (0-100), harf notu (A+, A, B, C, F) ve bulguları hesaplar"""
        score = 100
        findings: List[Dict[str, str]] = []

        # 1. Güven & Sertifika Doğrulama
        trust = cert_info.get('trust', {})
        if trust.get('is_trusted') is False:
            score -= 50
            findings.append({
                'level': 'CRITICAL',
                'message': f"Sertifika güven doğrulaması başarısız: {trust.get('error', 'Geçersiz Kök CA')}"
            })
        elif trust.get('is_trusted') is None:
            score -= 10
            findings.append({
                'level': 'WARNING',
                'message': "Sertifika doğrulaması kullanıcı tarafından atlandı (--no-verify)"
            })

        # 2. Geçerlilik Süresi
        days_left = cert_info.get('days_remaining', 0)
        if cert_info.get('is_expired'):
            score -= 50
            findings.append({
                'level': 'CRITICAL',
                'message': f"Sertifikanın süresi dolmuş! (Gecikme: {abs(days_left)} gün)"
            })
        elif cert_info.get('is_expiring_soon'):
            if days_left <= 7:
                score -= 20
                findings.append({
                    'level': 'CRITICAL',
                    'message': f"Sertifika süresinin dolmasına 7 günden az kaldı! ({days_left} gün)"
                })
            else:
                score -= 10
                findings.append({
                    'level': 'WARNING',
                    'message': f"Sertifika süresi yakında dolacak ({days_left} gün kaldı), yenileme başlatılmalı"
                })

        # 3. OCSP İptal Durumu
        ocsp_info = cert_info.get('ocsp', {})
        if ocsp_info.get('status') == 'REVOKED':
            score = 0
            findings.append({
                'level': 'CRITICAL',
                'message': "DİKKAT: Sertifika CA tarafından İPTAL EDİLMİŞTİR (Revoked)! Bağlantı güvensizdir."
            })

        # 4. Anahtar Boyutu ve Algoritma
        key_size = cert_info.get('public_key_size')
        key_type = cert_info.get('public_key_type', '')
        if isinstance(key_size, int):
            if 'RSA' in key_type and key_size < 2048:
                score -= 30
                findings.append({
                    'level': 'CRITICAL',
                    'message': f"Güvensiz RSA anahtar boyutu ({key_size}-bit). Minimum 2048-bit gereklidir."
                })
            elif 'EC' in key_type and key_size < 256:
                score -= 30
                findings.append({
                    'level': 'CRITICAL',
                    'message': f"Güvensiz Elliptic Curve anahtar boyutu ({key_size}-bit)."
                })

        # 5. İmza Algoritması
        sig_alg = cert_info.get('signature_algorithm', '').lower()
        if 'sha1' in sig_alg or 'md5' in sig_alg:
            score -= 35
            findings.append({
                'level': 'CRITICAL',
                'message': f"Kırılmış/Güvensiz imza algoritması ({sig_alg}). SHA-256 veya üstü kullanılmalıdır."
            })

        # 6. TLS Protokol Sürümü
        ssl_ver = cert_info.get('ssl_version', '')
        if '1.0' in ssl_ver or '1.1' in ssl_ver:
            score -= 35
            findings.append({
                'level': 'CRITICAL',
                'message': f"Kullanımdan kaldırılmış TLS sürümü ({ssl_ver}). En az TLSv1.2 veya TLSv1.3 gereklidir."
            })
        elif '1.3' in ssl_ver:
            # Modern TLS 1.3 bonus / standard
            pass

        # 7. SAN Domain Eşleşmesi
        domain = cert_info.get('domain', '')
        san = cert_info.get('san', {})
        dns_names = san.get('DNS', [])
        if domain and dns_names:
            matched = False
            for d in dns_names:
                if d == domain:
                    matched = True
                    break
                if d.startswith('*.') and domain.endswith(d[1:]) and domain.count('.') == d.count('.'):
                    matched = True
                    break
            if not matched:
                score -= 40
                findings.append({
                    'level': 'CRITICAL',
                    'message': f"Hedef domain ('{domain}') sertifikanın SAN listesiyle uyuşmuyor!"
                })

        # 8. HSTS Durumu
        hsts = cert_info.get('hsts', {})
        if not hsts.get('enabled'):
            score -= 10
            findings.append({
                'level': 'INFO',
                'message': "HSTS (Strict-Transport-Security) başlığı eksik. SSL Striping saldırılarına karşı risklidir."
            })
        elif hsts.get('max_age') and hsts.get('max_age') < 15768000:
            score -= 5
            findings.append({
                'level': 'INFO',
                'message': "HSTS max-age süresi 6 aydan kısa. Önerilen süre en az 1 yıl (31536000 saniye)."
            })

        # 9. Certificate Transparency
        ct = cert_info.get('certificate_transparency', {})
        if not ct.get('supported'):
            score -= 5
            findings.append({
                'level': 'INFO',
                'message': "Sertifikada gömülü SCT (Certificate Transparency) kaydı bulunamadı."
            })

        score = max(0, min(100, score))

        # Harf notu belirleme
        if score >= 95 and hsts.get('enabled') and cert_info.get('trust', {}).get('is_trusted') is True:
            grade = "A+"
        elif score >= 85:
            grade = "A"
        elif score >= 70:
            grade = "B"
        elif score >= 50:
            grade = "C"
        else:
            grade = "F"

        return score, grade, findings

    def _get_name_attributes(self, name: x509.Name) -> Dict[str, str]:
        """Name nesnesinden alanları çıkarır"""
        attributes = {}
        oid_map = {
            NameOID.COMMON_NAME: 'common_name',
            NameOID.ORGANIZATION_NAME: 'organization',
            NameOID.ORGANIZATIONAL_UNIT_NAME: 'organizational_unit',
            NameOID.COUNTRY_NAME: 'country',
            NameOID.STATE_OR_PROVINCE_NAME: 'state',
            NameOID.LOCALITY_NAME: 'locality',
            NameOID.EMAIL_ADDRESS: 'email',
        }
        for attr in name:
            oid_name = attr.oid._name
            key = oid_map.get(attr.oid, oid_name)
            attributes[key] = str(attr.value)
        return attributes

    def _get_san(self, cert: x509.Certificate) -> Dict[str, list]:
        """Subject Alternative Names (SAN) çıkarır"""
        san_dict = {'DNS': [], 'IP': [], 'Email': [], 'URI': []}
        try:
            san_ext = cert.extensions.get_extension_for_oid(ExtensionOID.SUBJECT_ALTERNATIVE_NAME).value
            for san in san_ext:
                if isinstance(san, x509.DNSName):
                    san_dict['DNS'].append(san.value)
                elif isinstance(san, x509.IPAddress):
                    san_dict['IP'].append(str(san.value))
                elif isinstance(san, x509.RFC822Name):
                    san_dict['Email'].append(san.value)
                elif isinstance(san, x509.UniformResourceIdentifier):
                    san_dict['URI'].append(san.value)
        except Exception:
            pass
        return san_dict

    def _get_key_usage(self, key_usage) -> list:
        """Anahtar kullanım yetkilerini listeler"""
        usage_flags = [
            ('digital_signature', 'Dijital İmza'),
            ('content_commitment', 'İçerik Taahhüdü'),
            ('key_encipherment', 'Anahtar Şifreleme'),
            ('data_encipherment', 'Veri Şifreleme'),
            ('key_agreement', 'Anahtar Anlaşması'),
            ('key_cert_sign', 'Sertifika İmzalama (CA)'),
            ('crl_sign', 'CRL İmzalama'),
            ('encipher_only', 'Sadece Şifreleme'),
            ('decipher_only', 'Sadece Deşifreleme'),
        ]
        return [label for attr, label in usage_flags if getattr(key_usage, attr, False)]


class SSLPyCLI:
    """sslpy Terminal ve Raporlama Arayüzü"""

    def __init__(self, inspector: SSLCertInspector, json_output: bool = False, verbose: bool = False):
        self.inspector = inspector
        self.json_output = json_output
        self.verbose = verbose

    def inspect_target(self, domain: str, port: int = 443, no_verify: bool = False) -> Dict[str, Any]:
        """Tek bir hedefi denetler ve sonuç nesnesini döndürür"""
        try:
            ascii_domain = idna.encode(domain).decode('ascii')
        except Exception:
            ascii_domain = domain

        start_time = time.time()
        cert_info, error = self.inspector.inspect(ascii_domain, port=port, no_verify=no_verify)
        elapsed = time.time() - start_time

        if error:
            return {
                'domain': domain,
                'port': port,
                'error': error,
                'status': 'FAILED',
                'scan_time': round(elapsed, 2)
            }

        cert_info['scan_time'] = round(elapsed, 2)
        cert_info['scan_timestamp'] = datetime.datetime.now(datetime.timezone.utc).isoformat()
        return cert_info

    def print_pretty_report(self, info: Dict[str, Any]) -> None:
        """Görsel ve profesyonel terminal güvenlik raporu"""
        width = 68

        if 'error' in info:
            print(f"\n{Colors.BOLD}{Colors.RED}{'='*width}")
            print(f"  [-] HATA: {info.get('domain')}:{info.get('port')}")
            print(f"  Açıklama: {info.get('error')}")
            print(f"{'='*width}{Colors.RESET}\n")
            return

        domain = info.get('domain', 'N/A')
        port = info.get('port', 443)
        ip = info.get('ip_address', 'N/A')
        scan_time = info.get('scan_time', 0)

        eval_info = info.get('security_evaluation', {})
        score = eval_info.get('score', 0)
        grade = eval_info.get('grade', 'F')

        # Grade Rengi
        if grade in ['A+', 'A']:
            grade_color = f"{Colors.BOLD}{Colors.GREEN}"
        elif grade == 'B':
            grade_color = f"{Colors.BOLD}{Colors.CYAN}"
        elif grade == 'C':
            grade_color = f"{Colors.BOLD}{Colors.YELLOW}"
        else:
            grade_color = f"{Colors.BOLD}{Colors.RED}"

        print(f"\n{Colors.BOLD}{Colors.CYAN}{'═'*width}")
        print(f"  sslpy v2.0 - KAPSAMLI SSL/TLS GÜVENLİK VE DENETİM RAPORU")
        print(f"{'═'*width}{Colors.RESET}")

        # 1. Genel Hedef ve Skor Başlığı
        print(f"\n{Colors.BOLD}[+] Hedef:{Colors.RESET} {Colors.WHITE}{domain}:{port}{Colors.RESET}  {Colors.DIM}(IP: {ip}){Colors.RESET}")
        print(f"    {Colors.BOLD}Tarama Süresi:{Colors.RESET} {scan_time:.2f} saniye")
        print(f"    {Colors.BOLD}Güvenlik Derecesi:{Colors.RESET} {grade_color}[ {grade} ] ({score}/100 Puan){Colors.RESET}")

        # 2. Güven ve Doğrulama Durumu (Kök CA)
        trust = info.get('trust', {})
        if trust.get('is_trusted') is True:
            trust_badge = f"{Colors.GREEN}[OK] GÜVENİLİR (Sistem Kök Sertifika Zinciri Doğrulandı){Colors.RESET}"
        elif trust.get('is_trusted') is False:
            trust_badge = f"{Colors.RED}[FAIL] GÜVENSİZ / DOĞRULANAMADI ({trust.get('error')}){Colors.RESET}"
        else:
            trust_badge = f"{Colors.YELLOW}[WARN] DOĞRULAMA ATLANDI (--no-verify aktif){Colors.RESET}"
        print(f"    {Colors.BOLD}Doğrulama Durumu:{Colors.RESET} {trust_badge}")

        # 3. Geçerlilik & Süre
        days = info.get('days_remaining', 0)
        if info.get('is_expired'):
            status_badge = f"{Colors.RED}[EXPIRED] SÜRESİ DOLMUŞ ({abs(days)} gün önce){Colors.RESET}"
        elif info.get('is_expiring_soon'):
            status_badge = f"{Colors.YELLOW}[WARN] YAKINDA DOLACAK ({days} gün kaldı){Colors.RESET}"
        else:
            status_badge = f"{Colors.GREEN}[GEÇERLİ] ({days} gün kaldı){Colors.RESET}"

        print(f"    {Colors.BOLD}Sertifika Durumu:{Colors.RESET} {status_badge}")
        print(f"    • Başlangıç: {info.get('not_before')}")
        print(f"    • Bitiş:     {info.get('not_after')}")

        # 4. Sertifika Güven Zinciri (Chain Analysis)
        chain = info.get('chain', [])
        print(f"\n{Colors.BOLD}{Colors.BLUE}[+] Sertifika Güven Zinciri ({len(chain)} Sertifika):{Colors.RESET}")
        for c in chain:
            idx = c.get('index')
            role = c.get('role')
            subj_cn = c.get('subject', {}).get('common_name') or c.get('subject', {}).get('organization') or 'N/A'
            issuer_cn = c.get('issuer', {}).get('common_name') or c.get('issuer', {}).get('organization') or 'N/A'
            k_type = c.get('public_key_type')
            k_size = c.get('public_key_size')
            c_days = c.get('days_remaining')
            prefix = "└─►" if idx == len(chain) - 1 else "├─►"

            role_color = Colors.CYAN if idx == 0 else (Colors.MAGENTA if "Root" in role else Colors.YELLOW)
            print(f"  {prefix} {Colors.BOLD}[{idx}] {role_color}{role}:{Colors.RESET} {subj_cn}")
            print(f"      {Colors.DIM}İmzalayan: {issuer_cn} | Anahtar: {k_type} {k_size}-bit | Kalan: {c_days} gün{Colors.RESET}")

        # 5. İleri Düzey Güvenlik Kontrolleri
        print(f"\n{Colors.BOLD}{Colors.BLUE}[+] İleri Düzey Güvenlik Denetimleri:{Colors.RESET}")

        # OCSP İptal Durumu
        ocsp_data = info.get('ocsp', {})
        ocsp_status = ocsp_data.get('status')
        if ocsp_status == 'GOOD':
            ocsp_badge = f"{Colors.GREEN}[OK] GEÇERLİ (GOOD) - Sertifika iptal edilmemiş{Colors.RESET}"
        elif ocsp_status == 'REVOKED':
            ocsp_badge = f"{Colors.RED}[REVOKED] İPTAL EDİLMİŞ! - Bu sertifika geçersizdir{Colors.RESET}"
        elif ocsp_status == 'NO_OCSP_RESPONDER':
            ocsp_badge = f"{Colors.YELLOW}[INFO] OCSP Responder Yok (CRL Dağıtım Noktaları Mevcut){Colors.RESET}"
        else:
            ocsp_badge = f"{Colors.DIM}[WARN] {ocsp_data.get('message', 'Bilinmiyor')}{Colors.RESET}"
        print(f"  • {Colors.BOLD}OCSP İptal Durumu:{Colors.RESET} {ocsp_badge}")

        # HSTS Durumu
        hsts = info.get('hsts', {})
        if hsts.get('enabled'):
            preload_str = ", preload" if hsts.get('preload') else ""
            sub_str = ", includeSubDomains" if hsts.get('include_subdomains') else ""
            hsts_badge = f"{Colors.GREEN}[OK] AKTİF{Colors.RESET} (max-age={hsts.get('max_age')} [{hsts.get('max_age_days')} gün]{sub_str}{preload_str})"
        else:
            hsts_badge = f"{Colors.YELLOW}[WARN] EKSİK{Colors.RESET} {Colors.DIM}({hsts.get('status')}){Colors.RESET}"
        print(f"  • {Colors.BOLD}HSTS Güvenliği:{Colors.RESET} {hsts_badge}")

        # Certificate Transparency (CT)
        ct = info.get('certificate_transparency', {})
        if ct.get('supported'):
            ct_badge = f"{Colors.GREEN}[OK] AKTİF{Colors.RESET} ({ct.get('count')} adet gömülü SCT kaydı)"
        else:
            ct_badge = f"{Colors.DIM}[INFO] Gömülü SCT kaydı yok{Colors.RESET}"
        print(f"  • {Colors.BOLD}Certificate Transparency (CT):{Colors.RESET} {ct_badge}")

        # TLS & Cipher
        cipher = info.get('cipher', {})
        print(f"  • {Colors.BOLD}TLS Protokolü:{Colors.RESET} {Colors.GREEN}{info.get('ssl_version', 'N/A')}{Colors.RESET}")
        print(f"  • {Colors.BOLD}Cipher Suite:{Colors.RESET} {cipher.get('name', 'N/A')} ({cipher.get('bits', 'N/A')}-bit)")

        # 6. Kimlik & SAN Bilgileri
        print(f"\n{Colors.BOLD}{Colors.BLUE}[+] Sertifika ve Anahtar Detayları:{Colors.RESET}")
        print(f"  • Seri No: {info.get('serial_number', 'N/A')}")
        print(f"  • Açık Anahtar: {info.get('public_key_type')} {info.get('public_key_size')}-bit")
        print(f"  • İmza Algoritması: {info.get('signature_algorithm', 'N/A')}")
        print(f"  • SHA-256 Parmak İzi: {info.get('fingerprint_sha256', 'N/A')}")

        san = info.get('san', {})
        dns_names = san.get('DNS', [])
        if dns_names:
            preview = ", ".join(dns_names[:5])
            if len(dns_names) > 5:
                preview += f" {Colors.DIM}(+{len(dns_names)-5} diğer alan adı){Colors.RESET}"
            print(f"  • SAN DNS ({len(dns_names)} adet): {preview}")

        # 7. Bulgular ve Güvenlik Önerileri
        findings = eval_info.get('findings', [])
        if findings:
            print(f"\n{Colors.BOLD}{Colors.YELLOW}[!] Güvenlik Bulguları ve İyileştirmeler:{Colors.RESET}")
            for f in findings:
                lvl = f.get('level')
                msg = f.get('message')
                if lvl == 'CRITICAL':
                    print(f"  {Colors.RED}[KRİTİK]{Colors.RESET} {msg}")
                elif lvl == 'WARNING':
                    print(f"  {Colors.YELLOW}[UYARI]{Colors.RESET} {msg}")
                else:
                    print(f"  {Colors.CYAN}[BİLGİ]{Colors.RESET} {msg}")
        else:
            print(f"\n{Colors.GREEN}[OK] Mükemmel: Kritik bir güvenlik açığı veya konfigürasyon hatası tespit edilmedi.{Colors.RESET}")

        print(f"{Colors.DIM}{'─'*width}{Colors.RESET}\n")


def parse_target(raw_target: str, default_port: int = 443) -> Optional[Tuple[str, int]]:
    """
    Kullanıcının girdiği URL, domain veya host:port ifadesini güvenle ayrıştırır.
    Örnekler:
      - 'https://example.com/' -> ('example.com', 443)
      - 'https://example.com:8443/login' -> ('example.com', 8443)
      - 'http://example.com' -> ('example.com', 443)
      - 'example.com:8443' -> ('example.com', 8443)
      - 'example.com' -> ('example.com', 443)
      - '[2001:db8::1]:8443' -> ('2001:db8::1', 8443)
    """
    raw = raw_target.strip()
    if not raw or raw.startswith('#'):
        return None

    # Eğer protokol şeması varsa (http://, https:// vb.)
    if "://" in raw:
        parsed = urllib.parse.urlparse(raw)
        host = parsed.hostname or (parsed.netloc.split(':')[0] if parsed.netloc else raw)
        port = parsed.port or default_port
        return host.strip('/'), port

    # Sondaki path/slashes temizle (örn. example.com/test)
    if '/' in raw:
        raw = raw.split('/')[0].strip()

    # IPv6 ayrıştırma: [::1]:8443
    if raw.startswith('['):
        if ']:' in raw:
            host_part, port_part = raw.rsplit(']:', 1)
            port = int(port_part) if port_part.isdigit() else default_port
            return host_part.lstrip('['), port
        return raw.strip('[]'), default_port

    # Standart host:port ayrıştırma: example.com:8443
    if ':' in raw:
        parts = raw.rsplit(':', 1)
        if parts[1].isdigit():
            return parts[0].strip(), int(parts[1])
        return parts[0].strip(), default_port

    return raw.strip(), default_port


def main():
    """sslpy CLI Ana Giriş Noktası"""
    parser = argparse.ArgumentParser(
        prog='sslpy',
        description='sslpy v2.0 - Kapsamlı SSL/TLS Sertifika Güvenlik ve Denetim Aracı',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Kullanım Örnekleri:
  sslpy example.com                  # Tek domain kapsamlı analizi
  sslpy example.com:8443             # Özel port ile analiz
  sslpy google.com github.com        # Birden fazla domaini analiz et
  sslpy -f domains.txt               # Dosyadan toplu domain tara
  sslpy -j example.com               # Tekil JSON çıktısı
  sslpy -j google.com github.com     # Birden çok domain için geçerli JSON dizisi çıktısı
  sslpy -j -f domains.txt -o out.json# Sonuçları JSON dosyasına kaydet
  sslpy -n self-signed.badssl.com    # Kök CA doğrulamasını atla (--no-verify)
  sslpy -b example.com               # Renksiz terminal çıktısı
        """
    )

    parser.add_argument('domains', nargs='*', help='Kontrol edilecek domain veya IP adresi')
    parser.add_argument('-p', '--port', type=int, default=443, help='Varsayılan port (varsayılan: 443)')
    parser.add_argument('-f', '--file', help='Domain listesi içeren metin dosyası')
    parser.add_argument('-j', '--json', action='store_true', help='Geçerli JSON formatında çıktı ver')
    parser.add_argument('-o', '--output', help='Çıktıyı belirtilen dosyaya kaydet')
    parser.add_argument('-t', '--timeout', type=int, default=5, help='Bağlantı zaman aşımı saniyesi (varsayılan: 5)')
    parser.add_argument('-b', '--no-color', action='store_true', help='Renksiz terminal çıktısı kullan')
    parser.add_argument('-n', '--no-verify', action='store_true', help='Kök CA ve sertifika güven doğrulamasını atla')
    parser.add_argument('--no-ocsp', action='store_true', help='OCSP iptal sorgusunu atla')
    parser.add_argument('--no-hsts', action='store_true', help='HSTS kontrolünü atla')
    parser.add_argument('-v', '--verbose', action='store_true', help='Ayrıntılı hata çıktısı')

    args = parser.parse_args()

    # Terminal Renk Ayarları
    setup_terminal_colors(no_color=args.no_color)

    # Domain Listesini Topla
    target_domains: List[Tuple[str, int]] = []

    if args.file:
        if not os.path.isfile(args.file):
            print(f"{Colors.RED}[-] Dosya bulunamadı: {args.file}{Colors.RESET}")
            sys.exit(1)
        with open(args.file, 'r', encoding='utf-8') as f:
            for line in f:
                target = parse_target(line, default_port=args.port)
                if target:
                    target_domains.append(target)

    for d in args.domains:
        target = parse_target(d, default_port=args.port)
        if target:
            target_domains.append(target)

    if not target_domains:
        parser.print_help()
        sys.exit(1)

    # Başlatıcıyı Kur
    inspector = SSLCertInspector(timeout=args.timeout)
    cli = SSLPyCLI(inspector, json_output=args.json, verbose=args.verbose)

    # CLI Açılış Başlığı (Sadece JSON değilse)
    if not args.json:
        print(f"{Colors.BOLD}{Colors.CYAN}")
        print("╔════════════════════════════════════════════════════════════════════╗")
        print("║          sslpy v2.0 - Kapsamlı SSL/TLS Denetleme Aracı             ║")
        print("╚════════════════════════════════════════════════════════════════════╝")
        print(f"{Colors.RESET}")
        print(f"{Colors.DIM}Platform: {platform.system()} {platform.release()} | Python: {platform.python_version()}{Colors.RESET}")
        print(f"{Colors.DIM}Doğrulama Modu: {'Sertifika Doğrulaması Devre Dışı (--no-verify)' if args.no_verify else 'Tam Güven Zinciri Doğrulaması Aktif'}{Colors.RESET}\n")

    results: List[Dict[str, Any]] = []

    # Tekil Domain
    if len(target_domains) == 1:
        domain, port = target_domains[0]
        res = cli.inspect_target(domain, port=port, no_verify=args.no_verify)
        results.append(res)
        if not args.json:
            cli.print_pretty_report(res)
    else:
        # Çoklu Domain - Paralel Tarama
        max_workers = min(10, len(target_domains))
        with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as executor:
            future_to_target = {
                executor.submit(cli.inspect_target, domain, port, args.no_verify): (domain, port)
                for domain, port in target_domains
            }
            for future in concurrent.futures.as_completed(future_to_target):
                domain, port = future_to_target[future]
                try:
                    res = future.result()
                    results.append(res)
                    if not args.json:
                        cli.print_pretty_report(res)
                except Exception as e:
                    err_res = {'domain': domain, 'port': port, 'error': str(e), 'status': 'FAILED'}
                    results.append(err_res)
                    if not args.json:
                        cli.print_pretty_report(err_res)

    # JSON Çıktısı Yönetimi (Tekil domain için tek dict, çoklu domain için tek liste)
    final_output = None
    if args.json:
        json_data = results[0] if len(results) == 1 else results
        final_output = json.dumps(json_data, indent=2, ensure_ascii=False, default=str)
        print(final_output)

    # Dosyaya Kayıt (-o / --output)
    if args.output:
        try:
            with open(args.output, 'w', encoding='utf-8') as out_file:
                if args.json:
                    out_file.write(final_output or "")
                else:
                    out_file.write(json.dumps(results, indent=2, ensure_ascii=False, default=str))
            if not args.json:
                print(f"{Colors.GREEN}[+] Sonuçlar '{args.output}' dosyasına başarıyla kaydedildi.{Colors.RESET}")
        except Exception as e:
            print(f"{Colors.RED}[-] Dosyaya kaydetme hatası: {str(e)}{Colors.RESET}")


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print(f"\n{Colors.YELLOW}[!] İşlem kullanıcı tarafından durduruldu.{Colors.RESET}")
        sys.exit(0)
    except Exception as e:
        print(f"\n{Colors.RED}[-] Beklenmeyen genel hata: {str(e)}{Colors.RESET}")
        sys.exit(1)