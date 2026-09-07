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
import csv
import base64
import html
import re
import argparse
import datetime
import urllib.request
import urllib.parse
from typing import Dict, Any, Optional, Tuple, List
import concurrent.futures
import platform
import time
import warnings

# ssl.TLSVersion.TLSv1 vb. deprecation uyarılarını CLI çıktısını kirletmemesi için filtrele
warnings.filterwarnings('ignore', category=DeprecationWarning)

try:
    import dns.resolver
    HAS_DNSPYTHON = True
except ImportError:
    HAS_DNSPYTHON = False

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


STARTTLS_DEFAULT_PORTS = {
    'smtp': 587,
    'imap': 143,
    'pop3': 110,
    'ftp': 21,
    'ldap': 389
}


def create_client_socket(
    target_host: str,
    target_port: int,
    timeout: int = 5,
    proxy_url: Optional[str] = None
) -> socket.socket:
    """
    Hedef sunucuya doğrudan veya HTTP CONNECT Proxy üzerinden tünel açarak TCP soketi oluşturur.
    CRLF ve başlık enjeksiyonlarına karşı hedef bilgilerini temizler.
    """
    clean_host = target_host.strip().replace("\r", "").replace("\n", "")
    if not proxy_url:
        return socket.create_connection((clean_host, target_port), timeout=timeout)

    parsed = urllib.parse.urlparse(proxy_url if "://" in proxy_url else f"http://{proxy_url}")
    proxy_host = parsed.hostname
    proxy_port = parsed.port or 8080

    if not proxy_host:
        raise ValueError(f"Geçersiz proxy adresi: {proxy_url}")

    sock = socket.create_connection((proxy_host, proxy_port), timeout=timeout)
    connect_req = f"CONNECT {clean_host}:{target_port} HTTP/1.1\r\nHost: {clean_host}:{target_port}\r\n"
    if parsed.username and parsed.password:
        user_clean = parsed.username.replace("\r", "").replace("\n", "")
        pass_clean = parsed.password.replace("\r", "").replace("\n", "")
        creds = f"{user_clean}:{pass_clean}".encode("utf-8")
        auth = base64.b64encode(creds).decode("ascii")
        connect_req += f"Proxy-Authorization: Basic {auth}\r\n"
    connect_req += "User-Agent: sslpy/2.0\r\n\r\n"
    sock.sendall(connect_req.encode("latin1"))

    resp_bytes = b""
    sock.settimeout(timeout)
    max_header_size = 65536  # OOM ve DoS önleme
    while b"\r\n\r\n" not in resp_bytes:
        chunk = sock.recv(1024)
        if not chunk:
            sock.close()
            raise ConnectionError("Proxy bağlantısı beklenmedik şekilde kapandı.")
        resp_bytes += chunk
        if len(resp_bytes) > max_header_size:
            sock.close()
            raise ConnectionError("HTTP CONNECT Proxy yanıt başlığı çok büyük (OOM koruması).")

    headers_part = resp_bytes.split(b"\r\n\r\n")[0]
    status_line = headers_part.split(b"\r\n")[0].decode("latin1", errors="replace")
    if " 200 " not in status_line and not status_line.endswith(" 200"):
        sock.close()
        raise ConnectionError(f"HTTP CONNECT Proxy hatası: {status_line}")

    return sock


def perform_starttls(sock: socket.socket, protocol: str, hostname: str, timeout: int = 5) -> None:
    """
    TLS el sıkışması öncesinde STARTTLS (SMTP, IMAP, POP3, FTP, LDAP) protokol komutlarını yürütür.
    Protokol enjeksiyonu ve DoS tampon taşmalarına karşı sınırlı okuma yapar.
    """
    proto = protocol.lower().strip()
    clean_hostname = hostname.strip().replace("\r", "").replace("\n", "")
    sock.settimeout(timeout)

    def _recv_line() -> str:
        buf = b""
        max_line_len = 4096  # Sonsuz satır tamponu DoS engeli
        while not buf.endswith(b"\n") and len(buf) < max_line_len:
            ch = sock.recv(1)
            if not ch:
                break
            buf += ch
        return buf.decode("latin1", errors="replace")

    def _recv_until_code(end_code_prefix: str) -> str:
        all_lines = []
        max_lines = 100  # Sonsuz döngü engeli
        for _ in range(max_lines):
            line = _recv_line()
            if not line:
                break
            all_lines.append(line)
            if len(line) >= 4 and line[:3] == end_code_prefix and line[3] in (' ', '\r', '\n'):
                break
            elif len(line) >= 3 and line[:3] == end_code_prefix and len(line.strip()) == 3:
                break
        return "".join(all_lines)

    if proto == 'smtp':
        # 1. 220 banner
        _recv_until_code('220')
        # 2. EHLO
        sock.sendall(f"EHLO {clean_hostname}\r\n".encode("latin1"))
        # 3. 250 response
        _recv_until_code('250')
        # 4. STARTTLS
        sock.sendall(b"STARTTLS\r\n")
        # 5. 220 TLS ready
        resp = _recv_line()
        if not resp.startswith('220'):
            raise ssl.SSLError(f"SMTP STARTTLS reddedildi: {resp.strip()}")

    elif proto == 'imap':
        # 1. * OK banner
        banner_lines = 0
        while banner_lines < 50:
            line = _recv_line()
            banner_lines += 1
            if not line or line.startswith('* OK'):
                break
        # 2. a001 STARTTLS
        sock.sendall(b"a001 STARTTLS\r\n")
        # 3. a001 OK response bekle
        resp_lines = 0
        while resp_lines < 50:
            line = _recv_line()
            resp_lines += 1
            if not line:
                raise ssl.SSLError("IMAP sunucusundan yanıt alınamadı")
            if line.startswith('a001 OK'):
                break
            elif line.startswith('a001 NO') or line.startswith('a001 BAD'):
                raise ssl.SSLError(f"IMAP STARTTLS reddedildi: {line.strip()}")

    elif proto == 'pop3':
        # 1. +OK banner
        line = _recv_line()
        if not line.startswith('+OK'):
            raise ssl.SSLError(f"POP3 geçersiz banner: {line.strip()}")
        # 2. STLS
        sock.sendall(b"STLS\r\n")
        # 3. +OK response bekle
        resp = _recv_line()
        if not resp.startswith('+OK'):
            raise ssl.SSLError(f"POP3 STLS reddedildi: {resp.strip()}")

    elif proto == 'ftp':
        # 1. 220 banner
        _recv_until_code('220')
        # 2. AUTH TLS
        sock.sendall(b"AUTH TLS\r\n")
        resp = _recv_line()
        if not resp.startswith('234'):
            sock.sendall(b"AUTH SSL\r\n")
            resp2 = _recv_line()
            if not resp2.startswith('234'):
                raise ssl.SSLError(f"FTP AUTH TLS/SSL reddedildi: {resp.strip()} / {resp2.strip()}")

    elif proto == 'ldap':
        # RFC 4511 / RFC 2830 StartTLS Extended Request ASN.1 BER payload
        ldap_starttls_req = b"\x30\x1d\x02\x01\x01\x77\x18\x80\x161.3.6.1.4.1.1466.20037"
        sock.sendall(ldap_starttls_req)
        resp = sock.recv(1024)
        if not resp or len(resp) < 7:
            raise ssl.SSLError("LDAP StartTLS yanıt vermedi")
        if resp[0] != 0x30 or b"\x0a\x01\x00" not in resp:
            raise ssl.SSLError("LDAP StartTLS sunucu tarafından reddedildi")
    else:
        raise ValueError(f"Desteklenmeyen STARTTLS protokolü: {protocol}. Desteklenenler: smtp, imap, pop3, ftp, ldap")


class SSLCertInspector:
    """Gelişmiş SSL/TLS Sertifika ve Güvenlik Denetleyicisi"""

    def __init__(self, timeout: int = 5, proxy: Optional[str] = None, ca_bundle: Optional[str] = None):
        self.timeout = timeout
        self.proxy = proxy
        self.ca_bundle = ca_bundle
        self.backend = default_backend()

    def _create_connected_socket(
        self,
        host: str,
        port: int,
        timeout: Optional[int] = None,
        starttls: Optional[str] = None
    ) -> socket.socket:
        t = timeout or self.timeout
        sock = create_client_socket(host, port, timeout=t, proxy_url=self.proxy)
        if starttls:
            try:
                perform_starttls(sock, starttls, host, timeout=t)
            except Exception:
                sock.close()
                raise
        return sock

    def inspect(
        self,
        hostname: str,
        port: int = 443,
        no_verify: bool = False,
        check_ocsp: bool = True,
        check_hsts: bool = True,
        check_matrix: bool = True,
        starttls: Optional[str] = None,
        sni: Optional[str] = None,
        check_caa: bool = True,
        check_crl: bool = True,
        check_headers: bool = False
    ) -> Tuple[Dict[str, Any], Optional[str]]:
        """
        Belirtilen domain için SSL/TLS sertifikasını, sertifika güven zincirini,
        OCSP/CRL iptal durumunu, DNS CAA, HSTS/Güvenlik başlıklarını ve protokol matrisini denetler.
        """
        # IP Çözümleme
        ip_address = None
        try:
            ip_address = socket.gethostbyname(hostname)
        except socket.gaierror:
            if self.proxy:
                ip_address = "Proxy Aracılığıyla"
            else:
                return {}, f"DNS çözümleme hatası: '{hostname}' adresi bulunamadı"
        except Exception as e:
            if self.proxy:
                ip_address = "Proxy Aracılığıyla"
            else:
                return {}, f"Ağ hatası: {str(e)}"

        # Sertifika ve Zincir Çekme
        is_trusted = True
        trust_error = None
        chain_ders: List[bytes] = []
        cipher_info = None
        ssl_version = None
        selected_alpn = None
        server_name = sni or hostname

        if no_verify:
            is_trusted = None
            trust_error = "Doğrulama kullanıcı tarafından atlandı (--no-verify)"
            unverified_ctx = ssl.create_default_context()
            unverified_ctx.check_hostname = False
            unverified_ctx.verify_mode = ssl.CERT_NONE
            try:
                unverified_ctx.set_ciphers('ALL:@SECLEVEL=0')
                unverified_ctx.minimum_version = ssl.TLSVersion.TLSv1
            except Exception:
                pass
            try:
                unverified_ctx.set_alpn_protocols(['h2', 'http/1.1'])
            except Exception:
                pass
            try:
                with self._create_connected_socket(hostname, port, timeout=self.timeout, starttls=starttls) as sock:
                    with unverified_ctx.wrap_socket(sock, server_hostname=server_name) as ssock:
                        chain_ders = ssock.get_unverified_chain()
                        cipher_info = ssock.cipher()
                        ssl_version = ssock.version()
                        try:
                            selected_alpn = ssock.selected_alpn_protocol()
                        except Exception:
                            selected_alpn = None
            except socket.timeout:
                return {}, f"Bağlantı zaman aşımı ({hostname}:{port} yanıt vermedi)"
            except ConnectionRefusedError:
                return {}, f"Bağlantı reddedildi ({hostname}:{port})"
            except Exception as e:
                return {}, f"SSL/TLS bağlantı hatası: {str(e)}"
        else:
            # Standart güven doğrulamalı bağlantı (Kök CA ve Hostname kontrolü)
            if self.ca_bundle and os.path.isfile(self.ca_bundle):
                try:
                    verified_ctx = ssl.create_default_context(cafile=self.ca_bundle)
                except Exception:
                    verified_ctx = ssl.create_default_context()
            else:
                verified_ctx = ssl.create_default_context()

            try:
                verified_ctx.set_alpn_protocols(['h2', 'http/1.1'])
            except Exception:
                pass
            try:
                with self._create_connected_socket(hostname, port, timeout=self.timeout, starttls=starttls) as sock:
                    with verified_ctx.wrap_socket(sock, server_hostname=server_name) as ssock:
                        chain_ders = ssock.get_verified_chain()
                        cipher_info = ssock.cipher()
                        ssl_version = ssock.version()
                        try:
                            selected_alpn = ssock.selected_alpn_protocol()
                        except Exception:
                            selected_alpn = None
            except ssl.SSLCertVerificationError as e:
                is_trusted = False
                trust_error = e.verify_message or str(e)
                # Güven doğrulaması başarısız olduysa sertifika detaylarını analiz etmek için CERT_NONE ile bağlan
                fallback_ctx = ssl.create_default_context()
                fallback_ctx.check_hostname = False
                fallback_ctx.verify_mode = ssl.CERT_NONE
                try:
                    fallback_ctx.set_ciphers('ALL:@SECLEVEL=0')
                    fallback_ctx.minimum_version = ssl.TLSVersion.TLSv1
                except Exception:
                    pass
                try:
                    fallback_ctx.set_alpn_protocols(['h2', 'http/1.1'])
                except Exception:
                    pass
                try:
                    with self._create_connected_socket(hostname, port, timeout=self.timeout, starttls=starttls) as sock:
                        with fallback_ctx.wrap_socket(sock, server_hostname=server_name) as ssock:
                            chain_ders = ssock.get_unverified_chain()
                            cipher_info = ssock.cipher()
                            ssl_version = ssock.version()
                            try:
                                selected_alpn = ssock.selected_alpn_protocol()
                            except Exception:
                                selected_alpn = None
                except Exception as fb_err:
                    return {}, f"Sertifika doğrulanamadı ve detaylar alınamadı: {str(fb_err)}"
            except socket.timeout:
                return {}, f"Bağlantı zaman aşımı ({hostname}:{port} yanıt vermedi)"
            except ConnectionRefusedError:
                return {}, f"Bağlantı reddedildi ({hostname}:{port})"
            except ssl.SSLError as e:
                # Sunucu modern güvenli TLS sürümlerini reddetmiş olabilir (örn. sadece TLS 1.0/1.1 destekleyen eski sunucu)
                # İnceleme yapabilmek için eski TLS bağlamıyla fallback dene
                legacy_ctx = ssl.create_default_context()
                legacy_ctx.check_hostname = False
                legacy_ctx.verify_mode = ssl.CERT_NONE
                try:
                    legacy_ctx.set_ciphers('ALL:@SECLEVEL=0')
                    legacy_ctx.minimum_version = ssl.TLSVersion.TLSv1
                    legacy_ctx.set_alpn_protocols(['h2', 'http/1.1'])
                except Exception:
                    pass
                try:
                    with self._create_connected_socket(hostname, port, timeout=self.timeout, starttls=starttls) as sock:
                        with legacy_ctx.wrap_socket(sock, server_hostname=server_name) as ssock:
                            chain_ders = ssock.get_unverified_chain()
                            cipher_info = ssock.cipher()
                            ssl_version = ssock.version()
                            is_trusted = False
                            trust_error = f"Sunucu modern TLS bağlantısını reddetti, yalnızca eski {ssl_version} ile yanıt verdi"
                            try:
                                selected_alpn = ssock.selected_alpn_protocol()
                            except Exception:
                                selected_alpn = None
                except Exception:
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
        cert_info['starttls'] = starttls
        cert_info['sni'] = sni
        cert_info['proxy'] = self.proxy
        cert_info['cipher'] = {
            'name': cipher_info[0] if cipher_info else 'N/A',
            'protocol': cipher_info[1] if cipher_info else 'N/A',
            'bits': cipher_info[2] if cipher_info else 0
        }

        # ALPN Bilgisi
        cert_info['alpn'] = {
            'supported': bool(selected_alpn),
            'selected': selected_alpn or 'Yok',
            'status': f"HTTP/2 ({selected_alpn}) Aktif" if selected_alpn == 'h2' else (f"Seçilen: {selected_alpn}" if selected_alpn else "ALPN Desteklenmiyor / Belirtilmedi")
        }

        # Cipher Detaylı Kriptografik Analizi & PFS
        cert_info['cipher_details'] = self._analyze_cipher(
            cipher_info[0] if cipher_info else '',
            ssl_version or '',
            cipher_info[2] if cipher_info else 0
        )

        # 2. Güven ve Doğrulama Durumu
        cert_info['trust'] = {
            'is_trusted': is_trusted,
            'status_text': "GÜVENİLİR" if is_trusted is True else ("DOĞRULANAMADI / GÜVENSİZ" if is_trusted is False else "DOĞRULAMA ATLANDI"),
            'error': trust_error
        }

        # 3. Sertifika Güven Zinciri Analizi (Chain Analysis)
        cert_info['chain'] = self._extract_chain_info(chain_certs)

        # 4. Certificate Transparency (CT) Denetimi
        cert_info['certificate_transparency'] = self._check_certificate_transparency(leaf_cert)

        # 5. OCSP İptal Durumu Denetimi
        if check_ocsp:
            cert_info['ocsp'] = self._check_ocsp(leaf_cert, issuer_cert)
        else:
            cert_info['ocsp'] = {'status': 'SKIPPED', 'message': 'OCSP kontrolü atlandı'}

        # 5b. CRL İptal Durumu Denetimi
        if check_crl:
            cert_info['crl'] = self._check_crl(leaf_cert)
        else:
            cert_info['crl'] = {'status': 'SKIPPED', 'message': 'CRL kontrolü atlandı (--no-crl)'}

        # 5c. DNS CAA Kayıtları Denetimi (RFC 6844)
        if check_caa:
            issuer_name = cert_info.get('issuer', {}).get('organization') or cert_info.get('issuer', {}).get('common_name') or ''
            cert_info['caa'] = self._check_caa_records(hostname, issuer_name)
        else:
            cert_info['caa'] = {'status': 'SKIPPED', 'message': 'CAA kontrolü atlandı (--no-caa)'}

        # 6. Web Güvenlik Başlıkları & HSTS Denetimi
        if starttls:
            cert_info['hsts'] = {'enabled': False, 'status': f'{starttls.upper()} protokolü için HTTP başlıkları uygulanamaz'}
            cert_info['security_headers'] = {'status': f'{starttls.upper()} protokolü için HTTP başlıkları uygulanamaz'}
        elif check_hsts or check_headers:
            sec_headers = self._check_security_headers(
                hostname,
                port=port,
                verify=(is_trusted is True),
                sni=sni,
                check_all=check_headers
            )
            cert_info['security_headers'] = sec_headers
            cert_info['hsts'] = sec_headers.get('hsts', {'enabled': False, 'status': 'Eksik'})
        else:
            cert_info['hsts'] = {'enabled': False, 'status': 'HSTS kontrolü atlandı (--no-hsts)'}
            cert_info['security_headers'] = {'status': 'Güvenlik başlıkları kontrolü atlandı'}

        # 7. Protokol ve El Sıkışma Matrisi (TLS 1.0, 1.1, 1.2, 1.3 ve Zayıf Cipher Testleri)
        if check_matrix:
            cert_info['protocols'] = self._probe_protocol_matrix(hostname, port, starttls=starttls, sni=sni)
            cert_info['legacy_ciphers'] = self._probe_legacy_ciphers(hostname, port, starttls=starttls, sni=sni)
        else:
            cert_info['protocols'] = {'status': 'SKIPPED', 'message': 'Protokol matrisi kontrolü atlandı (--no-matrix)'}
            cert_info['legacy_ciphers'] = {'status': 'SKIPPED', 'message': 'Zayıf şifreleme kontrolü atlandı (--no-matrix)'}

        # 8. Güvenlik Değerlendirmesi ve Skorlama (Grade Calculation)
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
        if not responder_url.startswith(('http://', 'https://')):
            return {
                'status': 'INVALID_URL',
                'revocation_status': 'Geçersiz Şema',
                'message': f"Desteklenmeyen OCSP protokol şeması (Yalnızca HTTP/HTTPS izin verilir): {responder_url}",
                'responder_url': responder_url,
                'crl_urls': crl_urls
            }

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

            handlers = []
            if self.proxy:
                handlers.append(urllib.request.ProxyHandler({'http': self.proxy, 'https': self.proxy}))
            opener = urllib.request.build_opener(*handlers)

            # Max 1 MB OCSP yanıt sınırı (DoS/OOM koruması)
            with opener.open(http_req, timeout=self.timeout) as resp:
                resp_data = resp.read(1024 * 1024)
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

    def _check_crl(self, leaf_cert: x509.Certificate) -> Dict[str, Any]:
        """
        Sertifikadaki CRL Dağıtım Noktalarını (CRL Distribution Points) indirir
        ve yaprak sertifikanın seri numarasının iptal listesinde olup olmadığını denetler.
        """
        crl_urls: List[str] = []
        try:
            crl_ext = leaf_cert.extensions.get_extension_for_oid(ExtensionOID.CRL_DISTRIBUTION_POINTS)
            for dp in crl_ext.value:
                if dp.full_name:
                    for name in dp.full_name:
                        if isinstance(name, x509.UniformResourceIdentifier):
                            u = str(name.value).strip()
                            if u.startswith(('http://', 'https://')):
                                crl_urls.append(u)
        except Exception:
            pass

        if not crl_urls:
            return {
                'status': 'NO_CRL_URL',
                'message': 'Sertifikada geçerli HTTP/HTTPS CRL dağıtım noktası (CRL Distribution Point) tanımlı değil',
                'urls': []
            }

        target_serial = leaf_cert.serial_number
        checked_url = crl_urls[0]

        try:
            req = urllib.request.Request(
                checked_url,
                headers={'User-Agent': 'sslpy/2.0 (Certificate Revocation Checker)'}
            )
            handlers = []
            if self.proxy:
                handlers.append(urllib.request.ProxyHandler({'http': self.proxy, 'https': self.proxy}))
            opener = urllib.request.build_opener(*handlers)

            # Max 30 MB CRL boyut sınırı (DoS/OOM koruması)
            max_crl_size = 30 * 1024 * 1024
            with opener.open(req, timeout=self.timeout) as resp:
                crl_data = resp.read(max_crl_size + 1)
                if len(crl_data) > max_crl_size:
                    return {
                        'status': 'ERROR',
                        'message': f"CRL listesi izin verilen maksimum boyutu aştı (> 30 MB): {checked_url}",
                        'url': checked_url
                    }

            try:
                crl = x509.load_der_x509_crl(crl_data, self.backend)
            except Exception:
                crl = x509.load_pem_x509_crl(crl_data, self.backend)

            revoked_cert = crl.get_revoked_certificate_by_serial_number(target_serial)
            if revoked_cert:
                rev_date = revoked_cert.revocation_date_utc.isoformat() if hasattr(revoked_cert, 'revocation_date_utc') else str(revoked_cert.revocation_date)
                return {
                    'status': 'REVOKED',
                    'message': f"DİKKAT: Sertifika CRL listesinde İPTAL EDİLMİŞTİR! (İptal Tarihi: {rev_date})",
                    'url': checked_url,
                    'revocation_date': rev_date
                }
            else:
                next_update = crl.next_update_utc.isoformat() if hasattr(crl, 'next_update_utc') else str(crl.next_update)
                return {
                    'status': 'GOOD',
                    'message': f"Geçerli (CRL listesinde iptal kaydı yok, Sonraki Güncelleme: {next_update})",
                    'url': checked_url,
                    'next_update': next_update
                }
        except Exception as e:
            return {
                'status': 'ERROR',
                'message': f"CRL listesi indirilemedi veya doğrulanamadı ({str(e)})",
                'url': checked_url
            }

    def _check_caa_records(self, domain: str, issuer_name: str) -> Dict[str, Any]:
        """
        RFC 6844 uyarınca domain ve üst domainler için DNS CAA kayıtlarını sorgular
        ve aktif sertifika düzenleyicisi (Issuer) ile eşleşip eşleşmediğini doğrular.
        """
        if not HAS_DNSPYTHON:
            return {
                'supported': False,
                'status': 'dnspython kütüphanesi yüklü değil (pip install dnspython)',
                'records': [],
                'matched': None
            }

        # IP adresi girilmişse CAA sorgusu yapılamaz
        if re.match(r'^\d{1,3}(\.\d{1,3}){3}$', domain) or ':' in domain:
            return {
                'supported': False,
                'status': 'IP adresi için DNS CAA sorgulanamaz',
                'records': [],
                'matched': None
            }

        parts = domain.strip('.').split('.')
        found_records = []
        queried_domain = domain

        resolver = dns.resolver.Resolver()
        resolver.timeout = min(3, self.timeout)
        resolver.lifetime = min(3, self.timeout)

        # RFC 6844 tree climbing
        for i in range(len(parts) - 1):
            cur = '.'.join(parts[i:])
            answers = None
            try:
                answers = resolver.resolve(cur, 'CAA')
            except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN):
                continue
            except (dns.resolver.LifetimeTimeout, dns.resolver.Timeout, dns.exception.DNSException):
                # Yerel/kurumsal DNS sunucusu CAA sorgularını engelliyor veya zaman aşımına uğruyorsa genel DNS'e başvur
                try:
                    fallback_resolver = dns.resolver.Resolver(configure=False)
                    fallback_resolver.nameservers = ['8.8.8.8', '1.1.1.1']
                    fallback_resolver.timeout = min(3, self.timeout)
                    fallback_resolver.lifetime = min(3, self.timeout)
                    answers = fallback_resolver.resolve(cur, 'CAA')
                except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN):
                    continue
                except Exception:
                    break
            except Exception:
                break

            if answers:
                for rdata in answers:
                    tag_str = rdata.tag.decode('ascii', errors='ignore') if isinstance(rdata.tag, bytes) else str(rdata.tag)
                    val_str = rdata.value.decode('utf-8', errors='ignore') if isinstance(rdata.value, bytes) else str(rdata.value)
                    found_records.append({
                        'flags': rdata.flags,
                        'tag': tag_str,
                        'value': val_str
                    })
                queried_domain = cur
                break  # İlk bulunan seviyede dur

        if not found_records:
            return {
                'supported': False,
                'status': 'CAA kaydı bulunamadı (Herhangi bir CA sertifika üretebilir)',
                'queried_domain': queried_domain,
                'records': [],
                'matched': None
            }

        # Eşleşme kontrolü (Issuer matching)
        KNOWN_CAA_MAPPINGS = {
            'pki.goog': ['google', 'gts'],
            'letsencrypt.org': ['let\'s encrypt', 'letsencrypt', 'isrg'],
            'digicert.com': ['digicert', 'geotrust', 'thawte', 'rapidssl', 'encryption everywhere'],
            'sectigo.com': ['sectigo', 'comodo', 'usertrust'],
            'globalsign.com': ['globalsign', 'alphassl'],
            'amazontrust.com': ['amazon'],
            'godaddy.com': ['godaddy', 'starfield'],
            'entrust.net': ['entrust'],
            'buypass.com': ['buypass'],
            'certum.pl': ['certum', 'asseco'],
            'ssl.com': ['ssl.com'],
            'actalis.it': ['actalis'],
            'quovadisglobal.com': ['quovadis'],
        }

        issue_values = [r['value'].split(';')[0].strip().lower() for r in found_records if r['tag'] in ('issue', 'issuewild')]
        issuer_lower = issuer_name.lower()
        matched = False
        for val in issue_values:
            # 1. Doğrudan veya kök alan adı eşleşmesi
            root_val = val.split('.')[0] if '.' in val else val
            if val in issuer_lower or (len(root_val) > 2 and root_val in issuer_lower):
                matched = True
                break
            # 2. Bilinen CA eşlemeleri (örn: pki.goog -> Google Trust Services)
            mapped_aliases = KNOWN_CAA_MAPPINGS.get(val, [])
            if any(alias in issuer_lower for alias in mapped_aliases):
                matched = True
                break
            # 3. Kök değerin parça eşleşmesi (örn: 'goog' in 'google')
            if len(root_val) >= 4 and any(root_val in part for part in issuer_lower.split()):
                matched = True
                break

        if matched:
            status_text = f"Aktif ({len(found_records)} kayıt) - Düzenleyici CA ({issuer_name}) onaylı"
        else:
            status_text = f"Aktif ({len(found_records)} kayıt) - UYARI: Düzenleyici CA ({issuer_name}) CAA kaydında yetkilendirilmemiş"

        return {
            'supported': True,
            'queried_domain': queried_domain,
            'status': status_text,
            'records': found_records,
            'matched': matched
        }

    def _check_security_headers(
        self,
        hostname: str,
        port: int = 443,
        verify: bool = True,
        sni: Optional[str] = None,
        check_all: bool = False
    ) -> Dict[str, Any]:
        """
        HTTPS web sunucusundan güvenlik başlıklarını (HSTS, CSP, X-Frame-Options,
        X-Content-Type-Options, Referrer-Policy, Permissions-Policy) çeker ve analiz eder.
        """
        target_host = sni or hostname
        clean_target = target_host.strip().replace("\r", "").replace("\n", "")
        formatted_host = f"[{clean_target}]" if (":" in clean_target and not clean_target.startswith("[")) else clean_target
        url = f"https://{formatted_host}:{port}/" if port != 443 else f"https://{formatted_host}/"

        ctx = ssl.create_default_context()
        if not verify:
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
        if self.ca_bundle and os.path.isfile(self.ca_bundle):
            try:
                ctx.load_verify_locations(cafile=self.ca_bundle)
            except Exception:
                pass

        headers_result: Dict[str, Any] = {
            'hsts': {'enabled': False, 'status': 'Eksik'},
            'csp': {'enabled': False, 'status': 'Eksik'},
            'x_frame_options': {'enabled': False, 'status': 'Eksik'},
            'x_content_type_options': {'enabled': False, 'status': 'Eksik'},
            'referrer_policy': {'enabled': False, 'status': 'Eksik'},
            'permissions_policy': {'enabled': False, 'status': 'Eksik'},
            'raw_headers': {}
        }

        try:
            req = urllib.request.Request(
                url,
                headers={
                    'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) sslpy/2.0',
                    'Host': formatted_host
                },
                method='HEAD'
            )
            handlers = [urllib.request.HTTPSHandler(context=ctx)]
            if self.proxy:
                handlers.append(urllib.request.ProxyHandler({'http': self.proxy, 'https': self.proxy}))
            opener = urllib.request.build_opener(*handlers)

            resp_headers = {}
            try:
                with opener.open(req, timeout=self.timeout) as resp:
                    resp_headers = {k.lower(): v for k, v in resp.headers.items()}
            except urllib.error.HTTPError as e:
                resp_headers = {k.lower(): v for k, v in e.headers.items()}

            if check_all:
                headers_result['raw_headers'] = resp_headers

            # 1. HSTS
            if 'strict-transport-security' in resp_headers:
                h_val = resp_headers['strict-transport-security']
                max_age = None
                subdomains = False
                preload = False
                for part in h_val.split(';'):
                    cp = part.strip().lower()
                    if cp.startswith('max-age='):
                        try:
                            max_age = int(cp.split('=')[1])
                        except ValueError:
                            pass
                    elif cp == 'includesubdomains':
                        subdomains = True
                    elif cp == 'preload':
                        preload = True
                days = round(max_age / 86400, 1) if max_age is not None else None
                headers_result['hsts'] = {
                    'enabled': True,
                    'header': h_val,
                    'max_age': max_age,
                    'max_age_days': days,
                    'include_subdomains': subdomains,
                    'preload': preload,
                    'status': 'Aktif ve Güvenli' if (max_age and max_age >= 15768000) else 'Aktif (Kısa Süreli max-age)'
                }

            # 2. CSP (Content-Security-Policy)
            if 'content-security-policy' in resp_headers:
                csp_val = resp_headers['content-security-policy']
                headers_result['csp'] = {
                    'enabled': True,
                    'header': csp_val,
                    'status': 'Aktif (XSS ve Enjeksiyon Koruması)'
                }

            # 3. X-Frame-Options (Clickjacking)
            if 'x-frame-options' in resp_headers:
                xfo_val = resp_headers['x-frame-options'].upper().strip()
                headers_result['x_frame_options'] = {
                    'enabled': True,
                    'header': xfo_val,
                    'status': f'Aktif ({xfo_val} - Clickjacking Koruması)'
                }

            # 4. X-Content-Type-Options (MIME Sniffing)
            if 'x-content-type-options' in resp_headers:
                xcto_val = resp_headers['x-content-type-options'].lower().strip()
                headers_result['x_content_type_options'] = {
                    'enabled': True,
                    'header': xcto_val,
                    'status': 'Aktif (nosniff - MIME Sniffing Korumalı)' if xcto_val == 'nosniff' else f'Aktif ({xcto_val})'
                }

            # 5. Referrer-Policy
            if 'referrer-policy' in resp_headers:
                ref_val = resp_headers['referrer-policy'].strip()
                headers_result['referrer_policy'] = {
                    'enabled': True,
                    'header': ref_val,
                    'status': f'Aktif ({ref_val})'
                }

            # 6. Permissions-Policy / Feature-Policy
            if 'permissions-policy' in resp_headers or 'feature-policy' in resp_headers:
                perm_val = resp_headers.get('permissions-policy') or resp_headers.get('feature-policy')
                headers_result['permissions_policy'] = {
                    'enabled': True,
                    'header': perm_val,
                    'status': 'Aktif (Donanım/API Kısıtlamaları)'
                }

            return headers_result
        except Exception as e:
            return {
                'hsts': {'enabled': False, 'status': f'Alınamadı ({str(e)})'},
                'csp': {'enabled': False, 'status': 'Eksik'},
                'x_frame_options': {'enabled': False, 'status': 'Eksik'},
                'x_content_type_options': {'enabled': False, 'status': 'Eksik'},
                'referrer_policy': {'enabled': False, 'status': 'Eksik'},
                'permissions_policy': {'enabled': False, 'status': 'Eksik'},
                'error': str(e)
            }

    def _check_hsts(self, hostname: str, port: int = 443, verify: bool = True) -> Dict[str, Any]:
        """Geriye dönük uyumluluk için HTTP Strict Transport Security (HSTS) başlığını denetler"""
        res = self._check_security_headers(hostname, port, verify=verify)
        return res.get('hsts', {'enabled': False, 'header': None, 'status': 'Eksik'})

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

    def _probe_protocol_matrix(
        self,
        hostname: str,
        port: int,
        starttls: Optional[str] = None,
        sni: Optional[str] = None
    ) -> Dict[str, Any]:
        """
        Sunucunun desteklediği SSL/TLS sürümlerini (TLS 1.0, 1.1, 1.2, 1.3)
        bağımsız el sıkışmalarla paralel olarak test eder.
        """
        versions_to_test = [
            ('TLSv1.0', ssl.TLSVersion.TLSv1),
            ('TLSv1.1', ssl.TLSVersion.TLSv1_1),
            ('TLSv1.2', ssl.TLSVersion.TLSv1_2),
            ('TLSv1.3', ssl.TLSVersion.TLSv1_3),
        ]

        matrix_results = {}
        probe_timeout = min(3, self.timeout)
        server_name = sni or hostname

        def _test_version(ver_name: str, ver_enum: ssl.TLSVersion):
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            try:
                ctx.set_ciphers('ALL:@SECLEVEL=0')
            except Exception:
                pass
            try:
                ctx.minimum_version = ver_enum
                ctx.maximum_version = ver_enum
            except Exception as e:
                return ver_name, {
                    'supported': False,
                    'client_supported': False,
                    'cipher': None,
                    'reason': f"İstemci ortamında bu protokol desteklenmiyor ({e})"
                }

            try:
                with self._create_connected_socket(hostname, port, timeout=probe_timeout, starttls=starttls) as sock:
                    with ctx.wrap_socket(sock, server_hostname=server_name) as ssock:
                        c_info = ssock.cipher()
                        return ver_name, {
                            'supported': True,
                            'client_supported': True,
                            'version_negotiated': ssock.version(),
                            'cipher': c_info[0] if c_info else None,
                            'bits': c_info[2] if c_info else None,
                            'reason': 'Sunucu tarafından kabul edildi'
                        }
            except ssl.SSLError as e:
                reason_str = getattr(e, 'verify_message', None) or getattr(e, 'reason', None) or str(e)
                return ver_name, {
                    'supported': False,
                    'client_supported': True,
                    'cipher': None,
                    'reason': f"Reddedildi ({reason_str})"
                }
            except (socket.timeout, ConnectionResetError, ConnectionRefusedError, socket.error) as e:
                return ver_name, {
                    'supported': False,
                    'client_supported': True,
                    'cipher': None,
                    'reason': f"Bağlantı kapandı ({type(e).__name__})"
                }
            except Exception as e:
                return ver_name, {
                    'supported': False,
                    'client_supported': True,
                    'cipher': None,
                    'reason': str(e)
                }

        with concurrent.futures.ThreadPoolExecutor(max_workers=4) as executor:
            future_to_ver = {
                executor.submit(_test_version, name, ver): name
                for name, ver in versions_to_test
            }
            for future in concurrent.futures.as_completed(future_to_ver):
                name, res = future.result()
                matrix_results[name] = res

        ordered_results = {}
        for name, _ in versions_to_test:
            if name in matrix_results:
                ordered_results[name] = matrix_results[name]
        return ordered_results

    def _probe_legacy_ciphers(
        self,
        hostname: str,
        port: int,
        starttls: Optional[str] = None,
        sni: Optional[str] = None
    ) -> Dict[str, Any]:
        """
        Sunucunun PFS desteği olmayan statik RSA (kRSA) veya CBC modu
        şifreleme kümelerini kabul edip etmediğini test eder.
        """
        results = {
            'static_rsa_accepted': False,
            'static_rsa_cipher': None,
            'cbc_accepted': False,
            'cbc_cipher': None,
            'details': []
        }
        probe_timeout = min(3, self.timeout)
        server_name = sni or hostname

        # 1. Statik RSA Testi (Forward Secrecy Olmayan)
        ctx_rsa = ssl.create_default_context()
        ctx_rsa.check_hostname = False
        ctx_rsa.verify_mode = ssl.CERT_NONE
        try:
            ctx_rsa.set_ciphers('kRSA:@SECLEVEL=0')
            ctx_rsa.maximum_version = ssl.TLSVersion.TLSv1_2
            with self._create_connected_socket(hostname, port, timeout=probe_timeout, starttls=starttls) as sock:
                with ctx_rsa.wrap_socket(sock, server_hostname=server_name) as ssock:
                    c = ssock.cipher()
                    results['static_rsa_accepted'] = True
                    results['static_rsa_cipher'] = c[0] if c else None
                    results['details'].append(f"Statik RSA (kRSA) kabul ediliyor: {c[0] if c else 'N/A'}")
        except Exception:
            results['static_rsa_accepted'] = False

        # 2. CBC Modu Şifreleme Testi
        ctx_cbc = ssl.create_default_context()
        ctx_cbc.check_hostname = False
        ctx_cbc.verify_mode = ssl.CERT_NONE
        try:
            ctx_cbc.set_ciphers('AES-CBC:ECDHE-RSA-AES128-SHA:ECDHE-RSA-AES256-SHA:AES128-SHA:AES256-SHA:@SECLEVEL=0')
            ctx_cbc.maximum_version = ssl.TLSVersion.TLSv1_2
            with self._create_connected_socket(hostname, port, timeout=probe_timeout, starttls=starttls) as sock:
                with ctx_cbc.wrap_socket(sock, server_hostname=server_name) as ssock:
                    c = ssock.cipher()
                    c_name = c[0] if c else ''
                    if 'CBC' in c_name or ('SHA' in c_name and 'GCM' not in c_name and 'POLY1305' not in c_name):
                        results['cbc_accepted'] = True
                        results['cbc_cipher'] = c_name
                        results['details'].append(f"CBC modu şifreleme kabul ediliyor: {c_name}")
        except Exception:
            results['cbc_accepted'] = False

        return results

    def _analyze_cipher(self, cipher_name: str, ssl_version: str, bits: int) -> Dict[str, Any]:
        """
        Mevcut bağlantıda anlaşma sağlanan Cipher Suite'i kriptografik olarak ayrıştırır.
        """
        name = cipher_name or "N/A"
        name_upper = name.upper()
        is_tls13 = (ssl_version == "TLSv1.3") or name_upper.startswith("TLS_")

        # 1. Anahtar Değişimi (Key Exchange) ve PFS
        if is_tls13:
            key_exchange = "ECDHE / DHE (TLS 1.3 Ephemeral)"
            has_pfs = True
        elif "ECDHE" in name_upper:
            key_exchange = "ECDHE (Elliptic Curve Diffie-Hellman Ephemeral)"
            has_pfs = True
        elif "DHE" in name_upper or "EDH" in name_upper:
            key_exchange = "DHE (Diffie-Hellman Ephemeral)"
            has_pfs = True
        elif name_upper.startswith("AES") or name_upper.startswith("DES") or name_upper.startswith("RC4") or "RSA" in name_upper:
            key_exchange = "Statik RSA (Forward Secrecy Yok!)"
            has_pfs = False
        else:
            key_exchange = "Bilinmiyor"
            has_pfs = False

        # 2. Simetrik Şifreleme Algoritması (Bulk Encryption)
        if "AES_256_GCM" in name_upper or "AES256-GCM" in name_upper:
            encryption = "AES-GCM (256-bit)"
        elif "AES_128_GCM" in name_upper or "AES128-GCM" in name_upper:
            encryption = "AES-GCM (128-bit)"
        elif "CHACHA20" in name_upper:
            encryption = "ChaCha20-Poly1305 (256-bit)"
        elif "AES256-SHA" in name_upper or "AES256-CBC" in name_upper:
            encryption = "AES-CBC (256-bit)"
        elif "AES128-SHA" in name_upper or "AES128-CBC" in name_upper:
            encryption = "AES-CBC (128-bit)"
        elif "3DES" in name_upper or "DES-CBC3" in name_upper:
            encryption = "3DES (Triple DES - Zayıf)"
        elif "RC4" in name_upper:
            encryption = "RC4 (Kırılmış / Güvensiz)"
        else:
            encryption = name

        # 3. Mesaj Doğrulama (MAC / Integrity)
        if "GCM" in name_upper or "POLY1305" in name_upper or is_tls13:
            mac = "AEAD (Authenticated Encryption)"
        elif "SHA384" in name_upper:
            mac = "HMAC-SHA384"
        elif "SHA256" in name_upper:
            mac = "HMAC-SHA256"
        elif "SHA" in name_upper:
            mac = "HMAC-SHA1 (Eski)"
        elif "MD5" in name_upper:
            mac = "HMAC-MD5 (Güvensiz)"
        else:
            mac = "N/A"

        is_weak = any(w in name_upper for w in ["RC4", "3DES", "DES", "NULL", "EXPORT", "MD5", "ANON"])

        return {
            'name': name,
            'protocol': ssl_version,
            'bits': bits,
            'has_pfs': has_pfs,
            'key_exchange': key_exchange,
            'encryption': encryption,
            'mac': mac,
            'is_weak': is_weak,
            'pfs_status': "Aktif (Perfect Forward Secrecy)" if has_pfs else "Pasif (Forward Secrecy Yok!)"
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

        # 3b. CRL İptal Durumu
        crl_info = cert_info.get('crl', {})
        if crl_info.get('status') == 'REVOKED':
            score = 0
            findings.append({
                'level': 'CRITICAL',
                'message': f"DİKKAT: Sertifika CRL (Certificate Revocation List) listesinde İPTAL EDİLMİŞTİR! {crl_info.get('message', '')}"
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

        # 6. TLS Protokol Sürümü & Protokol Matrisi
        ssl_ver = cert_info.get('ssl_version', '')
        if '1.0' in ssl_ver or '1.1' in ssl_ver:
            score -= 35
            findings.append({
                'level': 'CRITICAL',
                'message': f"Kullanımdan kaldırılmış TLS sürümüyle bağlantı kuruldu ({ssl_ver}). En az TLSv1.2 veya TLSv1.3 gereklidir."
            })

        protocols = cert_info.get('protocols', {})
        if isinstance(protocols, dict) and 'status' not in protocols:
            if protocols.get('TLSv1.0', {}).get('supported'):
                score -= 30
                findings.append({
                    'level': 'CRITICAL',
                    'message': "Sunucu kullanımdan kaldırılmış güvensiz TLS 1.0 protokolünü destekliyor! (RFC 8996 / PCI-DSS ihlali)"
                })
            if protocols.get('TLSv1.1', {}).get('supported'):
                score -= 20
                findings.append({
                    'level': 'CRITICAL',
                    'message': "Sunucu kullanımdan kaldırılmış TLS 1.1 protokolünü destekliyor! (RFC 8996 / PCI-DSS ihlali)"
                })
            if protocols.get('TLSv1.3', {}).get('supported') is False and protocols.get('TLSv1.3', {}).get('client_supported') is True:
                score -= 5
                findings.append({
                    'level': 'INFO',
                    'message': "Modern TLS 1.3 protokolü sunucuda aktif değil, bağlantılar en fazla TLS 1.2 ile sınırlandırılmış."
                })

        # Cipher Suite & Perfect Forward Secrecy (PFS)
        cipher_details = cert_info.get('cipher_details', {})
        if cipher_details:
            if not cipher_details.get('has_pfs'):
                score -= 25
                findings.append({
                    'level': 'CRITICAL',
                    'message': "Aktif şifreleme kümesinde Perfect Forward Secrecy (PFS) desteği yok! Özel anahtar ele geçirilirse geçmiş trafik çözülebilir."
                })
            if cipher_details.get('is_weak'):
                score -= 35
                findings.append({
                    'level': 'CRITICAL',
                    'message': f"Güvensiz/Zayıf simetrik şifreleme kümesi tespit edildi: {cipher_details.get('name')}"
                })

        legacy = cert_info.get('legacy_ciphers', {})
        if isinstance(legacy, dict) and legacy.get('static_rsa_accepted'):
            score -= 5
            findings.append({
                'level': 'WARNING',
                'message': f"Sunucu PFS desteği olmayan eski statik RSA şifreleme kümelerini kabul ediyor ({legacy.get('static_rsa_cipher')})."
            })

        # 7. SAN Domain Eşleşmesi (Büyük/Küçük Harf Duyarsız ve IP Destekli)
        domain = cert_info.get('domain', '').lower().strip()
        san = cert_info.get('san', {})
        dns_names = [d.lower().strip() for d in san.get('DNS', [])]
        ip_names = [str(ip).lower().strip() for ip in san.get('IP', [])]
        matched = False

        if domain:
            if domain in dns_names or domain in ip_names:
                matched = True
            else:
                for d in dns_names:
                    if d.startswith('*.') and domain.endswith(d[1:]) and domain.count('.') == d.count('.'):
                        matched = True
                        break
            if not matched and not dns_names and not ip_names:
                cn = (cert_info.get('subject', {}).get('common_name') or '').lower().strip()
                if cn == domain or (cn.startswith('*.') and domain.endswith(cn[1:]) and domain.count('.') == cn.count('.')):
                    matched = True

            if not matched and (dns_names or ip_names):
                score -= 40
                findings.append({
                    'level': 'CRITICAL',
                    'message': f"Hedef domain/IP ('{cert_info.get('domain')}') sertifikanın SAN listesiyle uyuşmuyor!"
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

        # 9b. DNS CAA Kaydı Doğrulaması (RFC 6844)
        caa_info = cert_info.get('caa', {})
        if caa_info.get('supported'):
            if caa_info.get('matched') is False:
                score -= 20
                findings.append({
                    'level': 'CRITICAL',
                    'message': f"DNS CAA İhlali: {caa_info.get('queried_domain')} için CAA kayıtları mevcut ancak düzenleyici CA ({cert_info.get('issuer', {}).get('organization') or cert_info.get('issuer', {}).get('common_name')}) bu yetkili listede bulunmuyor!"
                })
            elif caa_info.get('matched') is True:
                findings.append({
                    'level': 'INFO',
                    'message': f"DNS CAA Güvenliği: CAA kaydı mevcut ({len(caa_info.get('records', []))} kayıt) ve aktif CA ile eşleşiyor."
                })

        # 9c. Genişletilmiş Web Güvenlik Başlıkları
        sec_headers = cert_info.get('security_headers', {})
        if isinstance(sec_headers, dict) and 'status' not in sec_headers:
            if not sec_headers.get('csp', {}).get('enabled'):
                score -= 5
                findings.append({
                    'level': 'INFO',
                    'message': "Content-Security-Policy (CSP) başlığı eksik. XSS ve veri sızıntılarına karşı önerilir."
                })
            if not sec_headers.get('x_frame_options', {}).get('enabled'):
                score -= 3
                findings.append({
                    'level': 'INFO',
                    'message': "X-Frame-Options başlığı eksik. Clickjacking saldırılarına karşı risklidir."
                })
            if not sec_headers.get('x_content_type_options', {}).get('enabled'):
                score -= 2
                findings.append({
                    'level': 'INFO',
                    'message': "X-Content-Type-Options: nosniff başlığı eksik. MIME sniffing engellenmelidir."
                })

        score = max(0, min(100, score))

        has_tls10 = bool(isinstance(protocols, dict) and protocols.get('TLSv1.0', {}).get('supported'))
        has_tls11 = bool(isinstance(protocols, dict) and protocols.get('TLSv1.1', {}).get('supported'))
        has_tls13 = bool(isinstance(protocols, dict) and protocols.get('TLSv1.3', {}).get('supported'))
        has_pfs = cipher_details.get('has_pfs', True) if cipher_details else True

        is_expired = cert_info.get('is_expired', False)
        is_untrusted = (cert_info.get('trust', {}).get('is_trusted') is False)
        is_revoked = (ocsp_info.get('status') == 'REVOKED' or crl_info.get('status') == 'REVOKED')

        # Harf notu belirleme (Süresi dolmuş, iptal edilmiş veya kök CA'sı geçersiz sertifikalar zorunlu F alır)
        if is_expired or is_untrusted or is_revoked:
            grade = "F"
        elif (score >= 95 and hsts.get('enabled') and cert_info.get('trust', {}).get('is_trusted') is True 
                and not has_tls10 and not has_tls11 and has_pfs and (has_tls13 or protocols.get('status') == 'SKIPPED')):
            grade = "A+"
        elif score >= 85 and not has_tls10:
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


class CSVExporter:
    """Sonuçları Excel uyumlu CSV (UTF-8 BOM) formatında dışa aktarır (CSV Formula Injection korumalı)"""

    COLUMNS = [
        "Domain", "Port", "IP Adresi", "Güvenlik Derecesi", "Skor",
        "Güven Durumu", "Hata", "STARTTLS", "SNI", "Ortak Ad (CN)",
        "Düzenleyici (Issuer)", "Başlangıç", "Bitiş", "Kalan Gün",
        "Durum", "Anahtar Tipi", "Anahtar Boyutu (bit)", "İmza Algoritması",
        "TLS 1.0", "TLS 1.1", "TLS 1.2", "TLS 1.3", "PFS (Forward Secrecy)",
        "Aktif Cipher", "ALPN", "OCSP Durumu", "CRL Durumu", "DNS CAA",
        "HSTS", "CSP", "X-Frame-Options", "X-Content-Type-Options",
        "Bulgu Sayısı", "Kritik Bulgu Sayısı", "Tarama Süresi (sn)"
    ]

    @staticmethod
    def _sanitize_cell(val: Any) -> Any:
        """
        CSV Formula Injection (CWE-1236) koruması:
        Hücre '=' , '+' , '-' , '@' , '\t' veya '\r' ile başlıyorsa formül yürütmeyi engellemek için tek tırnak ekler.
        """
        if isinstance(val, str) and val.startswith(('=', '+', '-', '@', '\t', '\r')):
            return f"'{val}"
        return val

    @classmethod
    def export(cls, results: List[Dict[str, Any]], filepath: str) -> None:
        with open(filepath, 'w', encoding='utf-8-sig', newline='') as f:
            writer = csv.writer(f)
            writer.writerow(cls.COLUMNS)

            for item in results:
                if 'error' in item and 'security_evaluation' not in item:
                    row = [
                        item.get('domain', ''), item.get('port', ''), item.get('ip_address', ''),
                        'FAIL', 0, 'BAŞARISIZ', item.get('error', ''),
                        item.get('starttls', '') or '', item.get('sni', '') or '',
                        '', '', '', '', '', 'HATA', '', '', '', '', '', '', '', '', '', '', '', '', '', '', '', '', '',
                        0, 0, item.get('scan_time', 0)
                    ]
                    writer.writerow([cls._sanitize_cell(c) for c in row])
                    continue

                eval_info = item.get('security_evaluation', {})
                grade = eval_info.get('grade', 'N/A')
                score = eval_info.get('score', 0)
                findings = eval_info.get('findings', [])
                crit_count = sum(1 for x in findings if x.get('level') == 'CRITICAL')

                trust = item.get('trust', {})
                trust_str = trust.get('status_text', 'Bilinmiyor')

                subj = item.get('subject', {})
                cn = subj.get('common_name') or subj.get('organization') or ''
                issuer = item.get('issuer', {})
                iss_str = issuer.get('organization') or issuer.get('common_name') or ''

                days = item.get('days_remaining', '')
                status = 'SÜRESİ DOLMUŞ' if item.get('is_expired') else ('YAKINDA DOLACAK' if item.get('is_expiring_soon') else 'GEÇERLİ')

                proto = item.get('protocols', {})
                has_proto = bool(proto)
                t10 = ('Açık' if proto.get('TLSv1.0', {}).get('supported') else 'Kapalı') if has_proto else 'Atlandı'
                t11 = ('Açık' if proto.get('TLSv1.1', {}).get('supported') else 'Kapalı') if has_proto else 'Atlandı'
                t12 = ('Açık' if proto.get('TLSv1.2', {}).get('supported') else 'Kapalı') if has_proto else 'Atlandı'
                t13 = ('Açık' if proto.get('TLSv1.3', {}).get('supported') else 'Kapalı') if has_proto else 'Atlandı'

                cipher_d = item.get('cipher_details', {})
                pfs = 'Aktif' if cipher_d.get('has_pfs') else 'Pasif'
                act_cipher = cipher_d.get('name', item.get('cipher', {}).get('name', ''))

                alpn = item.get('alpn', {}).get('selected', 'Yok')
                ocsp = item.get('ocsp', {}).get('status', 'Bilinmiyor')
                crl = item.get('crl', {}).get('status', 'Bilinmiyor')
                caa = item.get('caa', {}).get('status', 'Bilinmiyor')

                sec_h = item.get('security_headers', {})
                hsts = item.get('hsts', {}).get('status', 'Eksik')
                csp = sec_h.get('csp', {}).get('status', 'Eksik') if isinstance(sec_h, dict) else 'Eksik'
                xfo = sec_h.get('x_frame_options', {}).get('status', 'Eksik') if isinstance(sec_h, dict) else 'Eksik'
                xcto = sec_h.get('x_content_type_options', {}).get('status', 'Eksik') if isinstance(sec_h, dict) else 'Eksik'

                row = [
                    item.get('domain', ''),
                    item.get('port', ''),
                    item.get('ip_address', ''),
                    grade,
                    score,
                    trust_str,
                    trust.get('error', '') or '',
                    item.get('starttls', '') or 'Yok (HTTPS/TLS)',
                    item.get('sni', '') or '',
                    cn,
                    iss_str,
                    item.get('not_before', ''),
                    item.get('not_after', ''),
                    days,
                    status,
                    item.get('public_key_type', ''),
                    item.get('public_key_size', ''),
                    item.get('signature_algorithm', ''),
                    t10, t11, t12, t13,
                    pfs,
                    act_cipher,
                    alpn,
                    ocsp,
                    crl,
                    caa,
                    hsts,
                    csp,
                    xfo,
                    xcto,
                    len(findings),
                    crit_count,
                    item.get('scan_time', 0)
                ]
                writer.writerow([cls._sanitize_cell(c) for c in row])


class MarkdownExporter:
    """Sonuçları GitHub uyumlu zengin Markdown formatında dışa aktarır"""

    @classmethod
    def export(cls, results: List[Dict[str, Any]], filepath: str) -> None:
        lines = []
        now_str = datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")

        lines.append("# sslpy v2.0 - SSL/TLS Güvenlik ve Denetim Raporu\n")
        lines.append(f"> **Rapor Tarihi:** `{now_str}`  \n> **Platform:** `{platform.system()} {platform.release()}` | **Hedef Sayısı:** `{len(results)}`\n")

        # Özet Tablo
        lines.append("## Genel Güvenlik Özeti\n")
        lines.append("| Hedef | Port | Derece | Skor | Kalan Gün | TLS 1.3 | PFS | HSTS | CAA | Durum |")
        lines.append("|:---|:---:|:---:|:---:|:---:|:---:|:---:|:---:|:---:|:---|")

        for item in results:
            domain = item.get('domain', 'N/A')
            port = item.get('port', 443)
            if 'error' in item and 'security_evaluation' not in item:
                lines.append(f"| `{domain}` | `{port}` | **FAIL** | 0 | - | - | - | - | - | ❌ `{item.get('error')}` |")
                continue

            ev = item.get('security_evaluation', {})
            grade = ev.get('grade', 'F')
            score = ev.get('score', 0)
            days = item.get('days_remaining', 0)
            has_proto = bool(item.get('protocols'))
            t13 = ("✅ Açık" if item.get('protocols', {}).get('TLSv1.3', {}).get('supported') else "❌ Kapalı") if has_proto else "⚪ Atlandı"
            pfs = "✅ Aktif" if item.get('cipher_details', {}).get('has_pfs') else "❌ Pasif"
            hsts = "✅ Aktif" if item.get('hsts', {}).get('enabled') else "⚠️ Eksik"
            caa = "✅ Onaylı" if item.get('caa', {}).get('matched') else ("⚠️ Uyuşmuyor" if item.get('caa', {}).get('supported') else "ℹ️ Yok")
            status = "❌ Süresi Dolmuş" if item.get('is_expired') else ("⚠️ Yakında Dolacak" if item.get('is_expiring_soon') else "✅ Geçerli")

            lines.append(f"| `{domain}` | `{port}` | **`{grade}`** | **{score}/100** | {days} | {t13} | {pfs} | {hsts} | {caa} | {status} |")

        lines.append("\n---\n")

        # Hedef Detayları
        for item in results:
            domain = item.get('domain', 'N/A')
            port = item.get('port', 443)
            lines.append(f"## Hedef: {domain}:{port}\n")

            if 'error' in item and 'security_evaluation' not in item:
                lines.append(f"> [!CAUTION]\n> **Tarama Hatası:** {item.get('error')}\n\n")
                continue

            ev = item.get('security_evaluation', {})
            grade = ev.get('grade', 'F')
            score = ev.get('score', 0)
            trust = item.get('trust', {})
            cipher_d = item.get('cipher_details', {})
            proto = item.get('protocols', {})

            if grade in ('A+', 'A'):
                alert_type = "NOTE"
            elif grade == 'B':
                alert_type = "TIP"
            elif grade == 'C':
                alert_type = "WARNING"
            else:
                alert_type = "CAUTION"

            lines.append(f"> [!{alert_type}]")
            lines.append(f"> **Güvenlik Derecesi:** **{grade}** ({score}/100 Puan)  ")
            lines.append(f"> **Güven Doğrulaması:** {trust.get('status_text', 'N/A')}  ")
            if item.get('starttls'):
                lines.append(f"> **STARTTLS:** {item.get('starttls').upper()} el sıkışması kullanıldı  ")
            if item.get('sni'):
                lines.append(f"> **Özel SNI:** `{item.get('sni')}`  ")
            lines.append(f"> **IP Adresi:** `{item.get('ip_address', 'N/A')}` | **Tarama Süresi:** `{item.get('scan_time', 0)} sn`\n")

            # Sertifika Bilgileri Tablosu
            subj = item.get('subject', {})
            iss = item.get('issuer', {})
            lines.append("### Sertifika ve Kimlik Bilgileri\n")
            lines.append("| Parametre | Değer |")
            lines.append("|:---|:---|")
            lines.append(f"| **Ortak Ad (CN)** | `{subj.get('common_name', 'N/A')}` |")
            lines.append(f"| **Kurum (O)** | `{subj.get('organization', 'N/A')}` |")
            lines.append(f"| **Düzenleyen CA** | `{iss.get('organization') or iss.get('common_name') or 'N/A'}` |")
            lines.append(f"| **Seri No** | `{item.get('serial_number', 'N/A')}` |")
            lines.append(f"| **Geçerlilik Başlangıcı** | `{item.get('not_before', 'N/A')}` |")
            lines.append(f"| **Geçerlilik Bitişi** | `{item.get('not_after', 'N/A')}` ({item.get('days_remaining')} gün kaldı) |")
            lines.append(f"| **Açık Anahtar** | `{item.get('public_key_type')} {item.get('public_key_size')}-bit` |")
            lines.append(f"| **İmza Algoritması** | `{item.get('signature_algorithm', 'N/A')}` |")
            lines.append(f"| **SHA-256 Özeti** | `{item.get('fingerprint_sha256', 'N/A')}` |\n")

            # Protokol ve El Sıkışma Matrisi Tablosu
            lines.append("### Protokol ve Şifreleme (Handshake Matrix)\n")
            if not proto:
                lines.append("> *El sıkışma matrisi ve cipher testleri atlandı (`--no-matrix` aktif).*\n")
            else:
                lines.append("| Protokol | Durum | Şifreleme Kümesi (Cipher) |")
                lines.append("|:---|:---:|:---|")
                for p_key, p_lbl in [('TLSv1.0', 'TLS 1.0'), ('TLSv1.1', 'TLS 1.1'), ('TLSv1.2', 'TLS 1.2'), ('TLSv1.3', 'TLS 1.3')]:
                    p_info = proto.get(p_key, {})
                    if p_info.get('supported'):
                        status_badge = "🔴 Açık (Güvensiz)" if p_lbl in ['TLS 1.0', 'TLS 1.1'] else "🟢 Açık"
                        c_name = p_info.get('cipher') or 'Bilinmiyor'
                    else:
                        status_badge = "🟢 Kapalı (Güvenli)" if p_lbl in ['TLS 1.0', 'TLS 1.1'] else "⚪ Kapalı"
                        c_name = "-"
                    lines.append(f"| **{p_lbl}** | {status_badge} | `{c_name}` |")

            lines.append(f"\n- **Aktif Anlaşma:** `{cipher_d.get('name', 'N/A')}` ({cipher_d.get('bits', 0)}-bit)")
            lines.append(f"- **PFS Durumu:** {'✅ ' + cipher_d.get('pfs_status', 'Aktif') if cipher_d.get('has_pfs') else '❌ Pasif (PFS Yok)'}")
            lines.append(f"- **ALPN Protokolü:** `{item.get('alpn', {}).get('status', 'N/A')}`\n")

            # Güvenlik Kontrolleri
            lines.append("### İleri Düzey Güvenlik Kontrolleri\n")
            ocsp = item.get('ocsp', {})
            crl = item.get('crl', {})
            caa = item.get('caa', {})
            sec_h = item.get('security_headers', {})

            lines.append(f"- **OCSP Durumu:** `{ocsp.get('message', ocsp.get('status', 'N/A'))}`")
            lines.append(f"- **CRL İptal Denetimi:** `{crl.get('message', crl.get('status', 'N/A'))}`")
            lines.append(f"- **DNS CAA Denetimi:** `{caa.get('status', 'N/A')}`")
            lines.append(f"- **HSTS Güvenliği:** `{item.get('hsts', {}).get('status', 'N/A')}`")
            if isinstance(sec_h, dict) and 'status' not in sec_h:
                lines.append(f"- **CSP (Content-Security-Policy):** `{sec_h.get('csp', {}).get('status', 'Eksik')}`")
                lines.append(f"- **X-Frame-Options:** `{sec_h.get('x_frame_options', {}).get('status', 'Eksik')}`")
                lines.append(f"- **X-Content-Type-Options:** `{sec_h.get('x_content_type_options', {}).get('status', 'Eksik')}`")
            lines.append("")

            # Bulgular
            findings = ev.get('findings', [])
            if findings:
                lines.append("### Bulgular ve Güvenlik Tavsiyeleri\n")
                for f in findings:
                    lvl = f.get('level')
                    tag = "🔴 **[KRİTİK]**" if lvl == 'CRITICAL' else ("🟡 **[UYARI]**" if lvl == 'WARNING' else "🔵 **[BİLGİ]**")
                    lines.append(f"- {tag} {f.get('message')}")
                lines.append("")
            else:
                lines.append("✅ **Kritik güvenlik açığı veya konfigürasyon hatası tespit edilmedi.**\n")

            lines.append("---\n")

        with open(filepath, 'w', encoding='utf-8') as f:
            f.write("\n".join(lines))


class HTMLExporter:
    """Tek dosyada bağımsız, modern ve karanlık modlu interaktif HTML Güvenlik Paneli oluşturur"""

    @classmethod
    def export(cls, results: List[Dict[str, Any]], filepath: str) -> None:
        total = len(results)
        count_a = sum(1 for r in results if r.get('security_evaluation', {}).get('grade') in ('A+', 'A'))
        count_b_c = sum(1 for r in results if r.get('security_evaluation', {}).get('grade') in ('B', 'C'))
        count_f = sum(1 for r in results if r.get('security_evaluation', {}).get('grade') == 'F' or 'error' in r)

        scan_time = datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")

        targets_html = []
        for r in results:
            domain = html.escape(str(r.get('domain', 'N/A')))
            port = r.get('port', 443)
            ip = html.escape(str(r.get('ip_address', 'N/A')))
            scan_sec = r.get('scan_time', 0)

            if 'error' in r and 'security_evaluation' not in r:
                err_msg = html.escape(str(r.get('error', 'Bilinmeyen Hata')))
                targets_html.append(f"""
                <div class="target-card grade-f" data-domain="{html.escape(domain.lower(), quote=True)}" data-grade="F">
                    <div class="target-header">
                        <div class="target-title-wrap">
                            <span class="target-domain">{domain}:{port}</span>
                            <span class="chip chip-ip">IP: {ip}</span>
                            <span class="chip chip-fail">BAĞLANTI BAŞARISIZ</span>
                        </div>
                        <div class="grade-badge badge-f">F</div>
                    </div>
                    <div class="error-box">
                        <strong>Hata:</strong> {err_msg}
                    </div>
                </div>
                """)
                continue

            ev = r.get('security_evaluation', {})
            grade = ev.get('grade', 'F')
            score = ev.get('score', 0)
            badge_class = f"badge-{grade.lower().replace('+', 'plus')}"

            # Trust
            trust = r.get('trust', {})
            is_tr = trust.get('is_trusted')
            if is_tr is True:
                trust_chip = '<span class="chip chip-success">Zincir Doğrulandı (CA OK)</span>'
            elif is_tr is False:
                trust_chip = f'<span class="chip chip-danger">Güvensiz: {html.escape(str(trust.get("error")))}</span>'
            else:
                trust_chip = '<span class="chip chip-warning">Doğrulama Atlandı (--no-verify)</span>'

            # Days remaining
            days = r.get('days_remaining', 0)
            if r.get('is_expired'):
                days_chip = f'<span class="chip chip-danger">Süresi Dolmuş ({abs(days)} gün)</span>'
            elif r.get('is_expiring_soon'):
                days_chip = f'<span class="chip chip-warning">Yakında Dolacak ({days} gün)</span>'
            else:
                days_chip = f'<span class="chip chip-success">Geçerli ({days} gün)</span>'

            # Meta chips
            extra_chips = []
            if r.get('starttls'):
                extra_chips.append(f'<span class="chip chip-info">STARTTLS: {r["starttls"].upper()}</span>')
            if r.get('sni'):
                extra_chips.append(f'<span class="chip chip-info">SNI: {html.escape(str(r["sni"]))}</span>')
            if r.get('proxy'):
                extra_chips.append(f'<span class="chip chip-info">Proxy: {html.escape(str(r["proxy"]))}</span>')

            # Protocol Matrix Pills
            proto = r.get('protocols', {})
            proto_items = [('TLS 1.0', 'TLSv1.0'), ('TLS 1.1', 'TLSv1.1'), ('TLS 1.2', 'TLSv1.2'), ('TLS 1.3', 'TLSv1.3')]
            matrix_html = []
            if not proto:
                matrix_html.append('<div class="proto-pill proto-pill-muted" style="grid-column: span 4; text-align: center;"><span>El Sıkışma Matrisi</span><strong>Atlandı (--no-matrix)</strong></div>')
            else:
                for label, key in proto_items:
                    p_data = proto.get(key, {})
                    supp = p_data.get('supported')
                    if supp:
                        cls_name = "proto-pill-danger" if label in ('TLS 1.0', 'TLS 1.1') else "proto-pill-success"
                        matrix_html.append(f'<div class="proto-pill {cls_name}"><span>{label}</span><strong>Açık</strong></div>')
                    else:
                        cls_name = "proto-pill-safe-off" if label in ('TLS 1.0', 'TLS 1.1') else "proto-pill-muted"
                        matrix_html.append(f'<div class="proto-pill {cls_name}"><span>{label}</span><strong>Kapalı</strong></div>')
            proto_grid_html = "".join(matrix_html)

            # Cipher & PFS
            cipher_d = r.get('cipher_details', {})
            pfs_badge = '<span class="status-pill status-ok">Aktif (PFS)</span>' if cipher_d.get('has_pfs') else '<span class="status-pill status-warn">Pasif (PFS Yok)</span>'
            alpn_badge = html.escape(str(r.get('alpn', {}).get('status', 'Yok')))

            # Chain info
            chain = r.get('chain', [])
            chain_html = []
            for c in chain:
                idx = c.get('index', 0)
                role = html.escape(str(c.get('role', 'CA')))
                cn = html.escape(str(c.get('subject', {}).get('common_name') or c.get('subject', {}).get('organization') or 'N/A'))
                c_ktype = html.escape(str(c.get('public_key_type', '')))
                c_ksize = str(c.get('public_key_size', ''))
                chain_html.append(f"""
                <div class="chain-node">
                    <span class="chain-step">#{idx}</span>
                    <div class="chain-info">
                        <strong>{role}:</strong> {cn}
                        <div class="chain-meta">{c_ktype} {c_ksize}-bit | Kalan: {c.get('days_remaining')} gün</div>
                    </div>
                </div>
                """)
            chain_list_html = "".join(chain_html)

            # Security controls
            ocsp = r.get('ocsp', {})
            ocsp_st = ocsp.get('status', 'Bilinmiyor')
            ocsp_cls = "status-ok" if ocsp_st == 'GOOD' else ("status-err" if ocsp_st == 'REVOKED' else "status-warn")

            crl = r.get('crl', {})
            crl_st = crl.get('status', 'Bilinmiyor')
            crl_cls = "status-ok" if crl_st == 'GOOD' else ("status-err" if crl_st == 'REVOKED' else "status-muted")

            caa = r.get('caa', {})
            if caa.get('supported'):
                caa_st = "Onaylı" if caa.get('matched') is True else "Uyuşmuyor!"
                caa_cls = "status-ok" if caa.get('matched') is True else "status-err"
            else:
                caa_st = "Kayıt Yok"
                caa_cls = "status-muted"

            hsts = r.get('hsts', {})
            hsts_st = "Aktif" if hsts.get('enabled') else "Eksik"
            hsts_cls = "status-ok" if hsts.get('enabled') else "status-warn"

            sec_h = r.get('security_headers', {})
            csp_st = "Aktif" if sec_h.get('csp', {}).get('enabled') else "Eksik"
            csp_cls = "status-ok" if sec_h.get('csp', {}).get('enabled') else "status-muted"

            xfo_st = "Aktif" if sec_h.get('x_frame_options', {}).get('enabled') else "Eksik"
            xfo_cls = "status-ok" if sec_h.get('x_frame_options', {}).get('enabled') else "status-muted"

            # Findings
            findings = ev.get('findings', [])
            findings_html = []
            for f in findings:
                lvl = f.get('level', 'INFO')
                lvl_cls = "finding-crit" if lvl == 'CRITICAL' else ("finding-warn" if lvl == 'WARNING' else "finding-info")
                lvl_lbl = "KRİTİK" if lvl == 'CRITICAL' else ("UYARI" if lvl == 'WARNING' else "BİLGİ")
                findings_html.append(f"""
                <div class="finding-item {lvl_cls}">
                    <span class="finding-badge">{lvl_lbl}</span>
                    <span class="finding-text">{html.escape(str(f.get('message', '')))}</span>
                </div>
                """)
            findings_list_html = "".join(findings_html) if findings_html else '<div class="finding-empty">✅ Kritik güvenlik açığı veya konfigürasyon hatası tespit edilmedi.</div>'

            # Subject & Issuer
            subj_cn = html.escape(str(r.get('subject', {}).get('common_name') or 'N/A'))
            iss_org = html.escape(str(r.get('issuer', {}).get('organization') or r.get('issuer', {}).get('common_name') or 'N/A'))
            fp256 = html.escape(str(r.get('fingerprint_sha256', 'N/A')))
            k_type = html.escape(str(r.get('public_key_type', 'N/A')))
            k_size = str(r.get('public_key_size', 'N/A'))
            sig_alg = html.escape(str(r.get('signature_algorithm', 'N/A')))

            targets_html.append(f"""
            <div class="target-card grade-{grade.lower().replace('+', 'plus')}" data-domain="{html.escape(domain.lower(), quote=True)}" data-grade="{html.escape(grade, quote=True)}">
                <div class="target-header">
                    <div class="target-title-wrap">
                        <div class="target-domain-row">
                            <span class="target-domain">{domain}:{port}</span>
                            <span class="chip chip-ip">IP: {ip}</span>
                            {days_chip}
                            {trust_chip}
                            {' '.join(extra_chips)}
                        </div>
                        <div class="target-sub-row">
                            <span>Düzenleyen: <strong>{iss_org}</strong></span> |
                            <span>Tarama: <strong>{scan_sec} sn</strong></span>
                        </div>
                    </div>
                    <div class="grade-badge {badge_class}">
                        <span class="grade-letter">{grade}</span>
                        <span class="grade-score">{score}/100</span>
                    </div>
                </div>

                <div class="target-body-grid">
                    <!-- Sütun 1: Sertifika ve Anahtar Bilgileri -->
                    <div class="panel-box">
                        <h4 class="panel-title">Sertifika ve Kimlik</h4>
                        <table class="data-table">
                            <tr><td>Ortak Ad (CN):</td><td><strong>{subj_cn}</strong></td></tr>
                            <tr><td>Düzenleyen CA:</td><td>{iss_org}</td></tr>
                            <tr><td>Açık Anahtar:</td><td>{k_type} {k_size}-bit</td></tr>
                            <tr><td>İmza Algoritması:</td><td>{sig_alg}</td></tr>
                            <tr><td>Geçerlilik Bitiş:</td><td>{html.escape(str(r.get('not_after', 'N/A')))}</td></tr>
                            <tr><td>SHA-256 Özeti:</td><td class="code-cell" title="Kopyalamak için tıklayın" data-copy="{fp256}" onclick="navigator.clipboard.writeText(this.getAttribute('data-copy'))">{fp256[:20]}...</td></tr>
                        </table>
                    </div>

                    <!-- Sütun 2: Protokol ve Handshake Matrix -->
                    <div class="panel-box">
                        <h4 class="panel-title">Protokol & Handshake Matrix</h4>
                        <div class="proto-grid">{proto_grid_html}</div>
                        <div class="divider"></div>
                        <table class="data-table">
                            <tr><td>Aktif Cipher:</td><td class="code-cell">{html.escape(str(cipher_d.get('name', 'N/A')))}</td></tr>
                            <tr><td>Forward Secrecy:</td><td>{pfs_badge}</td></tr>
                            <tr><td>ALPN:</td><td>{alpn_badge}</td></tr>
                        </table>
                    </div>

                    <!-- Sütun 3: Güvenlik Denetimleri -->
                    <div class="panel-box">
                        <h4 class="panel-title">Gelişmiş Güvenlik Kontrolleri</h4>
                        <table class="data-table">
                            <tr><td>OCSP Durumu:</td><td><span class="status-pill {ocsp_cls}">{ocsp_st}</span></td></tr>
                            <tr><td>CRL İptal Denetimi:</td><td><span class="status-pill {crl_cls}">{crl_st}</span></td></tr>
                            <tr><td>DNS CAA Kaydı:</td><td><span class="status-pill {caa_cls}">{caa_st}</span></td></tr>
                            <tr><td>HSTS Koruma:</td><td><span class="status-pill {hsts_cls}">{hsts_st}</span></td></tr>
                            <tr><td>CSP (Content-Security):</td><td><span class="status-pill {csp_cls}">{csp_st}</span></td></tr>
                            <tr><td>X-Frame-Options:</td><td><span class="status-pill {xfo_cls}">{xfo_st}</span></td></tr>
                        </table>
                    </div>
                </div>

                <!-- Sertifika Zinciri -->
                <div class="chain-box">
                    <h5 class="chain-title">Sertifika Güven Zinciri ({len(chain)} Sertifika)</h5>
                    <div class="chain-flex">{chain_list_html}</div>
                </div>

                <!-- Bulgular -->
                <div class="findings-box">
                    <h5 class="findings-title">Güvenlik Bulguları ve İyileştirmeler ({len(findings)})</h5>
                    <div class="findings-list">{findings_list_html}</div>
                </div>
            </div>
            """)

        cards_combined = "\n".join(targets_html)

        html_content = f"""<!DOCTYPE html>
<html lang="tr">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>sslpy v2.0 - SSL/TLS Güvenlik ve Denetim Raporu</title>
    <style>
        :root {{
            --bg: #090d16;
            --surface: #111827;
            --surface-sub: #1a2234;
            --border: #26334d;
            --text: #f8fafc;
            --text-muted: #94a3b8;
            --blue: #38bdf8;
            --green: #10b981;
            --yellow: #f59e0b;
            --red: #ef4444;
            --font: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, "Helvetica Neue", Arial, sans-serif;
        }}
        * {{ box-sizing: border-box; margin: 0; padding: 0; }}
        body {{
            background-color: var(--bg);
            color: var(--text);
            font-family: var(--font);
            line-height: 1.5;
            padding: 24px;
        }}
        .dashboard-container {{ max-width: 1240px; margin: 0 auto; }}
        
        /* Header */
        .dash-header {{
            display: flex;
            justify-content: space-between;
            align-items: center;
            padding-bottom: 20px;
            border-bottom: 1px solid var(--border);
            margin-bottom: 24px;
        }}
        .brand-title {{
            font-size: 26px;
            font-weight: 800;
            background: linear-gradient(135deg, #38bdf8 0%, #818cf8 100%);
            -webkit-background-clip: text;
            -webkit-text-fill-color: transparent;
        }}
        .brand-subtitle {{ font-size: 13px; color: var(--text-muted); margin-top: 4px; }}
        
        /* KPI Cards */
        .kpi-grid {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(220px, 1fr));
            gap: 16px;
            margin-bottom: 24px;
        }}
        .kpi-card {{
            background: var(--surface);
            border: 1px solid var(--border);
            border-radius: 12px;
            padding: 16px 20px;
            display: flex;
            flex-direction: column;
            gap: 6px;
        }}
        .kpi-label {{ font-size: 13px; color: var(--text-muted); font-weight: 500; }}
        .kpi-value {{ font-size: 30px; font-weight: 800; }}
        .kpi-value.val-blue {{ color: var(--blue); }}
        .kpi-value.val-green {{ color: var(--green); }}
        .kpi-value.val-yellow {{ color: var(--yellow); }}
        .kpi-value.val-red {{ color: var(--red); }}

        /* Toolbar */
        .toolbar {{
            display: flex;
            flex-wrap: wrap;
            justify-content: space-between;
            align-items: center;
            gap: 12px;
            margin-bottom: 24px;
            background: var(--surface);
            padding: 12px 16px;
            border-radius: 10px;
            border: 1px solid var(--border);
        }}
        .search-box {{
            flex: 1;
            min-width: 250px;
            background: var(--surface-sub);
            border: 1px solid var(--border);
            border-radius: 6px;
            padding: 8px 14px;
            color: var(--text);
            font-size: 14px;
            outline: none;
        }}
        .search-box:focus {{ border-color: var(--blue); }}
        .filter-buttons {{ display: flex; gap: 6px; }}
        .btn-filter {{
            background: var(--surface-sub);
            border: 1px solid var(--border);
            color: var(--text-muted);
            padding: 6px 14px;
            border-radius: 6px;
            font-size: 13px;
            font-weight: 600;
            cursor: pointer;
            transition: all 0.2s;
        }}
        .btn-filter.active, .btn-filter:hover {{
            background: var(--blue);
            color: #0b0f19;
            border-color: var(--blue);
        }}

        /* Target Cards */
        .target-card {{
            background: var(--surface);
            border: 1px solid var(--border);
            border-radius: 12px;
            margin-bottom: 20px;
            padding: 20px;
            transition: transform 0.15s ease, border-color 0.15s ease;
        }}
        .target-card:hover {{ border-color: #3b82f6; }}
        
        .target-header {{
            display: flex;
            justify-content: space-between;
            align-items: center;
            border-bottom: 1px solid var(--border);
            padding-bottom: 16px;
            margin-bottom: 16px;
        }}
        .target-title-wrap {{ display: flex; flex-direction: column; gap: 6px; }}
        .target-domain-row {{ display: flex; align-items: center; flex-wrap: wrap; gap: 10px; }}
        .target-domain {{ font-size: 20px; font-weight: 700; color: #fff; }}
        .target-sub-row {{ font-size: 13px; color: var(--text-muted); }}

        /* Chips */
        .chip {{
            font-size: 11px;
            font-weight: 600;
            padding: 3px 8px;
            border-radius: 6px;
            text-transform: uppercase;
        }}
        .chip-ip {{ background: #1e293b; color: #94a3b8; border: 1px solid #334155; }}
        .chip-success {{ background: rgba(16, 185, 129, 0.15); color: var(--green); border: 1px solid rgba(16, 185, 129, 0.3); }}
        .chip-warning {{ background: rgba(245, 158, 11, 0.15); color: var(--yellow); border: 1px solid rgba(245, 158, 11, 0.3); }}
        .chip-danger {{ background: rgba(239, 68, 68, 0.15); color: var(--red); border: 1px solid rgba(239, 68, 68, 0.3); }}
        .chip-info {{ background: rgba(56, 189, 248, 0.15); color: var(--blue); border: 1px solid rgba(56, 189, 248, 0.3); }}
        .chip-fail {{ background: #dc2626; color: #fff; }}

        /* Grade Badges */
        .grade-badge {{
            min-width: 72px;
            height: 72px;
            border-radius: 14px;
            display: flex;
            flex-direction: column;
            justify-content: center;
            align-items: center;
            font-weight: 800;
            border: 2px solid transparent;
        }}
        .grade-letter {{ font-size: 26px; line-height: 1; }}
        .grade-score {{ font-size: 11px; opacity: 0.85; margin-top: 2px; }}
        .badge-aplus, .badge-a {{ background: rgba(16, 185, 129, 0.15); color: var(--green); border-color: var(--green); }}
        .badge-b {{ background: rgba(56, 189, 248, 0.15); color: var(--blue); border-color: var(--blue); }}
        .badge-c {{ background: rgba(245, 158, 11, 0.15); color: var(--yellow); border-color: var(--yellow); }}
        .badge-f {{ background: rgba(239, 68, 68, 0.15); color: var(--red); border-color: var(--red); }}

        /* 3-Col Grid */
        .target-body-grid {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(310px, 1fr));
            gap: 16px;
            margin-bottom: 16px;
        }}
        .panel-box {{
            background: var(--surface-sub);
            border: 1px solid var(--border);
            border-radius: 8px;
            padding: 14px 16px;
        }}
        .panel-title {{ font-size: 14px; color: var(--blue); margin-bottom: 12px; font-weight: 700; }}
        .data-table {{ width: 100%; border-collapse: collapse; font-size: 12.5px; }}
        .data-table td {{ padding: 5px 0; }}
        .data-table td:first-child {{ color: var(--text-muted); width: 45%; }}
        .code-cell {{ font-family: monospace; font-size: 12px; color: #cbd5e1; cursor: pointer; }}
        .code-cell:hover {{ color: var(--blue); }}
        .divider {{ height: 1px; background: var(--border); margin: 10px 0; }}

        /* Protocol Grid */
        .proto-grid {{ display: grid; grid-template-columns: repeat(4, 1fr); gap: 6px; margin-bottom: 8px; }}
        .proto-pill {{
            border-radius: 6px;
            padding: 6px 4px;
            text-align: center;
            font-size: 11px;
            display: flex;
            flex-direction: column;
            gap: 2px;
        }}
        .proto-pill-success {{ background: rgba(16, 185, 129, 0.15); color: var(--green); border: 1px solid rgba(16, 185, 129, 0.3); }}
        .proto-pill-danger {{ background: rgba(239, 68, 68, 0.2); color: var(--red); border: 1px solid var(--red); }}
        .proto-pill-safe-off {{ background: rgba(16, 185, 129, 0.08); color: var(--green); border: 1px solid rgba(16, 185, 129, 0.15); opacity: 0.7; }}
        .proto-pill-muted {{ background: #1e293b; color: #64748b; border: 1px solid #334155; }}

        /* Status Pills */
        .status-pill {{ font-size: 11px; font-weight: 600; padding: 2px 7px; border-radius: 4px; }}
        .status-ok {{ background: rgba(16, 185, 129, 0.2); color: var(--green); }}
        .status-warn {{ background: rgba(245, 158, 11, 0.2); color: var(--yellow); }}
        .status-err {{ background: rgba(239, 68, 68, 0.2); color: var(--red); }}
        .status-muted {{ background: #334155; color: #94a3b8; }}

        /* Chain */
        .chain-box {{
            background: var(--surface-sub);
            border: 1px solid var(--border);
            border-radius: 8px;
            padding: 12px 16px;
            margin-bottom: 16px;
        }}
        .chain-title {{ font-size: 13px; color: #cbd5e1; margin-bottom: 10px; font-weight: 600; }}
        .chain-flex {{ display: flex; flex-direction: column; gap: 8px; }}
        .chain-node {{ display: flex; align-items: center; gap: 12px; font-size: 12px; }}
        .chain-step {{
            background: #273549;
            color: var(--blue);
            font-weight: 700;
            padding: 3px 8px;
            border-radius: 4px;
            font-size: 11px;
        }}
        .chain-meta {{ font-size: 11px; color: var(--text-muted); }}

        /* Findings */
        .findings-box {{
            background: var(--surface-sub);
            border: 1px solid var(--border);
            border-radius: 8px;
            padding: 14px 16px;
        }}
        .findings-title {{ font-size: 13px; color: #cbd5e1; margin-bottom: 10px; font-weight: 600; }}
        .findings-list {{ display: flex; flex-direction: column; gap: 6px; }}
        .finding-item {{
            display: flex;
            align-items: center;
            gap: 10px;
            padding: 6px 10px;
            border-radius: 6px;
            font-size: 12px;
        }}
        .finding-crit {{ background: rgba(239, 68, 68, 0.1); border-left: 3px solid var(--red); }}
        .finding-warn {{ background: rgba(245, 158, 11, 0.1); border-left: 3px solid var(--yellow); }}
        .finding-info {{ background: rgba(56, 189, 248, 0.1); border-left: 3px solid var(--blue); }}
        .finding-badge {{ font-weight: 700; font-size: 10px; }}
        .finding-empty {{ font-size: 12px; color: var(--green); }}
        .error-box {{ background: rgba(239, 68, 68, 0.15); border: 1px solid var(--red); color: #fca5a5; padding: 12px; border-radius: 8px; font-size: 13px; }}

        /* Footer */
        .dash-footer {{
            text-align: center;
            font-size: 12px;
            color: var(--text-muted);
            margin-top: 30px;
            padding-top: 20px;
            border-top: 1px solid var(--border);
        }}
    </style>
</head>
<body>
    <div class="dashboard-container">
        <!-- Header -->
        <header class="dash-header">
            <div>
                <h1 class="brand-title">sslpy v2.0 Dashboard</h1>
                <div class="brand-subtitle">Kapsamlı SSL/TLS Sertifika ve Güvenlik Denetim Paneli &bull; {scan_time}</div>
            </div>
            <div style="font-size: 12px; color: var(--text-muted); text-align: right;">
                <div>Platform: {platform.system()} {platform.release()}</div>
                <div>Motor: Python {platform.python_version()}</div>
            </div>
        </header>

        <!-- KPI Summary Cards -->
        <section class="kpi-grid">
            <div class="kpi-card">
                <span class="kpi-label">Toplam Taranan Hedef</span>
                <span class="kpi-value val-blue">{total}</span>
            </div>
            <div class="kpi-card">
                <span class="kpi-label">Yüksek Güvenlik (A+ / A)</span>
                <span class="kpi-value val-green">{count_a}</span>
            </div>
            <div class="kpi-card">
                <span class="kpi-label">Orta Güvenlik (B / C)</span>
                <span class="kpi-value val-yellow">{count_b_c}</span>
            </div>
            <div class="kpi-card">
                <span class="kpi-label">Kritik / Başarısız (F)</span>
                <span class="kpi-value val-red">{count_f}</span>
            </div>
        </section>

        <!-- Search & Filter Toolbar -->
        <div class="toolbar">
            <input type="text" id="domainSearch" class="search-box" placeholder="Domain, IP veya port filtrele... (örn: google, 443)">
            <div class="filter-buttons">
                <button class="btn-filter active" data-filter="ALL">Tümü ({total})</button>
                <button class="btn-filter" data-filter="A+">A+</button>
                <button class="btn-filter" data-filter="A">A</button>
                <button class="btn-filter" data-filter="B">B</button>
                <button class="btn-filter" data-filter="C">C</button>
                <button class="btn-filter" data-filter="F">F</button>
            </div>
        </div>

        <!-- Target Cards Container -->
        <main id="cardsContainer">
            {cards_combined}
        </main>

        <footer class="dash-footer">
            sslpy v2.0 &bull; Advanced Cross-Platform SSL/TLS Certificate Security Inspector &bull; Otomatik oluşturuldu.
        </footer>
    </div>

    <script>
        const searchInput = document.getElementById('domainSearch');
        const filterButtons = document.querySelectorAll('.btn-filter');
        let currentFilter = 'ALL';

        function applyFilters() {{
            const query = searchInput.value.trim().toLowerCase();
            const cards = document.querySelectorAll('.target-card');

            cards.forEach(card => {{
                const domain = card.getAttribute('data-domain') || '';
                const grade = card.getAttribute('data-grade') || '';
                const matchesSearch = !query || domain.includes(query);
                const matchesGrade = (currentFilter === 'ALL') || (grade === currentFilter);

                if (matchesSearch && matchesGrade) {{
                    card.style.display = '';
                }} else {{
                    card.style.display = 'none';
                }}
            }});
        }}

        searchInput.addEventListener('input', applyFilters);

        filterButtons.forEach(btn => {{
            btn.addEventListener('click', () => {{
                filterButtons.forEach(b => b.classList.remove('active'));
                btn.classList.add('active');
                currentFilter = btn.getAttribute('data-filter');
                applyFilters();
            }});
        }});
    </script>
</body>
</html>"""

        with open(filepath, 'w', encoding='utf-8') as f:
            f.write(html_content)


class SSLPyCLI:
    """sslpy Terminal ve Raporlama Arayüzü"""

    def __init__(self, inspector: SSLCertInspector, json_output: bool = False, verbose: bool = False):
        self.inspector = inspector
        self.json_output = json_output
        self.verbose = verbose

    def inspect_target(
        self,
        domain: str,
        port: int = 443,
        no_verify: bool = False,
        check_ocsp: bool = True,
        check_hsts: bool = True,
        check_matrix: bool = True,
        starttls: Optional[str] = None,
        sni: Optional[str] = None,
        check_caa: bool = True,
        check_crl: bool = True,
        check_headers: bool = False
    ) -> Dict[str, Any]:
        """Tek bir hedefi denetler ve sonuç nesnesini döndürür"""
        try:
            ascii_domain = idna.encode(domain).decode('ascii')
        except Exception:
            ascii_domain = domain

        start_time = time.time()
        cert_info, error = self.inspector.inspect(
            ascii_domain,
            port=port,
            no_verify=no_verify,
            check_ocsp=check_ocsp,
            check_hsts=check_hsts,
            check_matrix=check_matrix,
            starttls=starttls,
            sni=sni,
            check_caa=check_caa,
            check_crl=check_crl,
            check_headers=check_headers
        )
        elapsed = time.time() - start_time

        if error:
            return {
                'domain': domain,
                'port': port,
                'starttls': starttls,
                'sni': sni,
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
        if info.get('starttls'):
            print(f"    {Colors.BOLD}STARTTLS Protokolü:{Colors.RESET} {Colors.CYAN}{info['starttls'].upper()}{Colors.RESET}")
        if info.get('sni'):
            print(f"    {Colors.BOLD}Özel SNI Başlığı:{Colors.RESET} {Colors.WHITE}{info['sni']}{Colors.RESET}")
        if info.get('proxy'):
            print(f"    {Colors.BOLD}Proxy Tüneli:{Colors.RESET} {Colors.WHITE}{info['proxy']}{Colors.RESET}")
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

        # 5. Protokol ve Kriptografik El Sıkışma Matrisi (Handshake Matrix)
        protocols = info.get('protocols', {})
        alpn = info.get('alpn', {})
        cipher_det = info.get('cipher_details', {})
        legacy = info.get('legacy_ciphers', {})

        print(f"\n{Colors.BOLD}{Colors.BLUE}[+] Protokol ve Şifreleme Matrisi (Handshake Matrix):{Colors.RESET}")
        if isinstance(protocols, dict) and protocols.get('status') == 'SKIPPED':
            print(f"  • {Colors.DIM}Protokol matrisi ve cipher testleri atlandı (--no-matrix aktif){Colors.RESET}")
        elif isinstance(protocols, dict) and protocols:
            print(f"  • {Colors.BOLD}TLS Protokol Desteği:{Colors.RESET}")
            ver_items = [('TLSv1.0', '1.0'), ('TLSv1.1', '1.1'), ('TLSv1.2', '1.2'), ('TLSv1.3', '1.3')]
            for i, (k, short_name) in enumerate(ver_items):
                prefix = "└─►" if i == len(ver_items) - 1 else "├─►"
                p_data = protocols.get(k, {})
                if p_data.get('supported'):
                    c_name = p_data.get('cipher') or 'Bilinmiyor'
                    if short_name in ['1.0', '1.1']:
                        badge = f"{Colors.RED}[AÇIK - GÜVENSİZ]{Colors.RESET}"
                    elif short_name == '1.3':
                        badge = f"{Colors.GREEN}[AÇIK - EN YÜKSEK GÜVENLİK]{Colors.RESET}"
                    else:
                        badge = f"{Colors.GREEN}[AÇIK]{Colors.RESET}"
                    print(f"    {prefix} {Colors.BOLD}TLS {short_name}:{Colors.RESET} {badge} {Colors.DIM}({c_name}){Colors.RESET}")
                else:
                    if p_data.get('client_supported') is False:
                        badge = f"{Colors.DIM}[İSTEMCİ DESTEKLEMİYOR]{Colors.RESET}"
                    else:
                        badge = f"{Colors.GREEN}[KAPALI - GÜVENLİ]{Colors.RESET}" if short_name in ['1.0', '1.1'] else f"{Colors.YELLOW}[KAPALI]{Colors.RESET}"
                    print(f"    {prefix} {Colors.BOLD}TLS {short_name}:{Colors.RESET} {badge}")

        # ALPN
        if alpn.get('supported'):
            alpn_badge = f"{Colors.GREEN}[OK] {alpn.get('status')}{Colors.RESET}"
        else:
            alpn_badge = f"{Colors.DIM}[INFO] {alpn.get('status', 'Desteklenmiyor')}{Colors.RESET}"
        print(f"  • {Colors.BOLD}ALPN Protokolü:{Colors.RESET} {alpn_badge}")

        # Perfect Forward Secrecy (PFS)
        if cipher_det.get('has_pfs'):
            pfs_badge = f"{Colors.GREEN}[OK] AKTİF ({cipher_det.get('key_exchange')}){Colors.RESET}"
        else:
            pfs_badge = f"{Colors.RED}[UYARI] PASİF (Forward Secrecy Yok!){Colors.RESET}"
        print(f"  • {Colors.BOLD}Perfect Forward Secrecy (PFS):{Colors.RESET} {pfs_badge}")

        # Aktif Şifreleme Kümesi Detayları
        print(f"  • {Colors.BOLD}Aktif Şifreleme Kümesi:{Colors.RESET} {cipher_det.get('name', 'N/A')} ({cipher_det.get('bits', 0)}-bit)")
        print(f"    {Colors.DIM}Anahtar Değişimi: {cipher_det.get('key_exchange')} | Simetrik: {cipher_det.get('encryption')} | MAC: {cipher_det.get('mac')}{Colors.RESET}")

        # Zayıf / Eski Cipher Probları
        if legacy and legacy.get('status') != 'SKIPPED':
            rsa_badge = f"{Colors.YELLOW}[KABUL EDİLİYOR]{Colors.RESET} {Colors.DIM}({legacy.get('static_rsa_cipher')}){Colors.RESET}" if legacy.get('static_rsa_accepted') else f"{Colors.GREEN}[REDDEDİLDİ - GÜVENLİ]{Colors.RESET}"
            cbc_badge = f"{Colors.YELLOW}[KABUL EDİLİYOR]{Colors.RESET} {Colors.DIM}({legacy.get('cbc_cipher')}){Colors.RESET}" if legacy.get('cbc_accepted') else f"{Colors.GREEN}[REDDEDİLDİ - GÜVENLİ]{Colors.RESET}"
            print(f"  • {Colors.BOLD}Eski/Zayıf Cipher Kabulü:{Colors.RESET}")
            print(f"    ├─► Statik RSA (kRSA - No PFS): {rsa_badge}")
            print(f"    └─► CBC Modu Şifreleme:        {cbc_badge}")

        # 6. İleri Düzey Güvenlik Kontrolleri
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

        # CRL İptal Listesi Denetimi
        crl_data = info.get('crl', {})
        crl_st = crl_data.get('status')
        if crl_st == 'GOOD':
            crl_badge = f"{Colors.GREEN}[OK] GEÇERLİ (CRL listesinde iptal kaydı yok){Colors.RESET}"
        elif crl_st == 'REVOKED':
            crl_badge = f"{Colors.RED}[REVOKED] İPTAL EDİLMİŞ! ({crl_data.get('revocation_date')}){Colors.RESET}"
        elif crl_st == 'NO_CRL_URL':
            crl_badge = f"{Colors.DIM}[INFO] Sertifikada CRL adresi tanımlı değil{Colors.RESET}"
        else:
            crl_badge = f"{Colors.YELLOW}[WARN] {crl_data.get('message', crl_st)}{Colors.RESET}"
        print(f"  • {Colors.BOLD}CRL İptal Listesi:{Colors.RESET} {crl_badge}")

        # DNS CAA Kaydı Denetimi (RFC 6844)
        caa_data = info.get('caa', {})
        if caa_data.get('supported'):
            if caa_data.get('matched') is True:
                caa_badge = f"{Colors.GREEN}[OK] {caa_data.get('status')}{Colors.RESET}"
            elif caa_data.get('matched') is False:
                caa_badge = f"{Colors.RED}[UYARI] {caa_data.get('status')}{Colors.RESET}"
            else:
                caa_badge = f"{Colors.DIM}{caa_data.get('status')}{Colors.RESET}"
        else:
            caa_badge = f"{Colors.DIM}[INFO] {caa_data.get('status', 'CAA kaydı yok')}{Colors.RESET}"
        print(f"  • {Colors.BOLD}DNS CAA Kayıtları:{Colors.RESET} {caa_badge}")

        # HSTS Durumu
        hsts = info.get('hsts', {})
        if hsts.get('enabled'):
            preload_str = ", preload" if hsts.get('preload') else ""
            sub_str = ", includeSubDomains" if hsts.get('include_subdomains') else ""
            hsts_badge = f"{Colors.GREEN}[OK] AKTİF{Colors.RESET} (max-age={hsts.get('max_age')} [{hsts.get('max_age_days')} gün]{sub_str}{preload_str})"
        else:
            hsts_badge = f"{Colors.YELLOW}[WARN] EKSİK{Colors.RESET} {Colors.DIM}({hsts.get('status')}){Colors.RESET}"
        print(f"  • {Colors.BOLD}HSTS Güvenliği:{Colors.RESET} {hsts_badge}")

        # Web Güvenlik Başlıkları
        sec_h = info.get('security_headers', {})
        if isinstance(sec_h, dict) and 'status' not in sec_h:
            csp_b = f"{Colors.GREEN}[OK] AKTİF{Colors.RESET}" if sec_h.get('csp', {}).get('enabled') else f"{Colors.YELLOW}[EKSİK]{Colors.RESET}"
            xfo_b = f"{Colors.GREEN}[OK] {sec_h.get('x_frame_options', {}).get('header')}{Colors.RESET}" if sec_h.get('x_frame_options', {}).get('enabled') else f"{Colors.YELLOW}[EKSİK]{Colors.RESET}"
            xcto_b = f"{Colors.GREEN}[OK] nosniff{Colors.RESET}" if sec_h.get('x_content_type_options', {}).get('enabled') else f"{Colors.YELLOW}[EKSİK]{Colors.RESET}"
            print(f"  • {Colors.BOLD}Web Güvenlik Başlıkları:{Colors.RESET}")
            print(f"    ├─► Content-Security-Policy (CSP): {csp_b}")
            print(f"    ├─► X-Frame-Options (Clickjacking): {xfo_b}")
            print(f"    └─► X-Content-Type-Options:         {xcto_b}")

        # Certificate Transparency (CT)
        ct = info.get('certificate_transparency', {})
        if ct.get('supported'):
            ct_badge = f"{Colors.GREEN}[OK] AKTİF{Colors.RESET} ({ct.get('count')} adet gömülü SCT kaydı)"
        else:
            ct_badge = f"{Colors.DIM}[INFO] Gömülü SCT kaydı yok{Colors.RESET}"
        print(f"  • {Colors.BOLD}Certificate Transparency (CT):{Colors.RESET} {ct_badge}")

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

    # IPv6 ayrıştırma: [::1]:8443 veya [2001:db8::1]
    if raw.startswith('['):
        if ']:' in raw:
            host_part, port_part = raw.rsplit(']:', 1)
            port = int(port_part) if (port_part.isdigit() and 1 <= int(port_part) <= 65535) else default_port
            return host_part.lstrip('['), port
        return raw.strip('[]'), default_port

    # Parantezsiz IPv6 adresi (örn. 2001:db8::1 veya ::1) - 2 veya daha fazla iki nokta üst üste içerir
    if raw.count(':') >= 2:
        return raw.strip(), default_port

    # Standart host:port ayrıştırma: example.com:8443
    if ':' in raw:
        parts = raw.rsplit(':', 1)
        if parts[1].isdigit() and 1 <= int(parts[1]) <= 65535:
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
    parser.add_argument('-o', '--output', help='Çıktıyı belirtilen dosyaya kaydet (.html, .csv, .md, .json)')
    parser.add_argument('-t', '--timeout', type=int, default=5, help='Bağlantı zaman aşımı saniyesi (varsayılan: 5)')
    parser.add_argument('-b', '--no-color', action='store_true', help='Renksiz terminal çıktısı kullan')
    parser.add_argument('-n', '--no-verify', action='store_true', help='Kök CA ve sertifika güven doğrulamasını atla')
    parser.add_argument('--starttls', choices=['smtp', 'imap', 'pop3', 'ftp', 'ldap'], help='Web dışı servisler için STARTTLS el sıkışması (smtp, imap, pop3, ftp, ldap)')
    parser.add_argument('--sni', help='TLS el sıkışmasında kullanılacak özel SNI (Server Name Indication)')
    parser.add_argument('--ca-bundle', help='Özel Kök CA sertifika paketi dosyası (.pem / .crt)')
    parser.add_argument('--proxy', help='HTTP CONNECT Proxy sunucusu (örn: http://127.0.0.1:8080)')
    parser.add_argument('--all-headers', action='store_true', help='Tüm HTTP yanıt başlıklarını analiz et ve raporla')
    parser.add_argument('--no-caa', action='store_true', help='DNS CAA kayıt doğrulamasını atla')
    parser.add_argument('--no-crl', action='store_true', help='CRL iptal listesi indirmesini atla')
    parser.add_argument('--no-matrix', action='store_true', help='Protokol matrisi ve zayıf şifreleme el sıkışma testlerini atla')
    parser.add_argument('--no-ocsp', action='store_true', help='OCSP iptal sorgusunu atla')
    parser.add_argument('--no-hsts', action='store_true', help='HSTS kontrolünü atla')
    parser.add_argument('--html', action='store_true', help='Karanlık modlu interaktif HTML paneli oluştur')
    parser.add_argument('--csv', action='store_true', help='Excel uyumlu CSV (UTF-8 BOM) formatında rapor oluştur')
    parser.add_argument('--markdown', action='store_true', help='GitHub Markdown formatında rapor oluştur')
    parser.add_argument('-v', '--verbose', action='store_true', help='Ayrıntılı hata çıktısı')

    args = parser.parse_args()

    # Terminal Renk Ayarları
    setup_terminal_colors(no_color=args.no_color)

    # Port Belirleme: Eğer STARTTLS seçilmiş ve port 443 olarak kalmışsa standart protokole çevir
    effective_default_port = args.port
    if args.starttls and args.port == 443:
        effective_default_port = STARTTLS_DEFAULT_PORTS.get(args.starttls.lower(), 443)

    # Domain Listesini Topla
    target_domains: List[Tuple[str, int]] = []

    if args.file:
        if not os.path.isfile(args.file):
            print(f"{Colors.RED}[-] Dosya bulunamadı: {args.file}{Colors.RESET}")
            sys.exit(1)
        with open(args.file, 'r', encoding='utf-8') as f:
            for line in f:
                target = parse_target(line, default_port=effective_default_port)
                if target:
                    target_domains.append(target)

    for d in args.domains:
        target = parse_target(d, default_port=effective_default_port)
        if target:
            target_domains.append(target)

    if not target_domains:
        parser.print_help()
        sys.exit(1)

    # Başlatıcıyı Kur
    inspector = SSLCertInspector(timeout=args.timeout, proxy=args.proxy, ca_bundle=args.ca_bundle)
    cli = SSLPyCLI(inspector, json_output=args.json, verbose=args.verbose)

    # CLI Açılış Başlığı (Sadece JSON değilse)
    if not args.json:
        print(f"{Colors.BOLD}{Colors.CYAN}")
        print("╔════════════════════════════════════════════════════════════════════╗")
        print("║          sslpy v2.0 - Kapsamlı SSL/TLS Denetleme Aracı             ║")
        print("╚════════════════════════════════════════════════════════════════════╝")
        print(f"{Colors.RESET}")
        print(f"{Colors.DIM}Platform: {platform.system()} {platform.release()} | Python: {platform.python_version()}{Colors.RESET}")
        print(f"{Colors.DIM}Doğrulama Modu: {'Sertifika Doğrulaması Devre Dışı (--no-verify)' if args.no_verify else 'Tam Güven Zinciri Doğrulaması Aktif'}{Colors.RESET}")
        if args.ca_bundle:
            print(f"{Colors.DIM}Özel CA Paketi: {args.ca_bundle}{Colors.RESET}")
        if args.proxy:
            print(f"{Colors.DIM}HTTP CONNECT Proxy: {args.proxy}{Colors.RESET}")
        if args.starttls:
            print(f"{Colors.DIM}STARTTLS Modu: {args.starttls.upper()}{Colors.RESET}")
        if args.sni:
            print(f"{Colors.DIM}Özel SNI: {args.sni}{Colors.RESET}")
        print(f"{Colors.DIM}Protokol Matrisi: {'Devre Dışı (--no-matrix)' if args.no_matrix else 'Aktif (TLS 1.0 - 1.3 & Şifreleme Analizi)'}{Colors.RESET}\n")

    results: List[Dict[str, Any]] = []

    # Tekil Domain
    if len(target_domains) == 1:
        domain, port = target_domains[0]
        res = cli.inspect_target(
            domain,
            port=port,
            no_verify=args.no_verify,
            check_ocsp=not args.no_ocsp,
            check_hsts=not args.no_hsts,
            check_matrix=not args.no_matrix,
            starttls=args.starttls,
            sni=args.sni,
            check_caa=not args.no_caa,
            check_crl=not args.no_crl,
            check_headers=args.all_headers
        )
        results.append(res)
        if not args.json:
            cli.print_pretty_report(res)
    else:
        # Çoklu Domain - Paralel Tarama
        max_workers = min(10, len(target_domains))
        with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as executor:
            future_to_target = {
                executor.submit(
                    cli.inspect_target,
                    domain,
                    port,
                    args.no_verify,
                    not args.no_ocsp,
                    not args.no_hsts,
                    not args.no_matrix,
                    args.starttls,
                    args.sni,
                    not args.no_caa,
                    not args.no_crl,
                    args.all_headers
                ): (domain, port)
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

    # Format Belirleme
    out_format = None
    if args.json:
        out_format = 'json'
    elif args.html:
        out_format = 'html'
    elif args.csv:
        out_format = 'csv'
    elif args.markdown:
        out_format = 'markdown'
    elif args.output:
        ext = os.path.splitext(args.output)[1].lower()
        if ext in ('.html', '.htm'):
            out_format = 'html'
        elif ext == '.csv':
            out_format = 'csv'
        elif ext in ('.md', '.markdown'):
            out_format = 'markdown'
        elif ext == '.json':
            out_format = 'json'
        else:
            out_format = 'json'

    if not args.output:
        if args.html:
            args.output = 'sslpy_report.html'
        elif args.csv:
            args.output = 'sslpy_report.csv'
        elif args.markdown:
            args.output = 'sslpy_report.md'

    # JSON Çıktısı Yönetimi (Terminal için)
    final_json_output = None
    if args.json:
        json_data = results[0] if len(results) == 1 else results
        final_json_output = json.dumps(json_data, indent=2, ensure_ascii=False, default=str)
        print(final_json_output)

    # Dosyaya Kayıt (-o / --output / --html / --csv / --markdown)
    if args.output:
        try:
            if out_format == 'html':
                HTMLExporter.export(results, args.output)
            elif out_format == 'csv':
                CSVExporter.export(results, args.output)
            elif out_format == 'markdown':
                MarkdownExporter.export(results, args.output)
            else:
                with open(args.output, 'w', encoding='utf-8') as out_file:
                    if args.json:
                        out_file.write(final_json_output or "")
                    else:
                        out_file.write(json.dumps(results, indent=2, ensure_ascii=False, default=str))

            if not args.json:
                print(f"{Colors.GREEN}[+] Sonuçlar '{args.output}' ({out_format.upper()}) dosyasına başarıyla kaydedildi.{Colors.RESET}")
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