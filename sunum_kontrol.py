#!/usr/bin/env python3
"""Sunum kontrolü: servis, düzenlenen en yeni sertifikayı gerçekten sunuyor mu?

Yenileme hattından BAĞIMSIZ çalışır (ayrı zamanlayıcı, ayrı makine olabilir) ve üç şeye bakar:
  1. Zincir: yalnızca köke güvenen bir istemci el sıkışmayı doğrulayabiliyor mu?
  2. Düzenlenen = sunulan: servisin sunduğu sertifika, otomasyonun aldığı en yeni sertifika mı?
  3. Orantılı eşik: yenileme noktası geçtiği hâlde sunulan sertifika hâlâ eski mi?

Kullanım: sunum_kontrol.py <ad> <ip:port> <düzenlenen cert.pem> <kök.pem> <yenileme eşiği sn> <tolerans sn>
Çıkış kodu: 0 = sağlıklı, 2 = en az bir sorun
"""
import socket
import ssl
import sys
import time

from cryptography import x509
from cryptography.hazmat.primitives import hashes

name, addr, issued_pem, root, renew_before, grace = sys.argv[1:7]
host, port = addr.rsplit(":", 1)


def served(verify: bool) -> x509.Certificate:
    ctx = ssl.create_default_context(cafile=root)
    if not verify:
        ctx.check_hostname, ctx.verify_mode = False, ssl.CERT_NONE
    with socket.create_connection((host, int(port)), timeout=3) as sock:
        with ctx.wrap_socket(sock, server_hostname=name) as tls:
            return x509.load_der_x509_certificate(tls.getpeercert(True))


def fp(cert: x509.Certificate) -> str:
    return cert.fingerprint(hashes.SHA256()).hex()[:16]


problems = []
try:
    cert = served(verify=True)
except ssl.SSLCertVerificationError as e:
    problems.append(f"ZİNCİR: istemci doğrulayamadı ({e.verify_message})")
    cert = served(verify=False)

issued = x509.load_pem_x509_certificate(open(issued_pem, "rb").read())
if fp(cert) != fp(issued):
    problems.append(f"DÜZENLENEN ≠ SUNULAN: düzenlenen {fp(issued)}, sunulan {fp(cert)}")

left = cert.not_valid_after_utc.timestamp() - time.time()
if left < float(renew_before) - float(grace):
    problems.append(f"YENİLEME GECİKTİ: sunulan sertifikanın bitimine {left:.0f} sn kaldı, "
                    f"yenileme {float(renew_before):.0f} sn kala yapılmalıydı")

for p in problems:
    print(f"UYARI {name}: {p}")
if not problems:
    print(f"OK    {name}: sunulan = düzenlenen ({fp(cert)}), zincir doğrulandı, bitime {left:.0f} sn")
sys.exit(2 if problems else 0)
