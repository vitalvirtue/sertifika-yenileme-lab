#!/usr/bin/env python3
"""Hata enjeksiyonu laboratuvarı: otomatik sertifika yenilemesi sessizce bozulduğunda
hangi izleme sinyali, ne kadar önce fark eder?

Bileşenler (hepsi tek makinede, loopback üzerinde):
  * ACME CA      : Pebble (Let's Encrypt'in RFC 8555 test sunucusu), ömür sınıfı başına bir örnek
  * DNS          : dns_server.py (yetkili DNS + token'lı sağlayıcı API'si)
  * İstemci      : certbot (gerçek istemci, gerçek deploy-hook'lar)
  * Servis       : uç nokta başına bir nginx (TLS'i sonlandıran "uygulama")
  * Zamanlayıcı  : certbot renew'u günde iki kez (ölçekli) çalıştırır
  * İzleyici     : diskteki, düzenlenen ve SUNULAN sertifikayı örnekler

Zaman sıkıştırma: 1 gün = SCALE saniye. Sertifika ömürleri ve yenileme eşikleri aynı
oranda ölçeklenir; araçların kendisi (certbot, nginx, ACME protokolü) gerçektir.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import secrets
import socket
import ssl
import subprocess
import sys
import threading
import time
import urllib.request
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives.serialization import Encoding

import dns_server

BASE = Path(__file__).resolve().parent
MGMT_CA = BASE / "ca" / "mgmt-ca.crt"

# ömür sınıfı (gün) -> ağ indeksi, yenileme eşiği (certbot varsayılanı: ömrün 1/3'ü; <10 günde 1/2'si)
CLASSES = {90: dict(idx=1, renew_before=30), 45: dict(idx=2, renew_before=15), 6: dict(idx=3, renew_before=3)}

# (kimlik, kısa ad, doğrulama yöntemi)
FAULTS = [
    ("f0", "kontrol", "http"),
    ("f1", "san-dns-silindi", "http"),
    ("f2", "dns-kimlik-bilgisi", "dns"),
    ("f3", "cname-cakismasi", "dns"),
    ("f4", "ca-erisilemez", "http"),
    ("f5", "kurulmadi", "http"),
    ("f6", "yeniden-yuklenmedi", "http"),
    ("f7", "yanlis-zincir", "http"),
    ("f8", "zamanlayici-kapali", "http"),
]

DNS_PORT, API_PORT = 5053, 5380
STOP = threading.Event()
JOB_SEM = threading.Semaphore(2)
LOG_LOCK = threading.Lock()


def now() -> float:
    return time.time()


def jlog(path: Path, rec: dict) -> None:
    with LOG_LOCK, path.open("a") as f:
        f.write(json.dumps(rec, ensure_ascii=False) + "\n")


def cert_info(pem_or_der: bytes) -> tuple[str, float, float]:
    """(parmak izi, notBefore, notAfter) — PEM ise ilk (uç) sertifika."""
    if pem_or_der.lstrip().startswith(b"-----"):
        c = x509.load_pem_x509_certificate(pem_or_der)
    else:
        c = x509.load_der_x509_certificate(pem_or_der)
    der = c.public_bytes(Encoding.DER)
    return (hashlib.sha256(der).hexdigest()[:16],
            c.not_valid_before_utc.timestamp(), c.not_valid_after_utc.timestamp())


class Forwarder:
    """f4 için: uç nokta ile CA arasındaki 'ağ yolu'. close() = güvenlik duvarı kuralı değişti."""

    def __init__(self, listen_port: int, target_port: int):
        self.target = target_port
        self.closed = False
        self.sock = socket.socket()
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.sock.bind(("127.0.0.1", listen_port))
        self.sock.listen(16)
        threading.Thread(target=self._accept, daemon=True).start()

    def _accept(self):
        while True:
            try:
                c, _ = self.sock.accept()
            except OSError:
                return
            if self.closed:
                c.close()
                return
            try:
                u = socket.create_connection(("127.0.0.1", self.target))
            except OSError:
                c.close()
                continue
            for a, b in ((c, u), (u, c)):
                threading.Thread(target=self._pipe, args=(a, b), daemon=True).start()

    @staticmethod
    def _pipe(a, b):
        try:
            while (d := a.recv(65536)):
                b.sendall(d)
        except OSError:
            pass
        finally:
            for s in (a, b):
                try:
                    s.shutdown(socket.SHUT_RDWR)
                except OSError:
                    pass

    def close(self):
        self.closed = True
        try:
            self.sock.shutdown(socket.SHUT_RDWR)
        except OSError:
            pass
        self.sock.close()


class Host:
    def __init__(self, lab: "ClassLab", n: int, fid: str, label: str, method: str):
        self.lab, self.fid, self.label, self.method = lab, fid, label, method
        self.name = f"{fid}-{lab.days}.lab.internal"
        self.ip = f"127.0.{lab.idx}.{10 + n}"
        self.dir = lab.dir / fid
        self.sans = [self.name] + ([f"legacy-{self.name}"] if fid == "f1" else [])
        self.timer_disabled = False
        self.token = secrets.token_hex(8)
        self.server = lab.acme_url
        self.fwd: Forwarder | None = None
        self.t0 = 0.0          # ilk sertifikanın notBefore'u
        self.served_fp = None
        self.injected = False
        self.cb = ["--config-dir", str(self.dir / "cb/config"), "--work-dir", str(self.dir / "cb/work"),
                   "--logs-dir", str(self.dir / "cb/logs"), "-n"]
        self.live = self.dir / "cb/config/live" / self.name

    # ---------------------------------------------------------------- kurulum
    def write_files(self):
        d = self.dir
        (d / "tls").mkdir(parents=True)
        (d / "nginx.conf").write_text(f"""worker_processes 1;
pid {d}/nginx.pid;
error_log {d}/nginx-error.log;
events {{ worker_connections 64; }}
http {{
  access_log off;
  server {{
    listen {self.ip}:443 ssl;
    server_name {self.name};
    ssl_certificate     {d}/tls/fullchain.pem;
    ssl_certificate_key {d}/tls/privkey.pem;
    location / {{ return 200 "ok\\n"; }}
  }}
}}
""")
        self.write_deploy("normal")
        (d / "dns_token").write_text(self.token)
        (d / "dns-auth.sh").write_text(f"""#!/bin/sh
# certbot manual-auth-hook: TXT kaydını DNS sağlayıcı API'sine yazar
curl -sS -f -X PUT -H "X-Auth-Token: $(cat {d}/dns_token)" \\
  --data "$CERTBOT_VALIDATION" "http://127.0.0.1:{API_PORT}/records/TXT/_acme-challenge.$CERTBOT_DOMAIN"
""")
        (d / "dns-cleanup.sh").write_text(f"""#!/bin/sh
curl -sS -f -X DELETE -H "X-Auth-Token: $(cat {d}/dns_token)" \\
  "http://127.0.0.1:{API_PORT}/records/TXT/_acme-challenge.$CERTBOT_DOMAIN" || true
""")
        for f in ("dns-auth.sh", "dns-cleanup.sh"):
            os.chmod(d / f, 0o755)

    def write_deploy(self, variant: str):
        d = self.dir
        chain = "cert.pem" if variant == "wrong-chain" else "fullchain.pem"
        reload_cmd = (f"nginx -c {d}/nginx-tls.conf -p {d} -s reload"      # yeniden adlandırılmış yapılandırma: hata verir
                      if variant == "no-reload" else
                      f"if [ -f {d}/nginx.pid ]; then nginx -c {d}/nginx.conf -p {d} -s reload; "
                      f"else nginx -c {d}/nginx.conf -p {d}; fi")
        if self.lab.guard:
            reload_soft = reload_cmd.replace("; fi", " || true; fi") if reload_cmd.startswith("if ") else reload_cmd + " || true"
            (d / "deploy.sh").write_text(f"""#!/bin/sh
# Korumalı deploy-hook: kurmadan önce doğrula, kurduktan sonra SUNUMU doğrula, olmazsa geri al.
SRC="$RENEWED_LINEAGE/{chain}"
ROOT={self.lab.dir}/root.pem

# 1) Ön kontrol: zincir güven köküne kadar kuruluyor mu? Kurulmuyorsa canlı dosyalara dokunma.
if ! openssl verify -CAfile "$ROOT" -untrusted "$SRC" "$SRC" >/dev/null 2>&1; then
  echo "ON-KONTROL: zincir dogrulanamadi, kurulum iptal edildi" >&2; exit 2
fi

# 2) Yedekle, kur, yeniden yükle
cp {d}/tls/fullchain.pem {d}/tls/fullchain.pem.onceki
cp {d}/tls/privkey.pem   {d}/tls/privkey.pem.onceki
cp "$SRC" {d}/tls/fullchain.pem
cp "$RENEWED_LINEAGE/privkey.pem" {d}/tls/privkey.pem
{reload_soft}

# 3) Sunum doğrulaması: servis gerçekten yeni sertifikayı mı sunuyor?
BEKLENEN=$(openssl x509 -in "$RENEWED_LINEAGE/cert.pem" -noout -fingerprint -sha256)
for i in 1 2 3 4 5; do
  SUNULAN=$(echo | openssl s_client -connect {self.ip}:443 -servername {self.name} 2>/dev/null \\
            | openssl x509 -noout -fingerprint -sha256 2>/dev/null)
  [ "$SUNULAN" = "$BEKLENEN" ] && exit 0
  sleep 0.3
done

# 4) Geri al: disk ile bellekteki sertifika yeniden aynı olsun
mv {d}/tls/fullchain.pem.onceki {d}/tls/fullchain.pem
mv {d}/tls/privkey.pem.onceki   {d}/tls/privkey.pem
echo "SUNUM-DOGRULAMA: servis yeni sertifikayi sunmuyor, geri alindi" >&2; exit 3
""")
        else:
            (d / "deploy.sh").write_text(f"""#!/bin/sh
# certbot deploy-hook: yeni sertifikayı servisin okuduğu yere kopyalar ve servisi yeniden yükler
set -e
cp "$RENEWED_LINEAGE/{chain}" {d}/tls/fullchain.pem
cp "$RENEWED_LINEAGE/privkey.pem" {d}/tls/privkey.pem
{reload_cmd}
""")
        os.chmod(d / "deploy.sh", 0o755)

    def issue_first(self):
        zone = self.lab.zone
        for s in self.sans:
            zone.put("A", s, self.ip, replace=True)
        zone.tokens[self.token] = self.fid
        if self.fid == "f4":
            port = 16000 + self.lab.idx
            self.fwd = Forwarder(port, self.lab.acme_port)
            self.server = f"https://127.0.0.1:{port}/dir"
        args = ["certbot", "certonly", "--server", self.server, "--agree-tos", "--register-unsafely-without-email",
                "--key-type", "ecdsa", "--deploy-hook", str(self.dir / "deploy.sh")]
        for s in self.sans:
            args += ["-d", s]
        if self.method == "http":
            args += ["--standalone", "--http-01-address", self.ip, "--http-01-port", "80"]
        else:
            args += ["--manual", "--preferred-challenges", "dns",
                     "--manual-auth-hook", str(self.dir / "dns-auth.sh"),
                     "--manual-cleanup-hook", str(self.dir / "dns-cleanup.sh")]
        r = subprocess.run(args + self.cb, env=self.lab.env, capture_output=True, text=True)
        if r.returncode != 0:
            raise RuntimeError(f"{self.name} ilk düzenleme başarısız:\n{r.stdout}\n{r.stderr}")
        self.deactivate_authz()
        # certbot'un varsayılan yenileme kuralını ölçekli değerle sabitle
        conf = self.dir / "cb/config/renewal" / f"{self.name}.conf"
        rb = int(self.lab.renew_before * self.lab.scale)
        conf.write_text(f"renew_before_expiry = {rb} seconds\n" + conf.read_text())
        _, nb, na = cert_info((self.live / "cert.pem").read_bytes())
        self.t0, self.exp1 = nb, na
        self.lab.ev(self, "ilk-duzenleme", not_before=nb, not_after=na)

    def deactivate_authz(self):
        """İlk düzenlemede geçerli sayılan yetkilendirmeleri devre dışı bırak (RFC 8555 §7.5.2).

        Böylece CA sonraki yenilemelerde eski bir doğrulamayı yeniden kullanamaz; her yenileme
        canlı doğrulama yapmak zorunda kalır. (Pebble'da PEBBLE_AUTHZREUSE=0 iken bile %1 olasılıkla
        yeniden kullanım oluyor; bu, bozuk bir doğrulama yolunu rastgele maskeliyordu.)
        """
        import re
        import josepy
        from acme import client, messages
        acc = next((self.dir / "cb/config/accounts").glob("*/*/*"))
        key = josepy.JWK.json_loads((acc / "private_key.json").read_text())
        regr = messages.RegistrationResource.json_loads((acc / "regr.json").read_text())
        net = client.ClientNetwork(key, account=regr, verify_ssl=str(MGMT_CA))
        cl = client.ClientV2(messages.Directory.from_json(net.get(self.server).json()), net)
        log = (self.dir / "cb/logs/letsencrypt.log").read_text()
        urls = sorted(set(re.findall(r"https://127\.0\.0\.1:\d+/authZ/[\w-]+", log)))
        for u in urls:
            cl.deactivate_authorization(messages.AuthorizationResource(uri=u, body=messages.Authorization()))
        self.lab.ev(self, "yetkilendirme-kapatildi", adet=len(urls))

    # ---------------------------------------------------------------- arıza enjeksiyonu
    def inject(self):
        zone, f = self.lab.zone, self.fid
        if f == "f1":      # emekliye ayrılan ana bilgisayarın DNS kaydı silindi; adı hâlâ sertifikada
            zone.delete("A", self.sans[1])
        elif f == "f2":    # DNS sağlayıcı kimlik bilgisi döndürüldü; otomasyondaki kopya eski kaldı
            zone.tokens.pop(self.token, None)
        elif f == "f3":    # CDN devreye alınırken _acme-challenge adına CNAME kondu
            zone.put("CNAME", f"_acme-challenge.{self.name}", "dogrulama.cdn-saglayici.internal")
        elif f == "f4":    # CA'ya giden ağ yolu kapandı
            self.fwd.close()
        elif f == "f5":    # yapılandırma yönetimi yenileme dosyasını ezdi; deploy-hook satırı kayboldu
            conf = self.dir / "cb/config/renewal" / f"{self.name}.conf"
            conf.write_text("\n".join(l for l in conf.read_text().splitlines() if not l.startswith("renew_hook")) + "\n")
        elif f == "f6":    # servis yapılandırması yeniden adlandırıldı; hook'taki reload komutu eski kaldı
            self.write_deploy("no-reload")
        elif f == "f7":    # hook "sadeleştirildi": fullchain yerine yalnızca uç sertifika kopyalanıyor
            self.write_deploy("wrong-chain")
        elif f == "f8":    # işletim sistemi yükseltmesinden sonra zamanlayıcı etkinleştirilmedi
            self.timer_disabled = True
        self.injected = True
        self.lab.ev(self, "ariza-enjekte", label=self.label)

    # ---------------------------------------------------------------- zamanlayıcı
    def job_loop(self):
        interval = self.lab.scale / 2          # 12 saat
        nxt = self.t0 + interval * (1 + (hash(self.fid) % 100) / 100)
        n = 0
        while not STOP.is_set() and now() < self.lab.t_end:
            if not self.injected and self.fid != "f0" and now() >= self.t0 + 0.2 * self.lab.life:
                self.inject()
            if now() < nxt:
                time.sleep(min(0.2, nxt - now()))
                continue
            nxt += interval
            if self.timer_disabled:
                continue
            cmd = ([str(BASE / "renew-wrapper.sh")] if self.lab.guard else
                   ["certbot", "renew", "--no-random-sleep-on-renew"]) + self.cb
            with JOB_SEM:
                t = now()
                r = subprocess.run(cmd, env={**self.lab.env, "NABIZ": str(self.dir / "nabiz")},
                                   capture_output=True, text=True)
            out = r.stdout + r.stderr
            kind = ("bos" if "No renewals were attempted" in out else
                    "basarili" if "all renewals succeeded" in out else "hata")
            n += 1
            if kind != "bos":
                (self.dir / f"job-{n:03d}.log").write_text(out)
            self.lab.ev(self, "is", rc=r.returncode, sonuc=kind, sure=round(now() - t, 2), n=n, t=t)

    # ---------------------------------------------------------------- izleme örneği
    def sample(self) -> dict:
        s: dict = {"t": now(), "host": self.fid}
        for key, path in (("disk", self.dir / "tls/fullchain.pem"), ("duz", self.live / "cert.pem")):
            try:
                fp, _, na = cert_info(path.read_bytes())
                s[f"{key}_fp"], s[f"{key}_na"] = fp, na
            except Exception as e:  # noqa: BLE001
                s[f"{key}_err"] = str(e)[:80]
        der, ok, err = None, True, ""
        try:
            with socket.create_connection((self.ip, 443), timeout=2) as sock:
                with self.lab.ctx_verify.wrap_socket(sock, server_hostname=self.name) as ss:
                    der = ss.getpeercert(True)
        except ssl.SSLCertVerificationError as e:
            ok, err = False, e.verify_message
            try:
                with socket.create_connection((self.ip, 443), timeout=2) as sock:
                    with self.lab.ctx_noverify.wrap_socket(sock, server_hostname=self.name) as ss:
                        der = ss.getpeercert(True)
            except OSError as e2:
                err += f" / {e2}"
        except OSError as e:
            ok, err = False, f"baglanti: {e}"
        if der:
            s["sun_fp"], _, s["sun_na"] = cert_info(der)
        s["dogrulama_ok"], s["dogrulama_hata"] = ok, err
        return s


class ClassLab:
    def __init__(self, run_dir: Path, days: int, scale: float, zone, guard=False):
        self.days, self.scale, self.zone, self.guard = days, scale, zone, guard
        self.idx = CLASSES[days]["idx"]
        self.renew_before = CLASSES[days]["renew_before"]
        self.life = days * scale
        self.dir = run_dir / str(days)
        self.dir.mkdir(parents=True)
        self.acme_port, self.mgmt_port = 14000 + self.idx, 15000 + self.idx
        self.acme_url = f"https://127.0.0.1:{self.acme_port}/dir"
        self.env = {**os.environ, "REQUESTS_CA_BUNDLE": str(MGMT_CA)}
        self.events, self.samples = self.dir / "events.jsonl", self.dir / "samples.jsonl"
        self.hosts = [Host(self, n, *f) for n, f in enumerate(FAULTS)]
        self.t_end = float("inf")

    def ev(self, h: Host, ev: str, **kw):
        jlog(self.events, {"t": kw.pop("t", now()), "host": h.fid, "ev": ev, **kw})

    def start_ca(self):
        cfg = {"pebble": {
            "listenAddress": f"127.0.0.1:{self.acme_port}", "managementListenAddress": f"127.0.0.1:{self.mgmt_port}",
            "certificate": str(BASE / "ca/pebble.crt"), "privateKey": str(BASE / "ca/pebble.key"),
            "httpPort": 80, "tlsPort": 443, "ocspResponderURL": "", "externalAccountBindingRequired": False,
            "certificateValidityPeriod": int(self.life)}}
        (self.dir / "pebble.json").write_text(json.dumps(cfg, indent=1))
        # AUTHZREUSE=0: her yenilemede canlı doğrulama (Let's Encrypt'in 2028'de 7 saate indireceği yön)
        env = {**os.environ, "PEBBLE_VA_NOSLEEP": "1", "PEBBLE_WFE_NONCEREJECT": "0", "PEBBLE_AUTHZREUSE": os.environ.get("LAB_AUTHZREUSE", "0")}
        self.ca = subprocess.Popen(["pebble", "-config", str(self.dir / "pebble.json"), "-dnsserver", f"127.0.0.1:{DNS_PORT}"],
                                   env=env, stdout=(self.dir / "pebble.log").open("w"), stderr=subprocess.STDOUT)
        mctx = ssl.create_default_context(cafile=str(MGMT_CA))
        for _ in range(50):
            try:
                root = urllib.request.urlopen(f"https://127.0.0.1:{self.mgmt_port}/roots/0", context=mctx).read()
                break
            except OSError:
                time.sleep(0.1)
        (self.dir / "root.pem").write_bytes(root)
        self.ctx_verify = ssl.create_default_context(cafile=str(self.dir / "root.pem"))
        self.ctx_noverify = ssl.create_default_context()
        self.ctx_noverify.check_hostname = False
        self.ctx_noverify.verify_mode = ssl.CERT_NONE

    def ca_watch(self):
        """CA tarafı sinyali: CA günlüğünde geçersiz sayılan her yetkilendirmeyi alan adıyla eşle."""
        by_name = {san: h for h in self.hosts for san in h.sans}
        pending: list[str] = []      # doğrulama kuyruğuna alınan alan adları (sırayla sonuçlanır)
        with (self.dir / "pebble.log").open() as f:
            while not STOP.is_set() and now() < self.t_end + 2:
                line = f.readline()
                if not line:
                    time.sleep(0.2)
                    continue
                if "Pulled a task from the Tasks queue" in line:
                    pending.append(line.split('Value:"')[1].split('"')[0])
                elif " by completed challenge " in line and pending:
                    ident = pending.pop(0)
                    h = by_name.get(ident)
                    if h and " set INVALID " in line:
                        self.ev(h, "ca-hata", ident=ident)

    def evidence(self, h: Host, s: dict):
        """Kanıt kaydı: yeni sertifikanın SUNULDUĞU doğrulandığında hash zincirli bir satır yaz."""
        prev = getattr(self, "_ev_prev", "0" * 64)
        rec = {"ts": s["t"], "aktor": "sistem:sunum-dogrulayici", "uc_nokta": h.name, "islem": "sertifika-yenileme",
               "eski_parmak_izi": h.served_fp, "yeni_parmak_izi": s["sun_fp"], "gecerlilik_sonu": s["sun_na"],
               "duzenlenen_ile_ayni": s["sun_fp"] == s.get("duz_fp"), "zincir_dogrulandi": s["dogrulama_ok"], "prev": prev}
        rec["hash"] = hashlib.sha256(json.dumps(rec, sort_keys=True, separators=(",", ":")).encode()).hexdigest()
        self._ev_prev = rec["hash"]
        jlog(self.dir / "kanit.jsonl", rec)

    def run(self):
        try:
            self._run()
        finally:
            self.stop()

    def _run(self):
        self.start_ca()
        for h in self.hosts:
            h.write_files()
            h.issue_first()
        self.t_end = max(h.exp1 for h in self.hosts) + 1.5 * self.scale
        meta = {"days": self.days, "scale": self.scale, "guard": self.guard, "life_s": self.life, "renew_before_days": self.renew_before,
                "hosts": [{"fid": h.fid, "label": h.label, "method": h.method, "name": h.name, "ip": h.ip,
                           "t0": h.t0, "exp1": h.exp1} for h in self.hosts]}
        (self.dir / "meta.json").write_text(json.dumps(meta, indent=1))
        threads = [threading.Thread(target=h.job_loop, daemon=True) for h in self.hosts]
        for t in threads:
            t.start()
        threading.Thread(target=self.ca_watch, daemon=True).start()
        step = self.scale / 10                 # 0,1 gün
        nxt = now()
        while not STOP.is_set() and now() < self.t_end:
            for h in self.hosts:
                s = h.sample()
                jlog(self.samples, s)
                fp = s.get("sun_fp")
                if fp and fp != h.served_fp:
                    if h.served_fp and s["dogrulama_ok"] and fp == s.get("duz_fp"):
                        self.evidence(h, s)
                    h.served_fp = fp
            nxt += step
            time.sleep(max(0, nxt - now()))
        for t in threads:
            t.join(timeout=5)

    def stop(self):
        for h in self.hosts:
            pid = h.dir / "nginx.pid"
            if pid.exists():
                subprocess.run(["nginx", "-c", str(h.dir / "nginx.conf"), "-p", str(h.dir), "-s", "quit"],
                               capture_output=True)
        self.ca.terminate()


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--classes", default="6")
    ap.add_argument("--scale", type=float, default=20, help="1 günün karşılığı saniye")
    ap.add_argument("--run", default=time.strftime("%Y%m%d-%H%M%S"))
    ap.add_argument("--guard", action="store_true", help="korumalı hat: sarmalayıcı + doğrulayan deploy-hook")
    ap.add_argument("--dns-port", type=int, default=5053)
    a = ap.parse_args()
    global DNS_PORT, API_PORT
    DNS_PORT, API_PORT = a.dns_port, a.dns_port + 327
    run_dir = BASE / "runs" / a.run
    run_dir.mkdir(parents=True)
    zone = dns_server.start(DNS_PORT, API_PORT)
    labs = [ClassLab(run_dir, int(c), a.scale, zone, a.guard) for c in a.classes.split(",")]
    ts = [threading.Thread(target=l.run) for l in labs]
    for t in ts:
        t.start()
    try:
        for t in ts:
            t.join()
    except KeyboardInterrupt:
        STOP.set()
    print("bitti:", run_dir)


if __name__ == "__main__":
    main()
