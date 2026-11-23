"""Laboratuvar DNS'i: yetkili sunucu (UDP) + "DNS sağlayıcı API'si" (HTTP, token'lı).

ACME CA'sı alan adlarını buradan çözer; dns-01 kullanan istemciler TXT kayıtlarını
API üzerinden yazar. Gerçek sağlayıcılardaki iki davranışı taklit eder:
  * iptal edilmiş token -> 401
  * CNAME bulunan ada TXT eklenemez -> 409 (RFC 1034: CNAME tek başına durur)
"""
from __future__ import annotations

import json
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from dnslib import AAAA, CNAME, QTYPE, RCODE, RR, TXT, A
from dnslib.server import BaseResolver, DNSServer


class Zone(BaseResolver):
    def __init__(self):
        self.lock = threading.Lock()
        self.records: dict[tuple[str, str], list[str]] = {}
        self.tokens: dict[str, str] = {}  # token -> sahibi

    # --- kayıt işlemleri (API ve orkestratör kullanır)
    def put(self, rtype: str, name: str, value: str, replace=False):
        key = (name.lower().rstrip("."), rtype)
        with self.lock:
            if rtype != "CNAME" and (key[0], "CNAME") in self.records:
                raise ValueError("CNAME bulunan ada başka kayıt eklenemez")
            if replace:
                self.records[key] = [value]
            else:
                self.records.setdefault(key, []).append(value)

    def delete(self, rtype: str, name: str):
        with self.lock:
            self.records.pop((name.lower().rstrip("."), rtype), None)

    # --- DNS yanıtı
    def resolve(self, request, handler):
        reply = request.reply()
        qname = str(request.q.qname).lower().rstrip(".")
        qtype = QTYPE[request.q.qtype]
        with self.lock:
            cname = self.records.get((qname, "CNAME"))
            vals = self.records.get((qname, qtype), [])
            exists = any(k[0] == qname for k in self.records)
        if cname:
            reply.add_answer(RR(qname, QTYPE.CNAME, rdata=CNAME(cname[0]), ttl=1))
        elif vals:
            for v in vals:
                rdata = {"A": A, "AAAA": AAAA, "TXT": TXT}[qtype](v)
                reply.add_answer(RR(qname, getattr(QTYPE, qtype), rdata=rdata, ttl=1))
        elif not exists:
            reply.header.rcode = RCODE.NXDOMAIN
        return reply


def make_api(zone: Zone):
    class Api(BaseHTTPRequestHandler):
        def log_message(self, *a):
            pass

        def _auth(self) -> bool:
            if self.headers.get("X-Auth-Token") in zone.tokens:
                return True
            self._send(401, {"error": "geçersiz ya da iptal edilmiş token"})
            return False

        def _send(self, code, obj):
            body = json.dumps(obj).encode()
            self.send_response(code)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def do_PUT(self):  # /records/TXT/<ad>   gövde: değer
            if not self._auth():
                return
            _, _, rtype, name = self.path.split("/", 3)
            value = self.rfile.read(int(self.headers.get("Content-Length", 0))).decode().strip()
            try:
                zone.put(rtype, name, value)
            except ValueError as e:
                return self._send(409, {"error": str(e)})
            self._send(200, {"ok": True})

        def do_DELETE(self):
            if not self._auth():
                return
            _, _, rtype, name = self.path.split("/", 3)
            zone.delete(rtype, name)
            self._send(200, {"ok": True})

    return Api


def start(dns_port=5053, api_port=5380) -> Zone:
    zone = Zone()
    DNSServer(zone, port=dns_port, address="127.0.0.1").start_thread()
    DNSServer(zone, port=dns_port, address="127.0.0.1", tcp=True).start_thread()
    api = ThreadingHTTPServer(("127.0.0.1", api_port), make_api(zone))
    threading.Thread(target=api.serve_forever, daemon=True).start()
    return zone
