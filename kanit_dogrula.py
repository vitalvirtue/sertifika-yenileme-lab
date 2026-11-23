#!/usr/bin/env python3
"""Kanıt kaydının bütünlüğünü doğrular: her satırın hash'i ve bir öncekine bağlantısı."""
import hashlib, json, sys

prev, n = "0" * 64, 0
for n, line in enumerate(open(sys.argv[1]), 1):
    rec = json.loads(line)
    claimed = rec.pop("hash")
    if rec["prev"] != prev:
        sys.exit(f"ZİNCİR KIRIK: satır {n} önceki kayda bağlanmıyor")
    if hashlib.sha256(json.dumps(rec, sort_keys=True, separators=(",", ":")).encode()).hexdigest() != claimed:
        sys.exit(f"KURCALAMA: satır {n} içeriği değiştirilmiş")
    prev = claimed
print(f"OK: {n} kayıt, zincir sağlam. Son hash: {prev[:16]}…")
