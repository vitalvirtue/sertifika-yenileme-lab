#!/usr/bin/env python3
"""Ham olay ve örnek kayıtlarından tespit matrisini çıkarır.

Her arıza için: kesinti ne zaman başladı, hangi sinyal ilk ne zaman ateşledi,
ikisi arasındaki marj kaç (ölçekli) gün?
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

SIGNALS = [
    ("cikis_kodu", "İş çıkış kodu"),
    ("nabiz", "İş nabzı"),
    ("ca_hata", "CA hata kaydı"),
    ("disk_oran", "Diskteki dosya (orantılı eşik)"),
    ("sunulan_14", "Sunulan sertifika (14 gün eşiği)"),
    ("sunulan_oran", "Sunulan sertifika (orantılı eşik)"),
    ("duz_sun", "Düzenlenen ≠ sunulan"),
    ("zincir", "Zincir doğrulama"),
]
FIXED = (30, 14, 7)


def load(p: Path) -> list[dict]:
    return [json.loads(l) for l in p.open()] if p.exists() else []


def analyze_class(d: Path) -> dict:
    meta = json.loads((d / "meta.json").read_text())
    sc, rb = meta["scale"], meta["renew_before_days"]
    events, samples = load(d / "events.jsonl"), load(d / "samples.jsonl")
    out = {"days": meta["days"], "scale": sc, "renew_before": rb, "hosts": {}}
    for h in meta["hosts"]:
        fid = h["fid"]
        ev = [e for e in events if e["host"] == fid]
        sm = [s for s in samples if s["host"] == fid]
        jobs = sorted((e for e in ev if e["ev"] == "is"), key=lambda e: e["t"])
        inj = next((e["t"] for e in ev if e["ev"] == "ariza-enjekte"), None)
        # kesinti: istemcinin doğrulaması ilk kez başarısız olduğu an
        outage = next((s["t"] for s in sm if not s["dogrulama_ok"]), None)
        cause = next((s["dogrulama_hata"] for s in sm if not s["dogrulama_ok"]), "")
        fire: dict[str, float | None] = {}
        fire["cikis_kodu"] = next((j["t"] for j in jobs if j["rc"] != 0), None)
        # nabız: 1,5 günden uzun süre iş kaydı gelmezse
        fire["nabiz"] = None
        ts = [j["t"] for j in jobs] + [sm[-1]["t"]]
        for a, b in zip(ts, ts[1:]):
            if b - a > 1.5 * sc:
                fire["nabiz"] = a + 1.5 * sc
                break
        fire["ca_hata"] = next((e["t"] for e in ev if e["ev"] == "ca-hata"), None)
        prop = (rb - 1) * sc          # orantılı eşik: yenileme noktasından 1 gün sonra hâlâ yenilenmemişse
        fire["disk_oran"] = next((s["t"] for s in sm if "disk_na" in s and s["disk_na"] - s["t"] < prop), None)
        fire["sunulan_oran"] = next((s["t"] for s in sm if "sun_na" in s and s["sun_na"] - s["t"] < prop), None)
        for th in FIXED:
            fire[f"sunulan_{th}"] = next((s["t"] for s in sm if "sun_na" in s and s["sun_na"] - s["t"] < th * sc), None)
        # düzenlenen ≠ sunulan: yarım günden uzun süren uyuşmazlık
        fire["duz_sun"] = None
        start = None
        for s in sm:
            mism = s.get("duz_fp") and s.get("sun_fp") and s["duz_fp"] != s["sun_fp"]
            if mism and start is None:
                start = s["t"]
            elif not mism:
                start = None
            if start is not None and s["t"] - start >= 0.5 * sc:
                fire["duz_sun"] = start + 0.5 * sc
                break
        fire["zincir"] = outage
        lead = {}
        for k, t in fire.items():
            if t is None:
                lead[k] = None
            elif outage is None:
                lead[k] = "yanlis-alarm" if fid == "f0" else round((sm[-1]["t"] - t) / sc, 1)
            else:
                lead[k] = round((outage - t) / sc, 1)
        # sabit eşiklerin sağlıklı uç noktada alarmda kaldığı süre oranı (yalnızca kontrol)
        alarm_frac = {}
        if fid == "f0":
            # ilk yenileme döngüsü: ilk düzenlemeden ilk başarılı yenilemeye kadar
            t_ren = next((j["t"] for j in jobs if j["sonuc"] == "basarili"), sm[-1]["t"])
            ok = [s for s in sm if "sun_na" in s and s["t"] <= t_ren]
            for th in FIXED:
                alarm_frac[str(th)] = round(sum(1 for s in ok if s["sun_na"] - s["t"] < th * sc) / len(ok), 3)
            alarm_frac["oran"] = round(sum(1 for s in ok if s["sun_na"] - s["t"] < prop) / len(ok), 3)
        # düzenleme -> sunum gecikmesi (gerçek saniye), sağlıklı yenilemelerde
        renew_ok = [j for j in jobs if j["sonuc"] == "basarili"]
        out["hosts"][fid] = {
            "label": h["label"], "inject_day": None if inj is None else round((inj - h["t0"]) / sc, 1),
            "outage_day": None if outage is None else round((outage - h["t0"]) / sc, 1), "outage_cause": cause,
            "first_renew_day": next((round((j["t"] - h["t0"]) / sc, 1) for j in jobs if j["sonuc"] != "bos"), None),
            "jobs": len(jobs), "jobs_failed_rc": sum(1 for j in jobs if j["rc"] != 0),
            "jobs_ok_renew": len(renew_ok), "lead_days": lead, "alarm_frac": alarm_frac,
        }
    return out


def main():
    run = Path(sys.argv[1])
    res = {}
    for d in sorted(p for p in run.iterdir() if (p / "meta.json").exists()):
        r = analyze_class(d)
        res[str(r["days"])] = r
        print(f"\n=== {r['days']} günlük sınıf (yenileme: {r['renew_before']} gün kala; 1 gün = {r['scale']} sn)")
        cols = [k for k, _ in SIGNALS]
        print(f"{'arıza':<24}{'enj.':>5}{'ilk yen.':>9}{'kesinti':>8}  " + "".join(f"{c[:12]:>13}" for c in cols))
        for fid, h in r["hosts"].items():
            row = "".join(f"{str(h['lead_days'][c]) if h['lead_days'][c] is not None else '—':>13}" for c in cols)
            print(f"{fid+' '+h['label']:<24}{str(h['inject_day']):>5}{str(h['first_renew_day']):>9}{str(h['outage_day']):>8}  {row}")
        print("kontrol alarm oranı:", r["hosts"]["f0"]["alarm_frac"])
    (run / "sonuc.json").write_text(json.dumps(res, indent=1, ensure_ascii=False))


if __name__ == "__main__":
    main()
