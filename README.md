# Otomatik sertifika yenilemesi bozulursa kim fark eder?

Otomatik sertifika yenilemesi sessizce bozulduğunda hangi kontrol, kesintiden ne kadar önce fark ediyor?
Bu depoda yazıdaki ölçümleri üreten düzenek, ham kayıtlar ve çizimler var. Sadece deneme amaçlıdır,
üretim ortamında olduğu gibi kullanmayın.

## Kurulum

Ubuntu 24.04 üzerinde denendi. 80 ve 443 numaralı portları kullandığı için root gerekir.

```bash
apt-get install -y pebble nginx-light
pip install certbot dnslib cryptography
chmod +x ca_olustur.sh renew-wrapper.sh
./ca_olustur.sh
```

Denenen sürümler: certbot 5.10.0, nginx 1.24.0, Pebble 2.4.0, Python 3.13.

## Çalıştırma

```bash
python3 lab.py --classes 6 --scale 20 --run kisa                    # 6 günlük sertifika, yaklaşık 3 dakika
python3 lab.py --classes 45,90 --scale 20 --run uzun                # 45 ve 90 günlük, yaklaşık 33 dakika
python3 lab.py --classes 6 --scale 20 --run kisa-korumali --guard   # üç eklemeyle aynı deney
python3 analyze.py runs/kisa                                        # sonuç tablosu ve runs/kisa/sonuc.json
python3 kanit_dogrula.py runs/kisa-korumali/6/kanit.jsonl           # kayıt zinciri bozulmuş mu?
```

`--scale` bir günün kaç saniye süreceğini belirler. İki koşuyu aynı anda çalıştırmak için `--dns-port` verin.

## Yazıdaki numaralar ve buradaki adlar

Yazıda arızalar 1'den 8'e numaralı. Kodda ve ham kayıtlarda makinelerin kendi adı var:

| Yazıda | Kodda | Ne bozuluyor |
|---|---|---|
| kontrol | f0 | hiçbir şey |
| 1 | f1 `san-dns-silindi` | sertifikadaki eski bir alan adının DNS kaydı siliniyor |
| 2 | f2 `dns-kimlik-bilgisi` | DNS API anahtarı değişiyor |
| 3 | f3 `cname-cakismasi` | `_acme-challenge` adına CNAME giriyor |
| 4 | f4 `ca-erisilemez` | sertifika otoritesine erişim kesiliyor |
| 5 | f8 `zamanlayici-kapali` | timer duruyor |
| 6 | f5 `kurulmadi` | deploy hook yok, sertifika servise kopyalanmıyor |
| 7 | f6 `yeniden-yuklenmedi` | kopyalanıyor ama reload hata veriyor |
| 8 | f7 `yanlis-zincir` | tam zincir yerine yalnızca sertifika kopyalanıyor |

## Dosyalar

| Dosya | Ne yapar |
|---|---|
| `lab.py` | Her şeyi ayağa kaldırır: CA, uç noktalar, zamanlayıcı, arızalar, gözlemci, kayıt |
| `dns_server.py` | Küçük bir DNS sunucusu ve token'la çalışan kayıt API'si |
| `renew-wrapper.sh` | certbot'u sarar: hook hatasını exit code'a taşır, nabız dosyasına tarih yazar |
| `sunum_kontrol.py` | Yenilemeden bağımsız kontrol: zincir, alınan = sunulan, yenileme gecikti mi |
| `analyze.py` | Ham kayıtlardan her kontrolün arızayı kesintiden kaç gün önce gördüğünü hesaplar |
| `kanit_dogrula.py` | Hash zincirli kaydın bütünlüğünü doğrular |
| `cizim/` | Yazıdaki çizimler: Excalidraw dosyaları ve PNG çıktıları |
| `olcumler/` | Yazıda kullanılan koşuların ham kayıtları ve `sonuc.json` dosyaları. İş kayıtlarında koşu klasörünün tam yolu `…` ile kısaltılmıştır |

## Bilinen sınırlar

- Zaman sıkıştırılmıştır, "gün" değerleri ölçeklidir. Mekanizmayı gösterir, üretimdeki oranları göstermez.
- Pebble bir test sunucusudur. `PEBBLE_AUTHZREUSE=0` iken bile yaklaşık yüzde bir olasılıkla eski bir
  yetkilendirmeyi yeniden kullanır. `lab.py` bunu önlemek için ilk sertifika alınırken oluşan
  yetkilendirmeleri devre dışı bırakır (`deactivate_authz`).
- Yalnızca certbot ve nginx, Linux üzerinde denendi.
