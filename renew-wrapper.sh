#!/bin/sh
# certbot renew sarmalayıcısı.
# certbot, deploy-hook hata verse bile 0 ile çıkar; bu betik o hatayı çıkış koduna taşır
# ve her çalışmada bir "nabız" bırakır (iş hiç çalışmazsa nabzın yaşı alarm üretir).
OUT=$(certbot renew --no-random-sleep-on-renew "$@" 2>&1)
RC=$?
echo "$OUT"
if echo "$OUT" | grep -q "reported error code"; then
  RC=3
fi
date +%s > "$NABIZ"
exit $RC
