#!/bin/bash
set -euo pipefail
[[ $EUID -eq 0 ]] || { echo 'Run as root.' >&2; exit 2; }
release=$(readlink -f /opt/leakssr-platform/current)
test -r "$release/app/deploy/nginx-https.conf"
certbot certonly --non-interactive --webroot -w /var/www/letsencrypt \
    --cert-name leakssr.coinexo.top -d leakssr.coinexo.top
install -o root -g root -m 0644 "$release/app/deploy/nginx-https.conf" /etc/nginx/conf.d/leakssr.coinexo.top.conf
nginx -t
systemctl reload nginx
install -d -m 0755 /etc/letsencrypt/renewal-hooks/deploy
install -o root -g root -m 0755 "$release/app/deploy/renew-nginx.sh" /etc/letsencrypt/renewal-hooks/deploy/leakssr-platform-nginx
systemctl enable --now certbot.timer
