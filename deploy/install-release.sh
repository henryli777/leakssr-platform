#!/bin/bash
set -euo pipefail

if [[ $EUID -ne 0 || $# -ne 1 || ! $1 =~ ^[A-Za-z0-9][A-Za-z0-9._-]{0,79}$ ]]; then
    echo 'Usage (root): install-release.sh RELEASE_ID' >&2
    exit 2
fi
base=/opt/leakssr-platform
release="$base/releases/$1"
test -f "$release/app/platform_refresh.py"
test -f "$release/public/index.html"
test -f "$release/public/health.json"
getent passwd leakssr-refresh >/dev/null || useradd --system --user-group \
    --home-dir /var/lib/leakssr-platform --shell /usr/sbin/nologin leakssr-refresh
install -d -o root -g root -m 0755 "$base" "$base/releases"
install -d -o leakssr-refresh -g leakssr-refresh -m 0750 /var/lib/leakssr-platform
if [[ ! -f /var/lib/leakssr-platform/deploy-refresh.lock ]]; then
    install -o leakssr-refresh -g leakssr-refresh -m 0640 /dev/null /var/lib/leakssr-platform/deploy-refresh.lock
fi
python3 -m venv "$release/venv"
"$release/venv/bin/python" -m pip install --index-url https://pypi.org/simple -r "$release/app/requirements-platform.txt"
chown root:root "$release"
chmod 0755 "$release"
chown -R root:root "$release/app" "$release/venv"
chmod -R go-w "$release/app" "$release/venv"
chown -R leakssr-refresh:www-data "$release/public"
find "$release/public" -type d -exec chmod 2755 {} +
find "$release/public" -type f -exec chmod 0644 {} +
install -d -m 0755 /usr/local/libexec /etc/nginx/snippets
install -o root -g root -m 0755 "$release/app/deploy/refresh-current.sh" /usr/local/libexec/leakssr-platform-refresh
install -o root -g root -m 0755 "$release/app/deploy/switch-release.sh" /usr/local/sbin/leakssr-platform-switch
install -o root -g root -m 0644 "$release/app/deploy/leakssr-platform-refresh.service" \
    "$release/app/deploy/leakssr-platform-refresh.timer" /etc/systemd/system/
install -o root -g root -m 0644 "$release/app/deploy/nginx-static.conf" /etc/nginx/snippets/leakssr-platform-static.conf
if [[ ! -f /etc/nginx/conf.d/leakssr.coinexo.top.conf ]]; then
    install -o root -g root -m 0644 "$release/app/deploy/nginx-http.conf" /etc/nginx/conf.d/leakssr.coinexo.top.conf
fi
leakssr-platform-switch "$1"
nginx -t
systemctl reload nginx
systemctl daemon-reload
systemctl enable --now leakssr-platform-refresh.timer
echo 'Release installed; run a refresh and configure TLS as described in DEPLOYMENT.md.'
