# LeakSSR on Ubuntu

Deploy the static platform to `leakssr.coinexo.top` on `43.108.37.222`.
Nginx serves generated files; `platform_refresh.py` fetches the existing source
list every 30 minutes. The refresh job needs no scraper API key or notification
credential. Keep secrets, `.env`, repository history, development files, and
unrelated applications out of the release and public directory.

## Layout and ownership

```text
/opt/leakssr-platform/
  releases/<release-id>/
    app/                  root-owned Python source and data/live_urls.json
    public/               generated site, exports, snapshots, and health.json
    venv/                 root-owned Python virtual environment
  current -> releases/<release-id>
/var/lib/leakssr-platform/deploy-refresh.lock
/usr/local/libexec/leakssr-platform-refresh
/usr/local/sbin/leakssr-platform-switch
```

`app`, `venv`, the release directory, and `releases` must be owned by root and
not writable by the service account. Only `public` and its private state directory
are writable by the no-login `leakssr-refresh` user. Public directories use group
`www-data` and the setgid bit so Nginx can read newly generated snapshots.
Python publishes `health.json` with mode 0644; the service uses umask 0022.
Do not chmod setgid directories from the restricted refresh service.

Both refresh and release switching acquire the same persistent lock **before**
resolving `current`. The lock is held for the whole refresh. Never replace or
delete the lock file, change `current` by hand, or remove an active release.
Use the switch helper for rollout and rollback. Nginx follows `current` on each
request; switching releases does not require a Nginx reload.

The service's writable mount covers `releases` so resolving `current` after a
switch does not use an old writable mount. Root ownership and ordinary Unix
permissions keep every `app` and `venv` read-only to the service account.

## First Installation

Run the following on the Ubuntu server as root. Nginx, Certbot, Python venv,
rsync, and util-linux (`flock`) must be installed. This host already runs Nginx
and other applications; use the new filenames below and preserve their vhosts.

Upload a prepared release into
`/opt/leakssr-platform/releases/<release-id>/app` and its built site into
`.../public`. The refresh runtime requires only `platform_refresh.py`,
`node_lookup.py`, `data/live_urls.json`, and the deployment files in `app`.
Use a release ID containing letters, digits, `.`, `_`, or `-`, beginning with a
letter or digit. The examples use `20261012-001`; choose a new ID per upload.

```sh
LEAKSSR_RELEASE_ID=20261012-001
LEAKSSR_RELEASE=/opt/leakssr-platform/releases/$LEAKSSR_RELEASE_ID
getent passwd leakssr-refresh >/dev/null || useradd --system \
  --user-group --home-dir /var/lib/leakssr-platform \
  --shell /usr/sbin/nologin leakssr-refresh
install -d -o root -g root -m 0755 /opt/leakssr-platform/releases
install -d -o leakssr-refresh -g leakssr-refresh -m 0750 /var/lib/leakssr-platform
test -f /var/lib/leakssr-platform/deploy-refresh.lock || \
  install -o leakssr-refresh -g leakssr-refresh -m 0640 /dev/null \
    /var/lib/leakssr-platform/deploy-refresh.lock
python3 -m venv "$LEAKSSR_RELEASE/venv"
"$LEAKSSR_RELEASE/venv/bin/python" -m pip install \
  --index-url https://pypi.org/simple -r "$LEAKSSR_RELEASE/app/requirements-platform.txt"
chown root:root "$LEAKSSR_RELEASE"
chmod 0755 "$LEAKSSR_RELEASE"
chown -R root:root "$LEAKSSR_RELEASE/app" "$LEAKSSR_RELEASE/venv"
chmod -R go-w "$LEAKSSR_RELEASE/app" "$LEAKSSR_RELEASE/venv"
chown -R leakssr-refresh:www-data "$LEAKSSR_RELEASE/public"
find "$LEAKSSR_RELEASE/public" -type d -exec chmod 2755 {} +
find "$LEAKSSR_RELEASE/public" -type f -exec chmod 0644 {} +
install -d -m 0755 /usr/local/libexec /etc/nginx/snippets
install -o root -g root -m 0755 "$LEAKSSR_RELEASE/app/deploy/refresh-current.sh" \
  /usr/local/libexec/leakssr-platform-refresh
install -o root -g root -m 0755 "$LEAKSSR_RELEASE/app/deploy/switch-release.sh" \
  /usr/local/sbin/leakssr-platform-switch
install -o root -g root -m 0644 \
  "$LEAKSSR_RELEASE/app/deploy/leakssr-platform-refresh.service" \
  "$LEAKSSR_RELEASE/app/deploy/leakssr-platform-refresh.timer" /etc/systemd/system/
install -o root -g root -m 0644 "$LEAKSSR_RELEASE/app/deploy/nginx-static.conf" \
  /etc/nginx/snippets/leakssr-platform-static.conf
install -o root -g root -m 0644 "$LEAKSSR_RELEASE/app/deploy/nginx-http.conf" \
  /etc/nginx/conf.d/leakssr.coinexo.top.conf
leakssr-platform-switch "$LEAKSSR_RELEASE_ID"
nginx -t
systemctl reload nginx
systemctl daemon-reload
systemctl enable --now leakssr-platform-refresh.timer
systemctl start leakssr-platform-refresh.service
```

The prepared `public` directory must include `index.html`, `health.json`, the
static JS/CSS/vendor assets, and `sub/` exports. Upload with `rsync -a` or a tar
archive that preserves symbolic links: refresh publishes `sub` as a relative
symlink into `.platform-snapshots`. Do not dereference or omit that hidden
snapshot directory. Build virtual environments at their final release path.

The source list is private to the runtime location, but source links and node
credentials contained in subscription exports are intentionally available
through the public platform. Only publish sources that may be distributed.

## DNS and HTTPS

Create an A record `leakssr.coinexo.top` pointing to `43.108.37.222`. Remove an
incorrect AAAA record. Confirm public DNS outside any local fake-IP DNS/TUN
proxy. If Cloudflare proxying is enabled, use Full (strict) after installing a
valid origin certificate and bypass caching for `/health.json` and `/sub/*`.

HTTP validation can run before DNS propagation:

```sh
curl --resolve leakssr.coinexo.top:80:127.0.0.1 \
  http://leakssr.coinexo.top/health.json
curl --resolve leakssr.coinexo.top:80:127.0.0.1 \
  -I http://leakssr.coinexo.top/sub/all.txt
```

After public DNS resolves, keep port 80 reachable for the ACME challenge. Then:

```sh
install -d -m 0755 /var/www/letsencrypt/.well-known/acme-challenge
certbot certonly --webroot -w /var/www/letsencrypt \
  --cert-name leakssr.coinexo.top -d leakssr.coinexo.top
LEAKSSR_RELEASE=$(readlink -f /opt/leakssr-platform/current)
install -o root -g root -m 0644 "$LEAKSSR_RELEASE/app/deploy/nginx-https.conf" \
  /etc/nginx/conf.d/leakssr.coinexo.top.conf
nginx -t
systemctl reload nginx
install -d -m 0755 /etc/letsencrypt/renewal-hooks/deploy
install -o root -g root -m 0755 "$LEAKSSR_RELEASE/app/deploy/renew-nginx.sh" \
  /etc/letsencrypt/renewal-hooks/deploy/leakssr-platform-nginx
systemctl enable --now certbot.timer
certbot renew --cert-name leakssr.coinexo.top --dry-run
curl --resolve leakssr.coinexo.top:443:127.0.0.1 \
  -I https://leakssr.coinexo.top/
```

Do not install the TLS template before its named certificate exists. The
standalone host configuration uses the existing shared Nginx process, and
`nginx -t` must pass before any reload. The renewal hook reloads Nginx only for
the LeakSSR certificate. The CSP expects scripts, fonts, and images to be local.

## Updates and Rollback

Prepare a new release in a new directory, create its venv there, and apply the
same root/app/venv and refresh/public ownership rules. Ensure its complete
static snapshot is present before switching. Keep at least the preceding
release. Use these commands for both deployment and rollback:

```sh
leakssr-platform-switch 20261012-002
systemctl start leakssr-platform-refresh.service
curl --resolve leakssr.coinexo.top:443:127.0.0.1 \
  https://leakssr.coinexo.top/health.json
# Roll back to the retained release when necessary.
leakssr-platform-switch 20261012-001
```

The switch helper waits up to 30 minutes for a running refresh. A scheduled
refresh waits up to two minutes for a deployment lock, then reports failure if
it cannot start. A fully failed source fetch returns a failed service status;
when a prior snapshot exists, that snapshot remains available and health marks
it stale. Partial successful refreshes publish a new snapshot.

Keep the stable helper scripts, service units, Nginx snippet, and renewal hook
installed under root ownership. Updating those infrastructure files requires
separate syntax checks and `systemctl daemon-reload` or `nginx -t` plus reload;
an application release switch does not update them automatically.

```sh
systemctl status leakssr-platform-refresh.service --no-pager
systemctl list-timers leakssr-platform-refresh.timer --all --no-pager
journalctl -u leakssr-platform-refresh.service -n 50 --no-pager
readlink -f /opt/leakssr-platform/current
```

To retire old releases, stop the timer first and take the deployment lock while
checking that each removal target is neither `current` nor a retained rollback
release. Restart the timer after maintenance. The source Python code does not
run the scraper, mutate its input list, or send notifications.
