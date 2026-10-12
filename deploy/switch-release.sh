#!/bin/bash
set -euo pipefail

if [[ $EUID -ne 0 || $# -ne 1 || ! $1 =~ ^[A-Za-z0-9][A-Za-z0-9._-]{0,79}$ ]]; then
    echo 'Usage (root): leakssr-platform-switch RELEASE_ID' >&2
    exit 2
fi

base=/opt/leakssr-platform
lock=/var/lib/leakssr-platform/deploy-refresh.lock
target="$base/releases/$1"
if [[ ! -f "$lock" ]]; then
    echo 'Deployment lock is missing; finish service-account installation.' >&2
    exit 2
fi
exec 9<>"$lock"
/usr/bin/flock --exclusive --wait 1800 9

if [[ $(readlink -f "$target") != "$target" ||
      ! -r "$target/app/platform_refresh.py" ||
      ! -r "$target/app/data/live_urls.json" ||
      ! -x "$target/venv/bin/python" ||
      ! -r "$target/public/index.html" ||
      ! -r "$target/public/health.json" ]]; then
    echo 'Release must be a complete, real directory inside releases.' >&2
    exit 2
fi
if [[ -e "$base/current" && ! -L "$base/current" ]]; then
    echo 'Refusing to replace current because it is not a symlink.' >&2
    exit 2
fi

temporary="$base/.current-$$"
trap 'rm -f "$temporary"' EXIT
ln -s "$target" "$temporary"
mv -T "$temporary" "$base/current"
printf 'Active release: %s\n' "$target"
