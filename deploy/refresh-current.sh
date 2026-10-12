#!/bin/bash
set -euo pipefail

base=/opt/leakssr-platform
lock=/var/lib/leakssr-platform/deploy-refresh.lock

# Deployment takes the same lock before resolving or replacing current.
exec 9<>"$lock"
if ! /usr/bin/flock --exclusive --wait 120 9; then
    echo 'Refresh did not start: deployment lock is busy.' >&2
    exit 75
fi

release=$(readlink -f "$base/current")
case "$release" in
    "$base"/releases/*) ;;
    *) echo 'Refresh did not start: current is outside releases.' >&2; exit 2 ;;
esac
if [[ ! -d "$release/public" || ! -r "$release/app/data/live_urls.json" ||
      ! -x "$release/venv/bin/python" ]]; then
    echo 'Refresh did not start: release is incomplete.' >&2
    exit 2
fi

cd "$release/app"
status=0
"$release/venv/bin/python" "$release/app/platform_refresh.py" \
    --output-dir "$release/public" \
    --sources "$release/app/data/live_urls.json" \
    --workers 8 --timeout 12 || status=$?

# Python publishes readable files directly. chmod on setgid directories is
# rejected by RestrictSUIDSGID even when only read permissions are requested.
exit "$status"
