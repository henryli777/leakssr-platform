#!/bin/bash
set -euo pipefail

base=/opt/leakssr-platform
lock=/var/lib/leakssr-platform/deploy-refresh.lock

# Keep this descriptor open through Python and permission repair. Deployment
# takes the same lock before resolving or replacing current.
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

# Atomic temporary files may start as 0600. New files inherit www-data from
# the public directory's setgid bit; make them readable by Nginx after either
# a successful refresh or a failed attempt that preserves the old snapshot.
find "$release/public" -type d -exec chmod g+rx {} +
find "$release/public" -type f -exec chmod g+r {} +
exit "$status"
