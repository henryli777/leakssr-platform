#!/bin/bash
set -euo pipefail
if [[ $# -ne 1 || -e $1 ]]; then
    echo 'Usage: package-source.sh NEW_OUTPUT_DIRECTORY' >&2
    exit 2
fi
source_dir=$(cd "$(dirname "$0")/.." && pwd)
mkdir -p "$1/static/vendor" "$1/data" "$1/.github/workflows"
target=$(cd "$1" && pwd)
for name in LICENSE node_lookup.py platform_build.py platform_refresh.py \
    requirements-platform.txt test_node_lookup.py test_node_search.js \
    test_platform_build.py test_platform_refresh.py DEPLOYMENT.md .gitignore; do
    cp "$source_dir/$name" "$target/$name"
done
readme="$source_dir/PLATFORM_README.md"
[[ -f $readme ]] || readme="$source_dir/README.md"
cp "$readme" "$target/README.md"
cp "$source_dir/data/live_urls.json" "$target/data/live_urls.json"
cp "$source_dir/.github/workflows/platform-ci.yml" "$target/.github/workflows/"
for name in index.html.tpl styles.css node-search.css node-search.js platform.js source.html source.js; do
    cp "$source_dir/static/$name" "$target/static/$name"
done
cp "$source_dir/static/vendor/lucide.min.js" "$source_dir/static/vendor/LICENSE" "$target/static/vendor/"
cp -R "$source_dir/deploy" "$target/deploy"
printf 'Source package: %s\n' "$target"
