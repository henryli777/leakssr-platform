#!/usr/bin/env python3
"""Build the public LeakSSR UI without publishing development/admin files."""

import argparse
from pathlib import Path
import shutil


STATIC = Path(__file__).resolve().parent / "static"
ASSETS = ("favicon.svg", "styles.css", "node-search.css", "freshness.js", "node-search.js", "platform.js",
          "source.html", "source.js", "404.html", "error-page.js", "vendor/lucide.min.js", "vendor/LICENSE")


def build_assets(output_dir):
    output = Path(output_dir)
    output.mkdir(parents=True, exist_ok=True)
    shutil.copyfile(STATIC / "index.html.tpl", output / "index.html")
    for name in ASSETS:
        destination = output / name
        destination.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(STATIC / name, destination)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output-dir", type=Path, default=Path("dist"))
    build_assets(parser.parse_args().output_dir)
