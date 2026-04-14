#!/usr/bin/env python3
# /// script
# requires-python = ">=3.12"
# dependencies = [
#   "Pillow",
# ]
# ///

from __future__ import annotations

import argparse
import sys
from pathlib import Path


DEFAULT_INPUT = Path("crates/maya-scene-kit-gui/resources/windows/app.png")
DEFAULT_OUTPUT = Path("crates/maya-scene-kit-gui/resources/windows/app.ico")
DEFAULT_SIZES = (16, 24, 32, 48, 64, 128, 256)


def parse_sizes(raw: str) -> list[tuple[int, int]]:
    sizes: list[tuple[int, int]] = []
    for part in raw.split(","):
        token = part.strip()
        if not token:
            continue
        try:
            size = int(token)
        except ValueError as exc:
            raise argparse.ArgumentTypeError(f"invalid icon size: {token}") from exc
        if size <= 0:
            raise argparse.ArgumentTypeError(f"icon size must be positive: {token}")
        sizes.append((size, size))

    if not sizes:
        raise argparse.ArgumentTypeError("at least one icon size is required")

    deduped = sorted(set(sizes))
    return deduped


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Generate a Windows .ico file from a PNG image.",
    )
    parser.add_argument(
        "input_png",
        nargs="?",
        default=str(DEFAULT_INPUT),
        help=f"source PNG path (default: {DEFAULT_INPUT})",
    )
    parser.add_argument(
        "output_ico",
        nargs="?",
        default=str(DEFAULT_OUTPUT),
        help=f"destination ICO path (default: {DEFAULT_OUTPUT})",
    )
    parser.add_argument(
        "--sizes",
        default=",".join(str(size) for size in DEFAULT_SIZES),
        type=parse_sizes,
        help=(
            "comma-separated square icon sizes in pixels "
            f"(default: {','.join(str(size) for size in DEFAULT_SIZES)})"
        ),
    )
    return parser


def main() -> int:
    parser = build_parser()
    args = parser.parse_args()

    try:
        from PIL import Image
    except ImportError:
        parser.error("Pillow is required. Install it with `python -m pip install pillow`.")

    input_png = Path(args.input_png)
    output_ico = Path(args.output_ico)

    if not input_png.is_file():
        parser.error(f"input PNG does not exist: {input_png}")

    output_ico.parent.mkdir(parents=True, exist_ok=True)

    with Image.open(input_png) as image:
        image.convert("RGBA").save(output_ico, format="ICO", sizes=args.sizes)

    print(
        f"wrote {output_ico} from {input_png} "
        f"with sizes {', '.join(f'{width}x{height}' for width, height in args.sizes)}"
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
