#!/usr/bin/env python3
"""
ZaphNews OG Image Generator
============================
Generates Open Graph (1200x630) images for ZaphNews articles.

Usage:
    python scripts/zaphnews_og_generator.py --title "Article Title" --tag "BREAKING" --output og-glasswing.png
    python scripts/zaphnews_og_generator.py --all  # Generate OG images for all known articles

Requirements:
    pip install Pillow

Environment:
    ZAPHNEWS_OG_OUTPUT_DIR  - Output directory (default: zaphscore-landing/zaphnews/og/)
    ZAPHNEWS_OG_FONT_PATH   - Path to font file (default: system fonts)
"""
from __future__ import annotations

import argparse
import os
import sys
import textwrap
from dataclasses import dataclass
from pathlib import Path
from typing import Optional, Tuple

try:
    from PIL import Image, ImageDraw, ImageFont  # type: ignore
except ImportError:
    print("ERROR: Pillow not installed. Run: pip install Pillow", file=sys.stderr)
    sys.exit(1)

# ---- Design constants --------------------------------------------------------
OG_WIDTH = 1200
OG_HEIGHT = 630

# Color palette (matches ZaphNews CSS)
COLOR_BG = (8, 11, 16)          # --bg: #080b10
COLOR_SURFACE = (13, 17, 23)    # --surface: #0d1117
COLOR_BORDER = (30, 39, 51)     # --border: #1e2733
COLOR_ACCENT = (204, 136, 255)  # --accent: #cc88ff
COLOR_ACCENT2 = (85, 204, 255)  # --accent2: #55ccff
COLOR_RED = (255, 59, 59)       # --red: #ff3b3b
COLOR_TEXT = (232, 237, 243)    # --text: #e8edf3
COLOR_MUTED = (130, 146, 166)   # --muted: #8292a6

TAG_COLORS = {
    "BREAKING": COLOR_RED,
    "REGULATORY": COLOR_ACCENT,
    "RESEARCH": COLOR_ACCENT2,
    "OPINION": (255, 140, 66),   # --orange
    "SECURITY": COLOR_RED,
    "POLICY": COLOR_ACCENT,
}

# ---- Article registry --------------------------------------------------------
@dataclass
class ArticleSpec:
    slug: str
    title: str
    tag: str
    date: str


ARTICLES = [
    ArticleSpec("glasswing",    "Project Glasswing: The Day Claude Crossed the Line",           "BREAKING",   "April 8, 2026"),
    ArticleSpec("eu-ai-act",    "EU AI Act: The Clock That Will Bankrupt 60% of AI Teams",      "REGULATORY", "April 6, 2026"),
    ArticleSpec("fearscore",    "FearScore: Why Your AI Risk Number Is Lying to You",           "OPINION",    "April 5, 2026"),
    ArticleSpec("top10-mistakes","Top 10 AI Agent Security Mistakes Teams Make Before Launch",  "SECURITY",   "April 4, 2026"),
]

# ---- Font loading ------------------------------------------------------------

def load_font(size: int, bold: bool = False) -> ImageFont.FreeTypeFont:
    """Load a system font, falling back to PIL default."""
    candidates = [
        "/usr/share/fonts/truetype/dejavu/DejaVuSerif-Bold.ttf" if bold else "/usr/share/fonts/truetype/dejavu/DejaVuSerif.ttf",
        "/usr/share/fonts/truetype/liberation/LiberationSerif-Bold.ttf" if bold else "/usr/share/fonts/truetype/liberation/LiberationSerif-Regular.ttf",
        "C:/Windows/Fonts/Georgia Bold.ttf" if bold else "C:/Windows/Fonts/Georgia.ttf",
        "C:/Windows/Fonts/georgiab.ttf" if bold else "C:/Windows/Fonts/georgia.ttf",
        "/System/Library/Fonts/Supplemental/Georgia Bold.ttf" if bold else "/System/Library/Fonts/Supplemental/Georgia.ttf",
    ]
    font_path = os.environ.get("ZAPHNEWS_OG_FONT_PATH")
    if font_path:
        candidates.insert(0, font_path)

    for path in candidates:
        if os.path.exists(path):
            try:
                return ImageFont.truetype(path, size)
            except Exception:
                continue

    # Pillow built-in fallback (no size control)
    return ImageFont.load_default()


# ---- Drawing utilities -------------------------------------------------------

def draw_gradient_bg(draw: ImageDraw.Draw, width: int, height: int) -> None:
    """Draw dark background with subtle radial effect."""
    # Solid dark background
    draw.rectangle([0, 0, width, height], fill=COLOR_BG)

    # Subtle top highlight
    for y in range(80):
        alpha = int(20 * (1 - y / 80))
        draw.line([(0, y), (width, y)], fill=(*COLOR_ACCENT2, alpha))


def draw_grid_lines(draw: ImageDraw.Draw, width: int, height: int) -> None:
    """Draw subtle editorial grid lines."""
    # Top accent bar
    draw.rectangle([0, 0, width, 3], fill=COLOR_ACCENT2)
    # Bottom bar
    draw.rectangle([0, height - 1, width, height], fill=COLOR_BORDER)


def draw_tag_badge(draw: ImageDraw.Draw, tag: str, x: int, y: int, font: ImageFont.FreeTypeFont) -> int:
    """Draw colored tag badge, return right edge x."""
    color = TAG_COLORS.get(tag.upper(), COLOR_ACCENT)
    text = tag.upper()

    # Measure text
    bbox = draw.textbbox((0, 0), text, font=font)
    tw = bbox[2] - bbox[0]
    th = bbox[3] - bbox[1]

    pad_x, pad_y = 14, 6
    rx, ry = x + tw + pad_x * 2, y + th + pad_y * 2

    # Background
    draw.rectangle([x, y, rx, ry], fill=(*color, 20), outline=(*color, 80))
    draw.text((x + pad_x, y + pad_y), text, font=font, fill=color)

    return rx + 16


def wrap_title(title: str, max_chars_per_line: int = 36) -> list[str]:
    """Wrap title text for OG image."""
    words = title.split()
    lines: list[str] = []
    current = ""
    for word in words:
        test = (current + " " + word).strip()
        if len(test) > max_chars_per_line and current:
            lines.append(current)
            current = word
        else:
            current = test
    if current:
        lines.append(current)
    return lines[:4]  # Max 4 lines


# ---- Main generator ---------------------------------------------------------

def generate_og_image(
    title: str,
    tag: str = "BREAKING",
    date: str = "",
    output_path: str = "og-output.png",
) -> str:
    """Generate a single OG image and save to output_path."""
    img = Image.new("RGB", (OG_WIDTH, OG_HEIGHT), COLOR_BG)
    draw = ImageDraw.Draw(img, "RGBA")

    draw_gradient_bg(draw, OG_WIDTH, OG_HEIGHT)
    draw_grid_lines(draw, OG_WIDTH, OG_HEIGHT)

    # Fonts
    font_tag = load_font(18, bold=True)
    font_title = load_font(52, bold=True)
    font_title_sm = load_font(42, bold=True)
    font_brand = load_font(22, bold=True)
    font_meta = load_font(18)
    font_domain = load_font(16)

    # Left margin
    lm = 72

    # Brand name (top left)
    draw.text((lm, 52), "ZAPHNEWS", font=font_brand, fill=COLOR_ACCENT)
    draw.text((lm + 160, 52), "AI Security Intelligence", font=font_meta, fill=COLOR_MUTED)

    # Tag badge
    tag_y = 130
    draw_tag_badge(draw, tag, lm, tag_y, font_tag)

    # Title
    lines = wrap_title(title)
    font_t = font_title if len(lines) <= 2 else font_title_sm
    title_y = 200
    line_height = 68 if len(lines) <= 2 else 56
    for line in lines:
        draw.text((lm, title_y), line, font=font_t, fill=COLOR_TEXT)
        title_y += line_height

    # Date + separator
    if date:
        sep_y = OG_HEIGHT - 100
        draw.rectangle([lm, sep_y, OG_WIDTH - lm, sep_y + 1], fill=COLOR_BORDER)
        draw.text((lm, sep_y + 14), date, font=font_meta, fill=COLOR_MUTED)

    # Domain (bottom right)
    domain = "zaphscore.zaphenath.app"
    bbox = draw.textbbox((0, 0), domain, font=font_domain)
    dw = bbox[2] - bbox[0]
    draw.text((OG_WIDTH - lm - dw, OG_HEIGHT - 86), domain, font=font_domain, fill=COLOR_ACCENT2)

    # Score watermark (bottom right corner accent)
    draw.text((OG_WIDTH - 160, OG_HEIGHT - 140), "ZaphScore", font=font_meta, fill=(*COLOR_ACCENT2, 80))

    # Save
    Path(output_path).parent.mkdir(parents=True, exist_ok=True)
    img.save(output_path, "PNG", optimize=True)
    print(f"Generated: {output_path} ({OG_WIDTH}x{OG_HEIGHT})")
    return output_path


def main() -> None:
    parser = argparse.ArgumentParser(description="ZaphNews OG Image Generator")
    parser.add_argument("--title", help="Article title")
    parser.add_argument("--tag", default="BREAKING", help="Tag label (BREAKING, REGULATORY, etc.)")
    parser.add_argument("--date", default="", help="Publication date string")
    parser.add_argument("--output", default="og-output.png", help="Output file path")
    parser.add_argument("--all", action="store_true", help="Generate OG images for all known articles")
    args = parser.parse_args()

    output_dir = os.environ.get(
        "ZAPHNEWS_OG_OUTPUT_DIR",
        "zaphscore-landing/zaphnews/og"
    )

    if args.all:
        print(f"Generating OG images for {len(ARTICLES)} articles...")
        for art in ARTICLES:
            out = str(Path(output_dir) / f"og-{art.slug}.png")
            generate_og_image(art.title, art.tag, art.date, out)
        print("Done.")
    elif args.title:
        generate_og_image(args.title, args.tag, args.date, args.output)
    else:
        parser.print_help()
        sys.exit(1)


if __name__ == "__main__":
    main()
