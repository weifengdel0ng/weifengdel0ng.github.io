from __future__ import annotations

import argparse
import re
import shutil
from datetime import datetime
from pathlib import Path
from unicodedata import normalize
from urllib.parse import quote


VAULT_ROOT = Path(r"C:\Users\ericgao\Documents\Obsidian Vault")
IMAGE_EXTS = {".png", ".jpg", ".jpeg", ".webp", ".gif", ".svg", ".bmp"}
SKIP_EXTS = {".md"}


def read_text(path: Path) -> str:
    for encoding in ("utf-8", "utf-8-sig", "gb18030", "gbk"):
        try:
            return path.read_text(encoding=encoding)
        except UnicodeDecodeError:
            continue
    return path.read_text(encoding="utf-8", errors="ignore")


def slugify(value: str) -> str:
    value = normalize("NFKC", value).strip().lower()
    value = re.sub(r"[\\/:*?\"<>|]+", "-", value)
    value = re.sub(r"\s+", "-", value)
    value = re.sub(r"-{2,}", "-", value)
    value = value.strip(".-")
    return value or "post"


def encode_rel_path(path: str) -> str:
    return "/".join(quote(part) for part in path.split("/"))


def resolve_asset_path(source_root: Path, source_dir: Path, raw_target: str) -> Path | None:
    target = raw_target.split("|", 1)[0].strip()

    candidates = [
        source_dir / target,
        source_root / target,
        VAULT_ROOT / target,
    ]
    for candidate in candidates:
        if candidate.exists():
            return candidate

    name = Path(target).name
    for base in (source_dir, source_root, VAULT_ROOT):
        found = list(base.rglob(name))
        if found:
            return found[0]
    return None


def unique_asset_name(asset: Path, used: set[str]) -> str:
    stem = slugify(asset.stem)
    suffix = asset.suffix.lower()
    candidate = f"{stem}{suffix}"
    index = 1
    while candidate in used:
        index += 1
        candidate = f"{stem}-{index}{suffix}"
    used.add(candidate)
    return candidate


def convert_wikilinks(text: str, source_root: Path, source_dir: Path) -> tuple[str, dict[Path, str]]:
    asset_map: dict[Path, str] = {}
    used_names: set[str] = set()

    def replace_embed(match: re.Match[str]) -> str:
        raw = match.group(1).strip()
        asset = resolve_asset_path(source_root, source_dir, raw)
        label = Path(raw.split("|", 1)[0]).name
        if asset is None:
            return label

        target_name = asset_map.get(asset)
        if target_name is None:
            target_name = unique_asset_name(asset, used_names)
            asset_map[asset] = target_name

        rel = encode_rel_path(target_name)
        if asset.suffix.lower() in IMAGE_EXTS:
            return f"![{label}]({rel})"
        return f"[{label}]({rel})"

    def replace_link(match: re.Match[str]) -> str:
        raw = match.group(1).strip()
        if "|" in raw:
            _, label = raw.split("|", 1)
            return label.strip()
        return Path(raw).stem

    text = re.sub(r"!\[\[([^\]]+)\]\]", replace_embed, text)
    text = re.sub(r"(?<!!)\[\[([^\]]+)\]\]", replace_link, text)
    return text, asset_map


def write_section_index(target_dir: Path, title: str, description: str) -> None:
    content = "\n".join(
        [
            "+++",
            f'title = "{title.replace(chr(34), "")}"',
            f'description = "{description.replace(chr(34), "")}"',
            "+++",
            "",
        ]
    )
    (target_dir / "_index.md").write_text(content, encoding="utf-8")


def build_front_matter(source: Path, category: str, tag: str) -> str:
    date = datetime.fromtimestamp(source.stat().st_mtime).strftime("%Y-%m-%d")
    lines = [
        "+++",
        f'title = "{source.stem.replace(chr(34), "")}"',
        f'date = "{date}"',
        'type = "post"',
        f'categories = ["{category}"]',
        f'tags = ["{tag}"]',
        "draft = false",
        "+++",
        "",
    ]
    return "\n".join(lines)


def import_note(source_root: Path, dest_root: Path, source_file: Path, category: str, tag: str) -> None:
    rel_parent = source_file.parent.relative_to(source_root)
    dest_parent = dest_root.joinpath(*rel_parent.parts)
    bundle_dir = dest_parent / slugify(source_file.stem)
    bundle_dir.mkdir(parents=True, exist_ok=True)

    body, asset_map = convert_wikilinks(read_text(source_file), source_root, source_file.parent)
    body = body.replace("\r\n", "\n")
    front_matter = build_front_matter(source_file, category, tag)
    (bundle_dir / "index.md").write_text(front_matter + body.strip() + "\n", encoding="utf-8")

    for source_asset, target_name in asset_map.items():
        shutil.copy2(source_asset, bundle_dir / target_name)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--source", required=True)
    parser.add_argument("--dest", required=True)
    parser.add_argument("--title", required=True)
    parser.add_argument("--description", required=True)
    parser.add_argument("--category", required=True)
    parser.add_argument("--tag", required=True)
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    source_root = Path(args.source)
    dest_root = Path(args.dest)

    if dest_root.exists():
        shutil.rmtree(dest_root)
    dest_root.mkdir(parents=True, exist_ok=True)

    write_section_index(dest_root, args.title, args.description)

    for source_file in sorted(source_root.rglob("*.md")):
        import_note(source_root, dest_root, source_file, args.category, args.tag)


if __name__ == "__main__":
    main()
