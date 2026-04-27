from __future__ import annotations

import re
import shutil
from datetime import datetime
from pathlib import Path
from unicodedata import normalize
from urllib.parse import quote


SOURCE_ROOT = Path(r"C:\Users\ericgao\Documents\Obsidian Vault\pwn\题目\buu")
DEST_ROOT = Path(r"D:\blog\blog\content\buu")

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


def resolve_asset_path(source_dir: Path, raw_target: str) -> Path | None:
    target = raw_target.split("|", 1)[0].strip()
    direct = source_dir / target
    if direct.exists():
        return direct

    by_name = list(source_dir.rglob(Path(target).name))
    if by_name:
        return by_name[0]
    return None


def convert_wikilinks(text: str, source_dir: Path) -> str:
    def replace_embed(match: re.Match[str]) -> str:
        raw = match.group(1).strip()
        asset = resolve_asset_path(source_dir, raw)
        label = Path(raw.split("|", 1)[0]).name
        if asset is None:
            return label

        rel = encode_rel_path(asset.relative_to(source_dir).as_posix())
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
    return text


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


def ensure_section_indexes() -> None:
    write_section_index(DEST_ROOT, "BUU", "BUUOJ PWN 题解归档")

    for directory in sorted(path for path in SOURCE_ROOT.rglob("*") if path.is_dir()):
        rel = directory.relative_to(SOURCE_ROOT)
        dest = DEST_ROOT.joinpath(*rel.parts)
        dest.mkdir(parents=True, exist_ok=True)
        write_section_index(dest, directory.name, f"{directory.name} 目录")


def copy_assets(source_dir: Path, dest_dir: Path) -> None:
    for asset in source_dir.rglob("*"):
        if not asset.is_file() or asset.suffix.lower() in SKIP_EXTS:
            continue
        target = dest_dir / asset.relative_to(source_dir)
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(asset, target)


def build_front_matter(source: Path) -> str:
    date = datetime.fromtimestamp(source.stat().st_mtime).strftime("%Y-%m-%d")
    lines = [
        "+++",
        f'title = "{source.stem.replace(chr(34), "")}"',
        f'date = "{date}"',
        'type = "post"',
        "categories = ['BUU']",
        "tags = ['BUU']",
        "draft = false",
        "+++",
        "",
    ]
    return "\n".join(lines)


def import_note(source_file: Path) -> None:
    rel_parent = source_file.parent.relative_to(SOURCE_ROOT)
    dest_parent = DEST_ROOT.joinpath(*rel_parent.parts)
    bundle_dir = dest_parent / slugify(source_file.stem)
    bundle_dir.mkdir(parents=True, exist_ok=True)

    body = convert_wikilinks(read_text(source_file), source_file.parent).replace("\r\n", "\n")
    front_matter = build_front_matter(source_file)
    (bundle_dir / "index.md").write_text(front_matter + body.strip() + "\n", encoding="utf-8")
    copy_assets(source_file.parent, bundle_dir)


def main() -> None:
    if DEST_ROOT.exists():
        shutil.rmtree(DEST_ROOT)
    DEST_ROOT.mkdir(parents=True, exist_ok=True)

    ensure_section_indexes()

    for source_file in sorted(SOURCE_ROOT.rglob("*.md")):
        import_note(source_file)


if __name__ == "__main__":
    main()
