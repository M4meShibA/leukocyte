"""既知の不正ファイルのハッシュ(抗原データベース)を読み込む。"""
from pathlib import Path

_HEX = set("0123456789abcdef")


def load_hashes(path: Path) -> set[str]:
    """1行1ハッシュ(SHA-256)。'#'以降はコメント。不正な行は無視する。"""
    hashes: set[str] = set()
    for line in Path(path).read_text(encoding="utf-8").splitlines():
        value = line.split("#", 1)[0].strip().lower()
        if len(value) == 64 and set(value) <= _HEX:
            hashes.add(value)
    return hashes
