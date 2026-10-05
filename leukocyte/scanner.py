"""フォルダを走査し、ハッシュ一致・YARAルール一致・高エントロピー(難読化)のファイルを見つける。

自分自身のアプリ構造(Leukocyte)や隔離室、ルールフォルダは自動的にスキャン除外対象(Whitelist)とします。
"""
import math
import hashlib
from dataclasses import dataclass
import threading
from pathlib import Path
from typing import Callable, Iterator, Protocol

CHUNK = 1024 * 1024  # 1MBずつ読む
DEFAULT_ENTROPY_THRESHOLD = 7.8

# 自分自身(Leukocyte)のルートディレクトリを取得して安全策とする
APP_ROOT = Path(__file__).parent.resolve()      # leukocyte/ (ソースコードのフォルダ)
PROJECT_ROOT = APP_ROOT.parent                  # quarantine/ rules/ signatures/ が置かれる場所

class RuleEngine(Protocol):
    def match(self, path: Path) -> list[str]: ...

@dataclass(frozen=True)
class Detection:
    path: Path
    sha256: str
    reasons: tuple[str, ...] = ("hash",)  # "hash", "yara:ルール名", "high_entropy"

@dataclass(frozen=True)
class ScanError:
    path: Path
    reason: str

def sha256_of(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        while block := f.read(CHUNK):
            h.update(block)
    return h.hexdigest()

def calculate_entropy(path: Path) -> float:
    """ファイル全体のシャノンエントロピー(0.0〜8.0)を計算する。"""
    byte_counts = [0] * 256
    total_bytes = 0
    with path.open("rb") as f:
        while block := f.read(CHUNK):
            total_bytes += len(block)
            for b in block:
                byte_counts[b] += 1

    if total_bytes == 0:
        return 0.0

    entropy = 0.0
    for count in byte_counts:
        if count == 0:
            continue
        p = count / total_bytes
        entropy -= p * math.log2(p)
    return entropy

def check_file(
    path: Path,
    known_bad: set[str],
    engine: RuleEngine | None = None,
    entropy_threshold: float = DEFAULT_ENTROPY_THRESHOLD,
) -> Detection | ScanError | None:
    """1ファイルを調べる。検知ならDetection、読めなければScanError、問題なければNone。"""
    try:
        if path.is_symlink() or not path.is_file():
            return None
        digest = sha256_of(path)
    except (PermissionError, OSError) as e:
        return ScanError(path, str(e))

    reasons: list[str] = []

    # 1. ハッシュ一致チェック
    if digest in known_bad:
        reasons.append("hash")

    # 2. YARAルールチェック
    error = None
    if engine is not None:
        try:
            reasons += [f"yara:{name}" for name in engine.match(path)]
        except Exception as e:
            error = ScanError(path, f"YARA: {e}")

    # 3. 高エントロピー(難読化・パッカー・暗号化)チェック
    try:
        # 画像・動画・圧縮ファイル・仮想環境・Git関連などは誤検知を防ぐため除外
        ignored_extensions = {
            ".png", ".jpg", ".jpeg", ".gif", ".mp4", ".zip", ".7z", ".rar",
            ".gz", ".pyc", ".dll", ".exe", ".bin", ".so", ".dylib",
        }
        ignored_names = {".git", "Thumbs.db", "desktop.ini"}
        if path.suffix.lower() not in ignored_extensions and path.name not in ignored_names:
            ent = calculate_entropy(path)
            if ent >= entropy_threshold and path.stat().st_size >= 128:
                reasons.append(f"high_entropy({ent:.2f})")
    except OSError:
        pass

    if reasons:
        return Detection(path, digest, tuple(reasons))
    return error

def scan_dir(
    root: Path,
    known_bad: set[str],
    exclude: tuple[Path, ...] = (),
    engine: RuleEngine | None = None,
    on_file: Callable[[Path], None] | None = None,
    cancel: threading.Event | None = None,
) -> Iterator[Detection | ScanError]:
    root = Path(root).resolve()
    
    # 【自己免疫障害ガード】呼び出し側の除外指定に加えて、自作アプリ本体・隔離室・ルールフォルダを強制的に除外リストへ追加
    default_excludes = (
        APP_ROOT,                         # Leukocyte のソースコード全体
        PROJECT_ROOT / "quarantine",     # 隔離室
        PROJECT_ROOT / "rules",          # YARAルールフォルダ
        PROJECT_ROOT / "signatures",     # ハッシュDBフォルダ
        PROJECT_ROOT / ".git",           # Git管理フォルダ
        PROJECT_ROOT / "venv",           # Python仮想環境
        PROJECT_ROOT / ".venv",
    )
    
    combined_exclude = tuple(Path(e).resolve() for e in exclude) + default_excludes

    for p in root.rglob("*"):
        if cancel is not None and cancel.is_set():
            return
            
        # 自分自身や安全なシステム管理フォルダ以下なら判定せずにスキップ
        p_resolved = p.resolve()
        if any(e == p_resolved or e in p_resolved.parents for e in combined_exclude):
            continue
            
        if on_file is not None and p.is_file() and not p.is_symlink():
            on_file(p)
            
        result = check_file(p, known_bad, engine)
        if result is not None:
            yield result