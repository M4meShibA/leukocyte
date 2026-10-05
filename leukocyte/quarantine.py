"""検知したファイルを隔離フォルダへ移し、元の場所へ戻せるようにする。

隔離したファイルは「ID.quar」という名前に変え、権限も最小にして、
うっかり実行・開封されないようにする。元のパスなどは index.json に記録する。
"""
import json
import os
import shutil
import threading
import uuid
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from pathlib import Path


class QuarantineError(Exception):
    pass


class DestinationExists(QuarantineError):
    """復元先に同名のファイルがある。"""


@dataclass(frozen=True)
class Record:
    id: str
    original_path: str
    sha256: str
    quarantined_at: str


class Quarantine:
    def __init__(self, directory: Path):
        self.dir = Path(directory)
        self.dir.mkdir(parents=True, exist_ok=True)
        self.index_path = self.dir / "index.json"
        # スキャン・監視・画面操作が別スレッドから同時に索引を書き換えても、更新が消えないようにする
        self._lock = threading.RLock()

    def _load(self) -> dict[str, dict]:
        if not self.index_path.exists():
            return {}
        return json.loads(self.index_path.read_text(encoding="utf-8"))

    def _save(self, data: dict[str, dict]) -> None:
        tmp = self.index_path.with_suffix(".tmp")
        tmp.write_text(json.dumps(data, ensure_ascii=False, indent=2), encoding="utf-8")
        os.replace(tmp, self.index_path)  # 途中で止まっても壊れた索引を残さない

    def add(self, path: Path, sha256: str) -> Record:
        path = Path(path).resolve()
        rec = Record(
            id=uuid.uuid4().hex[:12],
            original_path=str(path),
            sha256=sha256,
            quarantined_at=datetime.now(timezone.utc).isoformat(timespec="seconds"),
        )
        dest = self.dir / f"{rec.id}.quar"
        shutil.move(str(path), str(dest))
        os.chmod(dest, 0o600)  # 実行権限を外す
        with self._lock:
            data = self._load()
            data[rec.id] = asdict(rec)
            self._save(data)
        return rec

    def list(self) -> list[Record]:
        with self._lock:
            return [Record(**v) for v in self._load().values()]

    def restore(self, record_id: str, force: bool = False) -> Path:
        with self._lock:
            data = self._load()
            if record_id not in data:
                raise QuarantineError(f"IDが見つかりません: {record_id}")
            rec = Record(**data[record_id])
            src = self.dir / f"{rec.id}.quar"
            dest = Path(rec.original_path)
            if not src.exists():
                raise QuarantineError("隔離ファイルの実体が見つかりません")
            if dest.exists() and not force:
                raise DestinationExists(f"復元先に同名ファイルがあります: {dest}")
            dest.parent.mkdir(parents=True, exist_ok=True)
            shutil.move(str(src), str(dest))
            del data[record_id]
            self._save(data)
            return dest
