"""フォルダを見張り、新しく入ってきたファイルを自動でスキャンする(常駐監視)。

流れ: watchdogがイベントを受ける -> キューに積む -> 作業スレッドが
「書き込みが終わるまで待つ」-> ハッシュ照合 -> (任意で)隔離。
イベントを受ける側は軽く保ち、重い処理は作業スレッドに任せる。
"""
import queue
import threading
import time
from pathlib import Path
from typing import Callable

from watchdog.events import FileSystemEventHandler
from watchdog.observers import Observer

from .quarantine import Quarantine
from .scanner import Detection, ScanError, check_file


def wait_until_stable(path: Path, interval: float = 0.5, checks: int = 2, timeout: float = 30.0) -> bool:
    """サイズと更新時刻が checks 回連続で変わらなければ「書き込み完了」とみなす。"""
    deadline = time.monotonic() + timeout
    last, stable = None, 0
    while time.monotonic() < deadline:
        try:
            st = path.stat()
        except OSError:
            return False  # 消えた
        state = (st.st_size, st.st_mtime_ns)
        stable = stable + 1 if state == last else 0
        if stable >= checks:
            return True
        last = state
        time.sleep(interval)
    return False


class _Handler(FileSystemEventHandler):
    def __init__(self, submit: Callable[[Path], None]):
        self.submit = submit

    def on_created(self, event):
        if not event.is_directory:
            self.submit(Path(event.src_path))

    def on_modified(self, event):
        if not event.is_directory:
            self.submit(Path(event.src_path))

    def on_moved(self, event):
        if not event.is_directory:
            self.submit(Path(event.dest_path))


class Watcher:
    def __init__(
        self,
        target: Path,
        known_bad: set[str],
        quarantine: Quarantine | None,
        log,
        exclude: tuple[Path, ...] = (),
        on_detect: Callable[[Detection, str | None], None] | None = None,
        stable_interval: float = 0.5,
        engine=None,
    ):
        self.target = Path(target).resolve()
        self.known_bad = known_bad
        self.quarantine = quarantine  # None なら検知の報告だけ
        self.log = log
        self.exclude = tuple(Path(e).resolve() for e in exclude)
        self.on_detect = on_detect
        self.stable_interval = stable_interval
        self.engine = engine  # YARAなどのルールエンジン(なければNone)
        self._queue: queue.Queue[Path] = queue.Queue()
        self._pending: set[Path] = set()
        self._reported: dict[Path, tuple[int, int]] = {}  # 報告済みファイルの(サイズ, 更新時刻)
        self._lock = threading.Lock()
        self._stop = threading.Event()
        self._observer = Observer()
        self._worker = threading.Thread(target=self._run, daemon=True)

    def _excluded(self, p: Path) -> bool:
        return any(e == p or e in p.parents for e in self.exclude)

    def _submit(self, path: Path) -> None:
        path = path.resolve()
        if self._excluded(path):
            return
        with self._lock:
            if path in self._pending:  # 同じファイルの連続イベントは1回にまとめる
                return
            self._pending.add(path)
        self._queue.put(path)

    def handle(self, path: Path) -> Detection | None:
        """1ファイルを調べて、必要なら隔離する。検知したらDetectionを返す。"""
        if not wait_until_stable(path, interval=self.stable_interval):
            self.log.info("書き込み完了を確認できず見送り: %s", path)
            return None
        try:
            st = path.stat()
        except OSError:
            return None
        state = (st.st_size, st.st_mtime_ns)
        if self._reported.get(path) == state:
            return None  # 報告済みで中身も変わっていない(報告のみモードでの二重通知を防ぐ)
        result = check_file(path, self.known_bad, self.engine)
        if isinstance(result, ScanError):
            self.log.info("読めなかった: %s (%s)", result.path, result.reason)
            return None
        if result is None:
            return None
        self._reported[path] = state
        self.log.warning("検知: %s 理由=%s sha256=%s", result.path, ",".join(result.reasons), result.sha256)

        record_id = None

        # 高エントロピーのみの場合は誤検知の可能性があるため自動隔離を行わない（日本語・英語両対応）
        is_only_high_entropy = len(result.reasons) == 1 and (
            "高エントロピー" in result.reasons[0] or result.reasons[0].startswith("high_entropy")
        )

        if self.quarantine is not None and not is_only_high_entropy:
            try:
                if result.path.exists() and result.path.is_file() and not result.path.is_symlink():
                    record_id = self.quarantine.add(result.path, result.sha256).id
                    self.log.info("隔離: %s -> ID %s", result.path, record_id)
                else:
                    self.log.warning("隔離対象がすでに失われているためスキップ: %s", result.path)
            except (OSError, ValueError) as exc:
                self.log.error("隔離に失敗: %s (%s)", result.path, exc)

        if self.on_detect:
            self.on_detect(result, record_id)
        return result

    def _run(self) -> None:
        while not self._stop.is_set():
            try:
                path = self._queue.get(timeout=0.2)
            except queue.Empty:
                continue
            with self._lock:
                self._pending.discard(path)  # 処理開始後の変更は、また新しいイベントとして拾う
            try:
                self.handle(path)
            except Exception:
                self.log.exception("監視中にエラー: %s", path)  # 1件の失敗で監視を止めない

    def start(self) -> None:
        self._observer.schedule(_Handler(self._submit), str(self.target), recursive=True)
        self._observer.start()
        self._worker.start()
        self.log.info("監視開始: %s", self.target)

    def stop(self) -> None:
        self._stop.set()
        self._observer.stop()
        self._observer.join()
        self._worker.join(timeout=2)
        self.log.info("監視終了: %s", self.target)