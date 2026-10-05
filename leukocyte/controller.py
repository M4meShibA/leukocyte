"""GUIの裏方。重い処理を別スレッドで動かし、結果をキューで画面側へ渡す。

画面(tkinter)はこのクラスを呼んで、drain() で届いた出来事を描画するだけ。
スレッドから直接ウィジェットを触ると壊れるので、必ずキュー経由にする。
"""
import queue
import threading
import time
from pathlib import Path

from .core import Leukocyte


class Controller:
    def __init__(self, core: Leukocyte):
        self.core = core
        self.events: queue.Queue[tuple] = queue.Queue()
        self.progress: tuple[int, str] = (0, "")  # (調べた数, 今のファイル)
        self._thread: threading.Thread | None = None
        self._cancel: threading.Event | None = None

    @property
    def scanning(self) -> bool:
        return self._thread is not None and self._thread.is_alive()

    def start_scan(self, target: Path, quarantine: bool) -> None:
        if self.scanning:
            raise RuntimeError("スキャン中です")
        self._cancel = threading.Event()
        self.progress = (0, "")
        self._thread = threading.Thread(
            target=self._scan_worker, args=(Path(target), quarantine, self._cancel), daemon=True
        )
        self._thread.start()

    def _scan_worker(self, target: Path, quarantine: bool, cancel: threading.Event) -> None:
        count = 0

        def on_file(p: Path) -> None:
            nonlocal count
            count += 1
            self.progress = (count, str(p))  # 1ファイルごとにキューへ積むと詰まるので、最新値だけ置く

        try:
            summary = self.core.scan(target, quarantine=quarantine, on_file=on_file, cancel=cancel)
            self.events.put(("scan_done", summary))
        except Exception as e:
            self.events.put(("scan_error", str(e)))

    def cancel_scan(self) -> None:
        if self._cancel is not None:
            self._cancel.set()

    def join_scan(self, timeout: float | None = None) -> None:
        if self._thread is not None:
            self._thread.join(timeout)

    def start_watch(self, target: Path) -> None:
        self.core.start_watch(
            target,
            on_detect=lambda d, rid: self.events.put(("watch_detect", d, rid, time.strftime("%H:%M:%S"))),
        )

    def stop_watch(self) -> None:
        self.core.stop_watch()

    def drain(self) -> list[tuple]:
        out = []
        while True:
            try:
                out.append(self.events.get_nowait())
            except queue.Empty:
                return out

    def shutdown(self) -> None:
        self.cancel_scan()
        self.join_scan(2)
        self.core.close()
