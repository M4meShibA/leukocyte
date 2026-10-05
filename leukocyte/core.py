"""白血球の本体。設定・ハッシュDB・YARA・隔離・ログ・監視を1か所に配線する。

CLIもGUIも、このクラスを呼ぶだけ。機能を足すときもここを直せば両方に反映される。
"""
import threading
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable

from .config import Config
from .logger import get_logger
from .quarantine import Quarantine
from .scanner import Detection, ScanError, scan_dir
from .signatures import load_hashes
from .watcher import Watcher
from .yara_engine import NoRulesFound, YaraEngine, YaraUnavailable


@dataclass(frozen=True)
class Finding:
    detection: Detection
    record_id: str | None  # 隔離したときだけID


@dataclass
class ScanSummary:
    findings: list[Finding]
    scanned: int
    skipped: int  # 読めない・ルール照合に失敗するなどで「検査できなかった」ファイルの数(安全という意味ではない)
    cancelled: bool
    errors: list[ScanError] = field(default_factory=list)  # 検査できなかった理由の一覧


@dataclass(frozen=True)
class Status:
    signature_count: int
    yara_enabled: bool
    yara_rule_files: int
    quarantined: int
    warnings: tuple[str, ...]


class Leukocyte:
    def __init__(self, config: Config, engine_kwargs: dict | None = None):
        """engine_kwargs はYaraEngineへそのまま渡す(テストで偽のyaraを差し込むため)。

        YARAルールの文法エラー(YaraRulesError)だけは、そのまま例外として伝わる。
        """
        self._engine_kwargs = engine_kwargs or {}
        self._watcher: Watcher | None = None
        self._watch_path: Path | None = None
        self._build(config)

    def _build(self, config: Config) -> None:
        self.config = config
        self.warnings: list[str] = []
        self.log = get_logger(config.log_path)
        self.quarantine = Quarantine(config.quarantine_dir)

        if config.signatures_path.exists():
            self.known_bad = load_hashes(config.signatures_path)
        else:
            self.known_bad = set()
            self.warnings.append(f"ハッシュ一覧が見つかりません: {config.signatures_path}")

        self.engine = None
        if config.use_yara:
            try:
                self.engine = YaraEngine(config.rules_dir, **self._engine_kwargs)
            except (YaraUnavailable, NoRulesFound) as e:
                self.warnings.append(f"YARAは無効です: {e}")

    def reconfigure(self, config: Config) -> None:
        """設定を差し替える。監視中なら止める(新しい設定で開始し直してもらう)。

        新しい設定の読み込みに失敗(YARAルールの文法エラーなど)したら、元の状態のまま例外を投げる。
        """
        old = (self.config, self.warnings, self.log, self.quarantine, self.known_bad, self.engine)
        self.stop_watch()
        try:
            self._build(config)
        except Exception:
            self.config, self.warnings, self.log, self.quarantine, self.known_bad, self.engine = old
            raise

    # ---- スキャン ----
    def scan(
        self,
        target: Path,
        *,
        quarantine: bool | None = None,
        on_file: Callable[[Path], None] | None = None,
        on_finding: Callable[[Finding], None] | None = None,
        cancel: threading.Event | None = None,
    ) -> ScanSummary:
        """フォルダをスキャンする。quarantine=None なら設定の auto_quarantine に従う。

        パターンC対応: 高エントロピーのみの検知は自動隔離から外し、ユーザー確認対象(is_warning)とする。
        """
        target = Path(target)
        if not target.is_dir():
            raise NotADirectoryError(f"フォルダが見つかりません: {target}")
        do_quarantine = self.config.auto_quarantine if quarantine is None else quarantine
        self.log.info("スキャン開始: %s (YARA: %s)", target, "有効" if self.engine else "無効")

        scanned = skipped = 0
        errors: list[ScanError] = []

        def count(p: Path) -> None:
            nonlocal scanned
            scanned += 1
            if on_file:
                on_file(p)

        detections: list[Detection] = []
        for item in scan_dir(
            target, self.known_bad, exclude=(self.quarantine.dir,),
            engine=self.engine, on_file=count, cancel=cancel,
        ):
            if isinstance(item, Detection):
                detections.append(item)
                self.log.warning("検知: %s 理由=%s sha256=%s", item.path, ",".join(item.reasons), item.sha256)
            elif isinstance(item, ScanError):
                skipped += 1
                errors.append(item)
                self.log.info("検査できなかった: %s (%s)", item.path, item.reason)

        findings: list[Finding] = []
        for d in detections:
            record_id = None
            # 高エントロピーのみの判定かどうかを確認（英語・日本語両対応）
            is_entropy_only = len(d.reasons) == 1 and ("高エントロピー" in d.reasons[0] or d.reasons[0].startswith("high_entropy"))

            # 確定脅威（YARAやハッシュ一致）かつ自動隔離有効時のみ隔離
            if do_quarantine and not is_entropy_only:
                try:
                    if d.path.exists() and d.path.is_file() and not d.path.is_symlink():
                        record_id = self.quarantine.add(d.path, d.sha256).id
                        self.log.info("自動隔離: %s -> ID %s", d.path, record_id)
                    else:
                        self.log.warning("隔離対象がすでに失われているためスキップ: %s", d.path)
                except (OSError, ValueError) as e:
                    self.log.error("隔離に失敗: %s (%s)", d.path, e)

            finding = Finding(d, record_id)
            findings.append(finding)
            if on_finding:
                on_finding(finding)

        cancelled = bool(cancel and cancel.is_set())
        self.log.info("スキャン終了: 調べた %d / 検知 %d / 検査できず %d%s",
                      scanned, len(findings), skipped, " (中止)" if cancelled else "")
        return ScanSummary(findings, scanned, skipped, cancelled, errors)

    # ---- 単一ファイル手動隔離 ----
    def quarantine_file(self, file_path: Path, sha256_val: str = "") -> str:
        """GUIのユーザー判断等から呼び出し、単一ファイルを隔離する"""
        record = self.quarantine.add(file_path, sha256_val)
        self.log.info("手動隔離: %s -> ID %s", file_path, record.id)
        return record.id

    # ---- 監視 ----
    @property
    def watching(self) -> Path | None:
        return self._watch_path

    def start_watch(self, target: Path, on_detect: Callable[[Detection, str | None], None] | None = None) -> None:
        target = Path(target)
        if self._watcher is not None:
            raise RuntimeError("すでに監視中です")
        if not target.is_dir():
            raise NotADirectoryError(f"フォルダが見つかりません: {target}")
        
        # 監視側の自動隔離も、設定に応じて適用
        quarantine_target = self.quarantine if self.config.auto_quarantine else None
        
        w = Watcher(
            target, self.known_bad,
            quarantine_target,
            self.log,
            exclude=(self.quarantine.dir, self.config.log_path),
            on_detect=on_detect, engine=self.engine,
        )
        w.start()
        self._watcher, self._watch_path = w, target

    def stop_watch(self) -> None:
        if self._watcher is not None:
            self._watcher.stop()
            self._watcher = self._watch_path = None

    # ---- 隔離 ----
    def list_quarantine(self):
        return self.quarantine.list()

    def restore(self, record_id: str, force: bool = False) -> Path:
        dest = self.quarantine.restore(record_id, force=force)
        self.log.info("復元: ID %s -> %s", record_id, dest)
        return dest

    # ---- 状態 ----
    def status(self) -> Status:
        return Status(
            signature_count=len(self.known_bad),
            yara_enabled=self.engine is not None,
            yara_rule_files=len(self.engine.rule_files) if self.engine else 0,
            quarantined=len(self.quarantine.list()),
            warnings=tuple(self.warnings),
        )

    def close(self) -> None:
        self.stop_watch()