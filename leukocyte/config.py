"""設定(config.toml)の読み書き。相対パスは設定ファイルのあるフォルダ基準。"""
import json
import tomllib
from dataclasses import dataclass
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
DEFAULT_CONFIG_PATH = ROOT / "config.toml"


class ConfigError(Exception):
    pass


@dataclass(frozen=True)
class Config:
    base_dir: Path
    signatures_path: Path
    rules_dir: Path
    quarantine_dir: Path
    log_path: Path
    auto_quarantine: bool = False  # 検知したら自動で隔離するか
    use_yara: bool = True


def default_config(base_dir: Path = ROOT) -> Config:
    base = Path(base_dir).resolve()
    return Config(
        base_dir=base,
        signatures_path=base / "signatures" / "hashes.txt",
        rules_dir=base / "rules",
        quarantine_dir=base / "quarantine",
        log_path=base / "scan.log",
    )


def load_config(path: Path | None = None) -> Config:
    path = Path(path) if path else DEFAULT_CONFIG_PATH
    cfg = default_config(path.resolve().parent)
    if not path.exists():
        return cfg
    try:
        data = tomllib.loads(path.read_text(encoding="utf-8"))
    except (tomllib.TOMLDecodeError, OSError) as e:
        raise ConfigError(f"設定ファイルを読めません: {path} ({e})") from e

    paths, behavior = data.get("paths", {}), data.get("behavior", {})

    def pick_path(key: str, current: Path) -> Path:
        value = paths.get(key)
        if value is None:
            return current
        if not isinstance(value, str):
            raise ConfigError(f"[paths] {key} は文字列で指定してください")
        p = Path(value).expanduser()
        return p if p.is_absolute() else cfg.base_dir / p

    def pick_bool(key: str, current: bool) -> bool:
        value = behavior.get(key, current)
        if not isinstance(value, bool):
            raise ConfigError(f"[behavior] {key} は true / false で指定してください")
        return value

    return Config(
        base_dir=cfg.base_dir,
        signatures_path=pick_path("signatures", cfg.signatures_path),
        rules_dir=pick_path("rules", cfg.rules_dir),
        quarantine_dir=pick_path("quarantine", cfg.quarantine_dir),
        log_path=pick_path("log", cfg.log_path),
        auto_quarantine=pick_bool("auto_quarantine", cfg.auto_quarantine),
        use_yara=pick_bool("use_yara", cfg.use_yara),
    )


def _fmt_path(p: Path, base: Path) -> str:
    try:
        p = p.relative_to(base)
    except ValueError:
        pass
    return json.dumps(p.as_posix(), ensure_ascii=False)  # TOMLの文字列としてそのまま使える


def save_config(cfg: Config, path: Path | None = None) -> None:
    path = Path(path) if path else DEFAULT_CONFIG_PATH
    b = cfg.base_dir
    text = (
        "# 白血球 (Leukocyte) の設定\n"
        "# 相対パスは、このファイルがあるフォルダが基準です。\n\n"
        "[paths]\n"
        f"signatures = {_fmt_path(cfg.signatures_path, b)}  # 不正ハッシュの一覧\n"
        f"rules = {_fmt_path(cfg.rules_dir, b)}  # YARAルールのフォルダ\n"
        f"quarantine = {_fmt_path(cfg.quarantine_dir, b)}  # 隔離フォルダ\n"
        f"log = {_fmt_path(cfg.log_path, b)}  # ログファイル\n\n"
        "[behavior]\n"
        f"auto_quarantine = {str(cfg.auto_quarantine).lower()}  # 検知したら自動で隔離する\n"
        f"use_yara = {str(cfg.use_yara).lower()}  # YARAルールを使う(yara-pythonが必要)\n"
    )
    tmp = path.with_suffix(".tmp")
    tmp.write_text(text, encoding="utf-8")
    tmp.replace(path)  # 途中で止まっても壊れた設定を残さない
