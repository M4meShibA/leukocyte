"""検知や隔離の履歴をファイル(と画面)に残す。"""
import logging
from pathlib import Path


def get_logger(log_path: Path, name: str = "leukocyte") -> logging.Logger:
    logger = logging.getLogger(name)
    logger.setLevel(logging.INFO)
    log_path = Path(log_path)
    log_path.parent.mkdir(parents=True, exist_ok=True)
    # 同じファイルへのハンドラーを二重に付けない(ログが2行ずつ出るのを防ぐ)
    target = str(log_path.resolve())
    if not any(getattr(h, "baseFilename", None) == target for h in logger.handlers):
        h = logging.FileHandler(log_path, encoding="utf-8")
        h.setFormatter(logging.Formatter("%(asctime)s [%(levelname)s] %(message)s"))
        logger.addHandler(h)
    return logger
