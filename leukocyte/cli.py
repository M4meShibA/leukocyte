import argparse
import sys
import time
from dataclasses import replace
from pathlib import Path

from .config import ConfigError, DEFAULT_CONFIG_PATH, load_config
from .core import Finding, Leukocyte
from .quarantine import QuarantineError
from .yara_engine import YaraRulesError


def add_detection_options(p: argparse.ArgumentParser) -> None:
    p.add_argument("target", type=Path)
    p.add_argument("--db", type=Path, help="不正ハッシュの一覧(設定を上書き)")
    p.add_argument("--rules", type=Path, help="YARAルールのフォルダ(設定を上書き)")
    p.add_argument("--no-yara", action="store_true", help="YARAを使わない(ハッシュ照合のみ)")
    p.add_argument("--quarantine", action="store_true", help="検知したファイルを隔離する(設定を上書き)")


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="leukocyte", description="白血球: 学習用の軽量スキャナー(引数なしでGUIが開きます)")
    p.add_argument("--config", type=Path, default=DEFAULT_CONFIG_PATH, help="設定ファイル(config.toml)")
    p.add_argument("--quarantine-dir", type=Path, help="隔離フォルダ(設定を上書き)")
    p.add_argument("--log", type=Path, help="ログファイル(設定を上書き)")
    sub = p.add_subparsers(dest="cmd")

    add_detection_options(sub.add_parser("scan", help="フォルダをスキャンする"))
    add_detection_options(sub.add_parser("watch", help="フォルダを見張り、新しいファイルを自動でスキャンする"))
    sub.add_parser("list", help="隔離中のファイルを一覧表示する")
    sub.add_parser("status", help="現在の設定と状態を表示する")
    sub.add_parser("gui", help="GUIを開く")

    r = sub.add_parser("restore", help="隔離したファイルを元に戻す")
    r.add_argument("id")
    r.add_argument("--force", action="store_true", help="復元先に同名ファイルがあっても上書きする")
    return p


def config_from_args(args):
    """config.toml を読み、コマンドラインで指定された項目だけ上書きする。"""
    cfg = load_config(args.config)
    over = {}
    if args.quarantine_dir:
        over["quarantine_dir"] = args.quarantine_dir.resolve()
    if args.log:
        over["log_path"] = args.log.resolve()
    if getattr(args, "db", None):
        over["signatures_path"] = args.db.resolve()
    if getattr(args, "rules", None):
        over["rules_dir"] = args.rules.resolve()
    if getattr(args, "no_yara", False):
        over["use_yara"] = False
    if getattr(args, "quarantine", False):
        over["auto_quarantine"] = True
    return replace(cfg, **over)


def describe(f: Finding) -> str:
    d = f.detection
    msg = f"[検知] {d.path}  理由={', '.join(d.reasons)}  sha256={d.sha256[:16]}..."
    if f.record_id:
        msg += f"  -> 隔離 (ID: {f.record_id})"
    return msg


def print_warnings(core: Leukocyte) -> None:
    for w in core.warnings:
        print(f"[注意] {w}", file=sys.stderr)


def cmd_scan(args, core: Leukocyte) -> int:
    try:
        summary = core.scan(args.target)
    except NotADirectoryError as e:
        print(e, file=sys.stderr)
        return 2
    for f in summary.findings:
        print(describe(f))
    print(f"完了: 検知 {len(summary.findings)} 件 / 読めなかったファイル {summary.skipped} 件")
    return 1 if summary.findings else 0


def cmd_watch(args, core: Leukocyte) -> int:
    def report(d, record_id):
        print(describe(Finding(d, record_id)), flush=True)

    try:
        core.start_watch(args.target, on_detect=report)
    except NotADirectoryError as e:
        print(e, file=sys.stderr)
        return 2
    print(f"監視中: {args.target}  (Ctrl+C で終了)", flush=True)
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        pass
    finally:
        core.stop_watch()
    print("監視を終了しました")
    return 0


def cmd_status(core: Leukocyte) -> int:
    c, s = core.config, core.status()
    print(f"ハッシュ一覧 : {c.signatures_path}  ({s.signature_count} 件)")
    print(f"YARA         : {'有効' if s.yara_enabled else '無効'}  (ルールファイル {s.yara_rule_files} 個, {c.rules_dir})")
    print(f"隔離フォルダ : {c.quarantine_dir}  (隔離中 {s.quarantined} 件)")
    print(f"ログ         : {c.log_path}")
    print(f"自動隔離     : {'オン' if c.auto_quarantine else 'オフ'}")
    return 0


def main(argv=None) -> int:
    args = build_parser().parse_args(argv)
    if args.cmd in (None, "gui"):
        from .gui import main as gui_main  # tkinterはGUIのときだけ読み込む
        return gui_main(args.config)

    try:
        core = Leukocyte(config_from_args(args))
    except ConfigError as e:
        print(e, file=sys.stderr)
        return 2
    except YaraRulesError as e:
        print(f"YARAルールにエラーがあります: {e}", file=sys.stderr)
        return 2

    try:
        if args.cmd in ("scan", "watch", "status"):
            print_warnings(core)
        if args.cmd == "scan":
            return cmd_scan(args, core)
        if args.cmd == "watch":
            return cmd_watch(args, core)
        if args.cmd == "status":
            return cmd_status(core)
        if args.cmd == "list":
            recs = core.list_quarantine()
            for r in recs:
                print(f"{r.id}  {r.quarantined_at}  {r.original_path}")
            if not recs:
                print("隔離中のファイルはありません")
            return 0
        if args.cmd == "restore":
            try:
                dest = core.restore(args.id, force=args.force)
            except QuarantineError as e:
                print(f"復元できません: {e}", file=sys.stderr)
                return 2
            print(f"復元しました: {dest}")
            return 0
        return 0
    finally:
        core.close()


if __name__ == "__main__":
    sys.exit(main())
