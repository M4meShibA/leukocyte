"""GUIの配線テスト。本物のtkinterの代わりに偽物を差し込むので、画面なしの環境でも動く。

見た目やレイアウトは確認できない。確認するのは「ボタンを押したときの処理の流れ」と
「結果が表(Treeview)に載ること」。
"""
import importlib
import sys
import tempfile
import time
import types
import unittest
from dataclasses import replace
from pathlib import Path
from unittest import mock

from leukocyte.config import default_config, load_config
from leukocyte.core import Leukocyte

EICAR = rb"X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"
EICAR_SHA = "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f"


class _Any:
    def __init__(self, *a, **k):
        self.opts = dict(k)

    def configure(self, **k):
        self.opts.update(k)

    def __getattr__(self, name):
        return _Any()

    def __call__(self, *a, **k):
        return _Any()


class _Tk(_Any):
    ALLOWED = {"title", "geometry", "minsize", "protocol", "after", "destroy", "mainloop", "withdraw"}

    def __getattr__(self, name):  # アプリ側のタイプミスを見逃さない
        if name in self.ALLOWED:
            return _Any()
        raise AttributeError(name)


class _Var:
    def __init__(self, value=None, **k):
        self._v = self.default if value is None else value

    def get(self):
        return self._v

    def set(self, v):
        self._v = v


class _StringVar(_Var):
    default = ""


class _BoolVar(_Var):
    default = False


class _Tree(_Any):
    def __init__(self, *a, **k):
        super().__init__(*a, **k)
        self.rows, self._sel = {}, ()

    def insert(self, parent, index, iid=None, values=(), **k):
        key = iid or f"I{len(self.rows)}"
        self.rows[key] = tuple(values)
        return key

    def delete(self, *items):
        for i in items:
            self.rows.pop(i, None)

    def get_children(self, *a):
        return tuple(self.rows)

    def selection(self):
        return self._sel


def load_gui_with_fake_tk():
    msgs = []
    tk = types.ModuleType("tkinter")
    tk.Tk, tk.StringVar, tk.BooleanVar = _Tk, _StringVar, _BoolVar
    ttk = types.ModuleType("tkinter.ttk")
    for n in ("Frame", "Label", "Button", "Entry", "Checkbutton", "Notebook", "Progressbar", "Scrollbar"):
        setattr(ttk, n, _Any)
    ttk.Treeview = _Tree
    mb = types.ModuleType("tkinter.messagebox")
    for n in ("showerror", "showinfo"):
        setattr(mb, n, lambda title, msg, _n=n: msgs.append((_n, msg)))
    mb.askyesno = lambda title, msg: True
    fd = types.ModuleType("tkinter.filedialog")
    fd.askdirectory = lambda **k: ""
    tk.ttk, tk.messagebox, tk.filedialog = ttk, mb, fd
    mods = {"tkinter": tk, "tkinter.ttk": ttk, "tkinter.messagebox": mb, "tkinter.filedialog": fd}
    sys.modules.pop("leukocyte.gui", None)
    with mock.patch.dict(sys.modules, mods):
        gui = importlib.import_module("leukocyte.gui")
    sys.modules.pop("leukocyte.gui", None)
    return gui, msgs


def wait_for(cond, timeout=8.0):
    end = time.monotonic() + timeout
    while time.monotonic() < end:
        if cond():
            return True
        time.sleep(0.05)
    return False


class GuiFlowTest(unittest.TestCase):
    def test_full_flow(self):
        gui, msgs = load_gui_with_fake_tk()
        with tempfile.TemporaryDirectory() as d:
            base = Path(d)
            cfg = default_config(base)
            cfg.signatures_path.parent.mkdir()
            cfg.signatures_path.write_text(EICAR_SHA + "\n")
            cfg = replace(cfg, use_yara=False)
            target = base / "target"
            target.mkdir()
            (target / "bad.com").write_bytes(EICAR)
            (target / "ok.txt").write_text("hi")
            config_path = base / "config.toml"

            app = gui.LeukocyteApp(Leukocyte(cfg), config_path)
            try:
                self.assertIn("ハッシュ 1 件", app.status_var.get())

                # フォルダ未指定のスキャンはエラー表示
                app.scan_target.set(str(base / "nope"))
                app.start_scan()
                self.assertEqual(msgs[-1][0], "showerror")

                # スキャン → 隔離
                app.scan_target.set(str(target))
                app.scan_quarantine.set(True)
                app.start_scan()
                self.assertEqual(app.btn_scan.opts["state"], "disabled")
                app.controller.join_scan(10)
                app.pump()
                self.assertEqual(len(app.scan_tree.rows), 1)
                self.assertIn("検知 1 件", app.scan_status.get())
                self.assertEqual(app.btn_scan.opts["state"], "normal")
                self.assertEqual(len(app.q_tree.rows), 1)
                self.assertFalse((target / "bad.com").exists())

                # 復元
                app.restore_selected()  # 未選択
                self.assertEqual(msgs[-1][0], "showinfo")
                app.q_tree._sel = (next(iter(app.q_tree.rows)),)
                app.restore_selected()
                self.assertTrue((target / "bad.com").exists())
                self.assertEqual(len(app.q_tree.rows), 0)

                # 設定の保存と適用
                app.set_auto_q.set(True)
                app.apply_settings()
                self.assertTrue(app.core.config.auto_quarantine)
                self.assertTrue(load_config(config_path).auto_quarantine)

                # 監視(自動隔離オン)
                app.watch_target.set(str(target))
                app.start_watch()
                self.assertIn("監視中", app.watch_state.get())
                time.sleep(0.3)
                (target / "dropped.bin").write_bytes(EICAR)
                self.assertTrue(wait_for(lambda: (app.pump() or True) and len(app.watch_tree.rows) >= 1))
                app.stop_watch()
                self.assertEqual(app.watch_state.get(), "停止中")
            finally:
                app._on_close()


if __name__ == "__main__":
    unittest.main()
