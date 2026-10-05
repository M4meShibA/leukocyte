import tempfile
import threading
import unittest
from dataclasses import replace
from pathlib import Path

from leukocyte.config import ConfigError, default_config, load_config, save_config
from leukocyte.controller import Controller
from leukocyte.core import Leukocyte
from leukocyte.yara_engine import YaraRulesError

EICAR = rb"X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"
EICAR_SHA = "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f"


class BrokenYara:
    class Error(Exception):
        pass

    def compile(self, filepaths):
        raise self.Error("bad rule")


def make_env(tmp: Path, **over):
    cfg = default_config(tmp)
    cfg.signatures_path.parent.mkdir(parents=True)
    cfg.signatures_path.write_text(f"{EICAR_SHA}  # eicar\n", encoding="utf-8")
    cfg = replace(cfg, use_yara=False, **over)
    target = tmp / "target"
    (target / "sub").mkdir(parents=True)
    (target / "sub" / "bad.com").write_bytes(EICAR)
    (target / "ok.txt").write_text("hello")
    return cfg, target


class ConfigTest(unittest.TestCase):
    def test_missing_file_gives_defaults(self):
        with tempfile.TemporaryDirectory() as d:
            cfg = load_config(Path(d) / "none.toml")
            self.assertEqual(cfg.quarantine_dir, Path(d).resolve() / "quarantine")
            self.assertFalse(cfg.auto_quarantine)

    def test_roundtrip_and_relative_paths(self):
        with tempfile.TemporaryDirectory() as d:
            path = Path(d) / "config.toml"
            cfg = replace(default_config(Path(d)), auto_quarantine=True, use_yara=False)
            save_config(cfg, path)
            self.assertIn('"quarantine"', path.read_text(encoding="utf-8"))  # 相対で保存される
            self.assertEqual(load_config(path), cfg)

    def test_invalid_values(self):
        with tempfile.TemporaryDirectory() as d:
            path = Path(d) / "c.toml"
            path.write_text("[behavior]\nauto_quarantine = 'yes'\n", encoding="utf-8")
            with self.assertRaises(ConfigError):
                load_config(path)
            path.write_text("this is not toml", encoding="utf-8")
            with self.assertRaises(ConfigError):
                load_config(path)


class CoreTest(unittest.TestCase):
    def test_scan_with_and_without_quarantine(self):
        with tempfile.TemporaryDirectory() as d:
            cfg, target = make_env(Path(d))
            core = Leukocyte(cfg)
            s = core.scan(target)  # 設定どおり(自動隔離オフ)
            self.assertEqual((len(s.findings), s.scanned), (1, 2))
            self.assertIsNone(s.findings[0].record_id)
            self.assertTrue((target / "sub" / "bad.com").exists())
            s = core.scan(target, quarantine=True)
            self.assertIsNotNone(s.findings[0].record_id)
            self.assertFalse((target / "sub" / "bad.com").exists())
            self.assertEqual(core.status().quarantined, 1)
            core.restore(s.findings[0].record_id)
            self.assertTrue((target / "sub" / "bad.com").exists())

    def test_auto_quarantine_setting_is_used(self):
        with tempfile.TemporaryDirectory() as d:
            cfg, target = make_env(Path(d), auto_quarantine=True)
            s = Leukocyte(cfg).scan(target)
            self.assertIsNotNone(s.findings[0].record_id)

    def test_cancel(self):
        with tempfile.TemporaryDirectory() as d:
            cfg, target = make_env(Path(d))
            ev = threading.Event()
            ev.set()
            s = Leukocyte(cfg).scan(target, cancel=ev)
            self.assertTrue(s.cancelled)
            self.assertEqual(s.scanned, 0)

    def test_missing_signature_file_warns_but_works(self):
        with tempfile.TemporaryDirectory() as d:
            cfg = replace(default_config(Path(d)), use_yara=False)
            core = Leukocyte(cfg)
            self.assertEqual(len(core.warnings), 1)
            self.assertEqual(core.status().signature_count, 0)

    def test_scan_missing_folder(self):
        with tempfile.TemporaryDirectory() as d:
            cfg, _ = make_env(Path(d))
            with self.assertRaises(NotADirectoryError):
                Leukocyte(cfg).scan(Path(d) / "nope")

    def test_reconfigure_failure_keeps_old_state(self):
        with tempfile.TemporaryDirectory() as d:
            cfg, _ = make_env(Path(d))
            cfg.rules_dir.mkdir()
            (cfg.rules_dir / "x.yar").write_text("rule x { condition: true }")
            core = Leukocyte(cfg, engine_kwargs={"yara_module": BrokenYara()})
            self.assertFalse(core.status().yara_enabled)  # 最初はuse_yara=False
            with self.assertRaises(YaraRulesError):
                core.reconfigure(replace(cfg, use_yara=True))
            self.assertFalse(core.config.use_yara)  # 元の設定のまま


class ControllerTest(unittest.TestCase):
    def test_scan_in_background(self):
        with tempfile.TemporaryDirectory() as d:
            cfg, target = make_env(Path(d))
            c = Controller(Leukocyte(cfg))
            c.start_scan(target, quarantine=True)
            c.join_scan(10)
            events = c.drain()
            self.assertEqual([e[0] for e in events], ["scan_done"])
            self.assertEqual(len(events[0][1].findings), 1)
            self.assertGreaterEqual(c.progress[0], 2)

    def test_scan_error_event(self):
        with tempfile.TemporaryDirectory() as d:
            cfg, _ = make_env(Path(d))
            c = Controller(Leukocyte(cfg))
            c.start_scan(Path(d) / "nope", quarantine=False)
            c.join_scan(10)
            self.assertEqual([e[0] for e in c.drain()], ["scan_error"])


if __name__ == "__main__":
    unittest.main()
