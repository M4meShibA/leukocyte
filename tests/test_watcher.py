import logging
import tempfile
import time
import unittest
from pathlib import Path

from leukocyte.quarantine import Quarantine
from leukocyte.signatures import load_hashes
from leukocyte.watcher import Watcher, wait_until_stable

EICAR = rb"X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"
DB = Path(__file__).resolve().parent.parent / "signatures" / "hashes.txt"
LOG = logging.getLogger("test-watcher")


def wait_for(cond, timeout=8.0):
    end = time.monotonic() + timeout
    while time.monotonic() < end:
        if cond():
            return True
        time.sleep(0.05)
    return False


class WatcherTest(unittest.TestCase):
    def test_wait_until_stable(self):
        with tempfile.TemporaryDirectory() as d:
            f = Path(d) / "a.txt"
            f.write_text("x")
            self.assertTrue(wait_until_stable(f, interval=0.05))
            self.assertFalse(wait_until_stable(Path(d) / "missing", interval=0.05))

    def test_watch_detects_and_quarantines_new_file(self):
        with tempfile.TemporaryDirectory() as d:
            d = Path(d)
            target = d / "watched"
            target.mkdir()
            q = Quarantine(d / "q")
            hits = []
            w = Watcher(target, load_hashes(DB), q, LOG, exclude=(q.dir,),
                        on_detect=lambda det, rid: hits.append((det, rid)), stable_interval=0.05)
            w.start()
            try:
                time.sleep(0.3)
                (target / "clean.txt").write_text("hello")
                (target / "dropped.bin").write_bytes(EICAR)
                self.assertTrue(wait_for(lambda: hits), "検知されなかった")
                time.sleep(0.5)
            finally:
                w.stop()
            self.assertEqual(len(hits), 1)  # 同じファイルを二重に検知しない
            self.assertFalse((target / "dropped.bin").exists())
            self.assertTrue((target / "clean.txt").exists())
            self.assertEqual(len(q.list()), 1)

    def test_report_only_mode_keeps_file(self):
        with tempfile.TemporaryDirectory() as d:
            target = Path(d)
            hits = []
            w = Watcher(target, load_hashes(DB), None, LOG,
                        on_detect=lambda det, rid: hits.append(rid), stable_interval=0.05)
            w.start()
            try:
                time.sleep(0.3)
                (target / "x.bin").write_bytes(EICAR)
                self.assertTrue(wait_for(lambda: hits))
            finally:
                w.stop()
            self.assertEqual(hits, [None])
            self.assertTrue((target / "x.bin").exists())


if __name__ == "__main__":
    unittest.main()
