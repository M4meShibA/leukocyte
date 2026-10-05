import tempfile
import unittest
from pathlib import Path

from leukocyte.quarantine import Quarantine, QuarantineError
from leukocyte.scanner import Detection, scan_dir


class QuarantineTest(unittest.TestCase):
    def test_roundtrip(self):
        with tempfile.TemporaryDirectory() as d:
            d = Path(d)
            f = d / "target" / "bad.txt"
            f.parent.mkdir()
            f.write_text("payload")
            q = Quarantine(d / "q")
            rec = q.add(f, "a" * 64)
            self.assertFalse(f.exists())
            self.assertEqual(len(q.list()), 1)
            self.assertEqual(q.restore(rec.id), f.resolve())
            self.assertEqual(f.read_text(), "payload")
            self.assertEqual(q.list(), [])

    def test_restore_refuses_overwrite(self):
        with tempfile.TemporaryDirectory() as d:
            d = Path(d)
            f = d / "bad.txt"
            f.write_text("old")
            q = Quarantine(d / "q")
            rec = q.add(f, "a" * 64)
            f.write_text("new")  # 同じ場所に別ファイルができた
            with self.assertRaises(QuarantineError):
                q.restore(rec.id)
            self.assertEqual(f.read_text(), "new")
            q.restore(rec.id, force=True)
            self.assertEqual(f.read_text(), "old")

    def test_unknown_id(self):
        with tempfile.TemporaryDirectory() as d:
            with self.assertRaises(QuarantineError):
                Quarantine(Path(d) / "q").restore("nope")

    def test_scan_skips_excluded_dir(self):
        with tempfile.TemporaryDirectory() as d:
            d = Path(d)
            (d / "q").mkdir()
            (d / "q" / "x.quar").write_text("same")
            (d / "y.txt").write_text("same")
            from leukocyte.scanner import sha256_of
            bad = {sha256_of(d / "y.txt")}
            hits = [r for r in scan_dir(d, bad, exclude=(d / "q",)) if isinstance(r, Detection)]
            self.assertEqual([h.path.name for h in hits], ["y.txt"])


if __name__ == "__main__":
    unittest.main()


class QuarantineConcurrencyTest(unittest.TestCase):
    def test_parallel_adds_keep_every_record(self):
        import threading

        with tempfile.TemporaryDirectory() as d:
            d = Path(d)
            q = Quarantine(d / "q")
            files = []
            for i in range(40):
                f = d / f"f{i}.txt"
                f.write_text(str(i))
                files.append(f)
            threads = [threading.Thread(target=q.add, args=(f, "a" * 64)) for f in files]
            for t in threads:
                t.start()
            for t in threads:
                t.join()
            self.assertEqual(len(q.list()), 40)  # 索引の更新が1件も消えていない

    def test_entropy_threshold_ignores_small_files(self):
        from leukocyte.scanner import check_file, sha256_of

        with tempfile.TemporaryDirectory() as d:
            d = Path(d)
            p = d / "tiny.bin"
            p.write_bytes(b"\x00\x01\x02\x03\x04\x05\x06\x07")
            result = check_file(p, set(), entropy_threshold=7.8)
            self.assertIsNone(result)

            p2 = d / "big.dat"
            payload = (b"\x00\x11\x22\x33\x44\x55\x66\x77" * 4096)
            p2.write_bytes(payload)
            result2 = check_file(p2, set(), entropy_threshold=7.8)
            self.assertIsNone(result2)
