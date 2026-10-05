import tempfile
import unittest
from pathlib import Path

from leukocyte.scanner import Detection, scan_dir, sha256_of
from leukocyte.signatures import load_hashes

# アンチウイルスの動作確認用に世界共通で使われる、無害なテスト文字列
EICAR = rb"X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"
DB = Path(__file__).resolve().parent.parent / "signatures" / "hashes.txt"


class ScannerTest(unittest.TestCase):
    def test_detects_eicar_and_ignores_clean(self):
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            (root / "sub").mkdir()
            (root / "sub" / "eicar.txt").write_bytes(EICAR)
            (root / "hello.txt").write_text("こんにちは")
            hits = [r for r in scan_dir(root, load_hashes(DB)) if isinstance(r, Detection)]
            self.assertEqual([h.path.name for h in hits], ["eicar.txt"])
            self.assertEqual(hits[0].sha256, sha256_of(root / "sub" / "eicar.txt"))

    def test_bad_lines_in_db_are_ignored(self):
        with tempfile.TemporaryDirectory() as d:
            db = Path(d) / "h.txt"
            db.write_text("# comment\nnot-a-hash\n" + "a" * 64 + "\n")
            self.assertEqual(load_hashes(db), {"a" * 64})


if __name__ == "__main__":
    unittest.main()
