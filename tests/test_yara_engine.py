import tempfile
import unittest
from pathlib import Path

from leukocyte.scanner import Detection, ScanError, check_file, sha256_of
from leukocyte.yara_engine import NoRulesFound, YaraEngine, YaraRulesError, YaraUnavailable

try:
    import yara as real_yara
except ImportError:
    real_yara = None

EICAR = rb"X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"
RULE = 'rule T { strings: $a = "EICAR-STANDARD-ANTIVIRUS-TEST-FILE!" ascii condition: $a }\n'


class FakeYara:
    """yara-pythonの代わり。必要な部分だけ真似た偽物(インストール不要でロジックを試せる)。"""

    class Error(Exception):
        pass

    def __init__(self, names=("FakeRule",), compile_error=False):
        self.names, self.compile_error, self.sources = names, compile_error, None

    def compile(self, filepaths):
        if self.compile_error:
            raise self.Error("syntax error")
        self.sources = filepaths
        outer = self

        class Rules:
            def match(self, filepath, timeout):
                return [type("M", (), {"rule": n}) for n in outer.names]

        return Rules()


class BrokenEngine:
    def match(self, path):
        raise RuntimeError("boom")


class EngineLogicTest(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.d = Path(self._tmp.name)
        (self.d / "rules").mkdir()
        (self.d / "rules" / "a.yar").write_text(RULE)
        (self.d / "rules" / "ignore.txt").write_text("x")
        self.f = self.d / "f.bin"
        self.f.write_bytes(b"data")

    def tearDown(self):
        self._tmp.cleanup()

    def test_match_returns_rule_names(self):
        e = YaraEngine(self.d / "rules", yara_module=FakeYara(names=("A", "B")))
        self.assertEqual(e.match(self.f), ["A", "B"])
        self.assertEqual(len(e.rule_files), 1)  # .yar だけ読み込む

    def test_unavailable_when_module_missing(self):
        with self.assertRaises(YaraUnavailable):
            YaraEngine(self.d / "rules", yara_module=None)

    def test_no_rules(self):
        with self.assertRaises(NoRulesFound):
            YaraEngine(self.d / "missing", yara_module=FakeYara())

    def test_compile_error(self):
        with self.assertRaises(YaraRulesError):
            YaraEngine(self.d / "rules", yara_module=FakeYara(compile_error=True))

    def test_check_file_combines_hash_and_yara(self):
        e = YaraEngine(self.d / "rules", yara_module=FakeYara(names=("R1",)))
        det = check_file(self.f, {sha256_of(self.f)}, e)
        self.assertIsInstance(det, Detection)
        self.assertEqual(det.reasons, ("hash", "yara:R1"))

    def test_yara_only_detection(self):
        e = YaraEngine(self.d / "rules", yara_module=FakeYara(names=("R1",)))
        self.assertEqual(check_file(self.f, set(), e).reasons, ("yara:R1",))

    def test_engine_failure_does_not_hide_hash_match(self):
        det = check_file(self.f, {sha256_of(self.f)}, BrokenEngine())
        self.assertEqual(det.reasons, ("hash",))

    def test_engine_failure_without_match_is_scan_error(self):
        self.assertIsInstance(check_file(self.f, set(), BrokenEngine()), ScanError)

    def test_no_engine_no_match_is_none(self):
        self.assertIsNone(check_file(self.f, set(), None))


@unittest.skipUnless(real_yara, "yara-python が入っている環境でのみ実行")
class RealYaraTest(unittest.TestCase):
    def test_variant_missed_by_hash_is_caught_by_yara(self):
        with tempfile.TemporaryDirectory() as d:
            d = Path(d)
            (d / "rules").mkdir()
            (d / "rules" / "t.yar").write_text(RULE)
            variant = d / "variant.bin"
            variant.write_bytes(EICAR + b"\r\n\r\n  extra padding")  # ハッシュは変わる
            engine = YaraEngine(d / "rules")
            det = check_file(variant, {"0" * 64}, engine)  # ハッシュ一覧には載っていない
            self.assertEqual(det.reasons, ("yara:T",))

    def test_bundled_sample_rule_compiles(self):
        rules = Path(__file__).resolve().parent.parent / "rules"
        self.assertGreaterEqual(len(YaraEngine(rules).rule_files), 1)


if __name__ == "__main__":
    unittest.main()
