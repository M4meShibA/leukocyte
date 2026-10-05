"""YARAルール(中身のパターン検知)を読み込んで、ファイルに当てる。

yara-python は任意の依存。入っていなくても他の機能は動く。
"""
from pathlib import Path

try:
    import yara
except ImportError:  # pragma: no cover
    yara = None

_DEFAULT = object()
RULE_SUFFIXES = {".yar", ".yara"}
MAX_IN_MEMORY = 64 * 1024 * 1024  # これ以下のファイルは中身を読んでYARAに渡す


class YaraUnavailable(Exception):
    """yara-python が入っていない。"""


class NoRulesFound(Exception):
    """ルールファイルが1つも見つからない。"""


class YaraRulesError(Exception):
    """ルールの文法エラーなどで読み込めない。"""


class YaraEngine:
    def __init__(self, rules_dir: Path, yara_module=_DEFAULT, timeout: int = 30):
        self._yara = yara if yara_module is _DEFAULT else yara_module
        if self._yara is None:
            raise YaraUnavailable("yara-python が見つかりません (pip install yara-python)")
        rules_dir = Path(rules_dir)
        files = sorted(
            p for p in rules_dir.rglob("*") if p.is_file() and p.suffix.lower() in RULE_SUFFIXES
        ) if rules_dir.is_dir() else []
        if not files:
            raise NoRulesFound(f"ルールファイルがありません: {rules_dir}")
        # ファイルごとに別の名前空間にして、ルール名が他のファイルと被っても衝突しないようにする
        sources = {f"r{i}_{p.stem}": str(p) for i, p in enumerate(files)}
        try:
            self._rules = self._yara.compile(filepaths=sources)
        except self._yara.Error as e:
            raise YaraRulesError(str(e)) from e
        self._timeout = timeout
        self.rule_files = files

    def match(self, path: Path) -> list[str]:
        """一致したルール名の一覧を返す(なければ空)。"""
        path = Path(path)
        try:
            small = path.stat().st_size <= MAX_IN_MEMORY
        except OSError:
            small = False
        if small:
            # パス名(日本語など)の扱いに左右されないよう、中身を読んで渡す
            matches = self._rules.match(data=path.read_bytes(), timeout=self._timeout)
        else:
            matches = self._rules.match(filepath=str(path), timeout=self._timeout)
        return [m.rule for m in matches]