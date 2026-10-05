// YARAルールの見本。ファイルの「中身のパターン」で検知する。
// ハッシュ照合は1バイト違うだけで見逃すが、YARAなら一部が変わっていても検知できる。

rule EICAR_Test_File
{
    meta:
        description = "EICAR standard antivirus test file (harmless)"
    strings:
        $eicar = "EICAR-STANDARD-ANTIVIRUS-TEST-FILE!" ascii
    condition:
        $eicar
}
