rule Suspicious_Script_And_Commands
{
    meta:
        description = "不審なコマンド実行や難読化スクリプトを広く捕捉するルール"
        author = "Leukocyte Security Team"
    strings:
        // PowerShellのセキュリティ回避・暗号化実行
        $ps1 = "powershell" nocase
        $ps2 = "-ExecutionPolicy Bypass" nocase
        $ps3 = "-EncodedCommand" nocase
        $ps4 = "-WindowStyle Hidden" nocase

        // 外部からのファイルダウンロード処理
        $net1 = "Net.WebClient" nocase
        $net2 = "DownloadFile" nocase
        $net3 = "Invoke-WebRequest" nocase
        $net4 = "curl" nocase
        $net5 = "wget" nocase

        // システム操作・不審なプロセス起動
        $sys1 = "WScript.Shell" nocase
        $sys2 = "cmd.exe /c" nocase
        $sys3 = "RegAdd" nocase
        
        // ランサムウェアがバックアップ・復元機能を破壊する定番コマンド群
        $sys4_1 = "vssadmin" nocase
        $sys4_2 = "delete shadows" nocase
        $sys5 = "wbadmin delete catalog" nocase
        $sys6 = "bcdedit" nocase
        $sys7 = "recoveryenabled No" nocase

    condition:
        // パワーセルの不審な実行、外部通信とコマンドの組み合わせなどを検知
        (2 of ($ps*)) or
        (any of ($net*) and any of ($sys*)) or
        ($sys4_1 and $sys4_2) or
        $sys5 or
        ($sys6 and $sys7)
}

rule Suspicious_Executable_Structures
{
    meta:
        description = "パッカー(UPX等)で固められた実行ファイルの特徴"
    strings:
        $upx1 = "UPX0"
        $upx2 = "UPX1"
        $upx3 = "UPX!"
    condition:
        2 of ($upx*)
}