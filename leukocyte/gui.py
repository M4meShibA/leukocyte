"""Leukocyte GUI - 日本語完全対応版フロントエンド（パターンC確認ダイアログ・手動隔離・オリジナルアイコン・完全削除機能対応）

機能:
1. Tkinter UI の日本語フォント設定（文字化け・崩れ防止）
2. ReportLab による日本語対応 PDF 診断レポート出力（MS ゴシック登録）
3. Windows トースト通知機能 (plyer)
4. YARAルールの追加・管理機能
5. パターンC対応：高エントロピー検出時の確認ポップアップおよび手動隔離アクション
6. アプリケーションアイコン（.ico）の動的読み込み＆タスクバー・ウィンドウ枠表示
7. 隔離室ファイルの個別・一括完全削除機能
"""
import os
import sys
import subprocess
import threading
import tkinter as tk
from datetime import datetime
from pathlib import Path
from tkinter import filedialog, messagebox, ttk

# Windowsタスクバーのアイコン表示の分離用 (Windows環境のみ)
if os.name == "nt":
    import ctypes
    try:
        # アプリ固有のProcess AppUserModelIDを設定してタスクバーアイコンを独立表示
        myappid = "leukocyte.security.system.gui.1.0"
        ctypes.windll.shell32.SetCurrentProcessExplicitAppUserModelID(myappid)
    except Exception:
        pass

# 通知用ライブラリ
try:
    from plyer import notification
    PLYER_AVAILABLE = True
except ImportError:
    PLYER_AVAILABLE = False

# PDF出力用ライブラリ（日本語フォント登録対応）
try:
    from reportlab.lib import colors
    from reportlab.lib.pagesizes import letter
    from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
    from reportlab.pdfbase import pdfmetrics
    from reportlab.pdfbase.ttfonts import TTFont
    from reportlab.platypus import Paragraph, SimpleDocTemplate, Spacer, Table, TableStyle
    REPORTLAB_AVAILABLE = True
except ImportError:
    REPORTLAB_AVAILABLE = False

from .core import Leukocyte
from .quarantine import QuarantineError


def resource_path(relative_path: str) -> Path:
    """PyInstallerの--onefile実行時と通常実行時の両方で正しいリソースパスを取得する"""
    if hasattr(sys, '_MEIPASS'):
        return Path(sys._MEIPASS) / relative_path
    return Path(__file__).parent / relative_path


def register_japanese_font():
    """ReportLab 用に Windows 標準の日本語フォント（MS ゴシック）を登録する"""
    if not REPORTLAB_AVAILABLE:
        return None

    font_paths = [
        Path(os.environ.get("WINDIR", "C:\\Windows")) / "Fonts" / "msgothic.ttc",
        Path(os.environ.get("WINDIR", "C:\\Windows")) / "Fonts" / "msmincho.ttc",
        Path("/usr/share/fonts/opentype/noto/NotoSansCJK-Regular.ttc"),
    ]

    for fp in font_paths:
        if fp.exists():
            try:
                pdfmetrics.registerFont(TTFont("JapaneseFont", str(fp), subfontIndex=0))
                return "JapaneseFont"
            except Exception:
                continue
    return None


class LeukocyteGUI(tk.Tk):
    def __init__(self, core: Leukocyte):
        super().__init__()
        self.core = core
        self.title("Leukocyte - 学習用セキュリティスキャナー")
        sw, sh = self.winfo_screenwidth(), self.winfo_screenheight()
        w, h = min(980, int(sw * 0.85)), min(720, int(sh * 0.8))
        self.geometry(f"{w}x{h}")
        self.minsize(min(880, w), min(580, h))

        # アイコンの設定
        self.set_app_icon()

        self.setup_styles()

        self.cancel_event = threading.Event()
        self.scan_thread = None
        self.last_summary = None  # PDF出力用データ

        self.create_widgets()
        self.update_status_bar()

    def set_app_icon(self):
        """アプリケーションアイコンを設定"""
        icon_file = resource_path("app_icon.ico")
        if icon_file.exists():
            try:
                self.iconbitmap(str(icon_file))
            except Exception as e:
                print(f"[WARN] アイコンの読み込みに失敗しました: {e}")

    def setup_styles(self):
        self.configure(bg="#1e1e1e")
        style = ttk.Style(self)
        style.theme_use("clam")

        BG_COLOR = "#1e1e1e"
        PANEL_BG = "#252526"
        TEXT_COLOR = "#d4d4d4"
        BORDER_COLOR = "#3c3c3c"
        FONT_FAMILY = "Yu Gothic UI" if os.name == "nt" else "Sans"

        style.configure(".", background=BG_COLOR, foreground=TEXT_COLOR, font=(FONT_FAMILY, 9))
        style.configure("TFrame", background=BG_COLOR)
        style.configure("TLabelframe", background=PANEL_BG, foreground=TEXT_COLOR, bordercolor=BORDER_COLOR)
        style.configure("TLabelframe.Label", background=PANEL_BG, foreground="#569cd6", font=(FONT_FAMILY, 10, "bold"))

        style.configure("TNotebook", background=BG_COLOR, borderwidth=0)
        style.configure("TNotebook.Tab", background="#2d2d2d", foreground="#858585", padding=[12, 6], font=(FONT_FAMILY, 9, "bold"))
        style.map("TNotebook.Tab", background=[("selected", PANEL_BG)], foreground=[("selected", "#4ec9b0")])

        style.configure("TButton", background="#333333", foreground=TEXT_COLOR, borderwidth=1, focuscolor="none")
        style.map("TButton", background=[("active", "#007acc")], foreground=[("active", "#ffffff")])

        style.configure("Accent.TButton", background="#0e639c", foreground="#ffffff")
        style.map("Accent.TButton", background=[("active", "#1177bb")])

        style.configure("Danger.TButton", background="#9a0007", foreground="#ffffff")
        style.map("Danger.TButton", background=[("active", "#d32f2f")])

        style.configure("Treeview", background="#252526", foreground=TEXT_COLOR, fieldbackground="#252526", rowheight=26, borderwidth=0)
        style.configure("Treeview.Heading", background="#333333", foreground=TEXT_COLOR, font=(FONT_FAMILY, 9, "bold"))
        style.map("Treeview", background=[("selected", "#04395e")])

        style.configure("Horizontal.TProgressbar", background="#007acc", troughcolor="#2d2d2d", bordercolor=BG_COLOR)

    def send_notification(self, title: str, message: str):
        """Windowsトースト通知を発行"""
        if PLYER_AVAILABLE:
            try:
                notification.notify(
                    title=title,
                    message=message,
                    app_name="Leukocyte セキュリティ",
                    timeout=5
                )
            except Exception:
                pass

    def create_widgets(self):
        self.notebook = ttk.Notebook(self)
        self.notebook.pack(fill=tk.BOTH, expand=True, padx=10, pady=(10, 0))

        self.tab_scan = ttk.Frame(self.notebook)
        self.tab_watch = ttk.Frame(self.notebook)
        self.tab_quarantine = ttk.Frame(self.notebook)
        self.tab_rules = ttk.Frame(self.notebook)

        self.notebook.add(self.tab_scan, text=" 🔍 スキャン ")
        self.notebook.add(self.tab_watch, text=" 🛡️ フォルダ監視 ")
        self.notebook.add(self.tab_quarantine, text=" ☣ 隔離室 ")
        self.notebook.add(self.tab_rules, text=" ⚙️ YARAルール管理 ")

        self.build_scan_tab()
        self.build_watch_tab()
        self.build_quarantine_tab()
        self.build_rules_tab()

        self.status_frame = tk.Frame(self, bg="#007acc", height=24)
        self.status_frame.pack(fill=tk.X, side=tk.BOTTOM)

        self.lbl_status = tk.Label(self.status_frame, text="準備完了", bg="#007acc", fg="#ffffff", font=("Yu Gothic UI", 9))
        self.lbl_status.pack(side=tk.LEFT, padx=10)

    # ------------------------------------------------------------------
    # 1. スキャン タブ (パターンC: 要確認表示 & 手動隔離対応)
    # ------------------------------------------------------------------
    def build_scan_tab(self):
        pnl = ttk.Frame(self.tab_scan, padding=10)
        pnl.pack(fill=tk.BOTH, expand=True)

        scan_box = ttk.LabelFrame(pnl, text=" 手動スキャン対象フォルダ ", padding=10)
        scan_box.pack(fill=tk.X, pady=(0, 10))

        self.ent_scan_path = ttk.Entry(scan_box, font=("Consolas", 10))
        self.ent_scan_path.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=(0, 5))
        self.ent_scan_path.insert(0, str(Path.home() / "Downloads"))

        btn_browse = ttk.Button(scan_box, text="参照...", command=self.browse_scan_folder)
        btn_browse.pack(side=tk.LEFT, padx=2)

        self.btn_start_scan = ttk.Button(scan_box, text="スキャン開始", style="Accent.TButton", command=self.start_scan)
        self.btn_start_scan.pack(side=tk.LEFT, padx=5)

        self.btn_cancel_scan = ttk.Button(scan_box, text="中断", state=tk.DISABLED, command=self.cancel_scan)
        self.btn_cancel_scan.pack(side=tk.LEFT)

        prog_box = ttk.Frame(pnl)
        prog_box.pack(fill=tk.X, pady=(0, 10))

        self.progress = ttk.Progressbar(prog_box, mode="indeterminate")
        self.progress.pack(fill=tk.X)
        self.lbl_scan_info = ttk.Label(prog_box, text="対象フォルダを指定して「スキャン開始」を押してください", foreground="#858585")
        self.lbl_scan_info.pack(anchor=tk.W, pady=(2, 0))

        table_box = ttk.LabelFrame(pnl, text=" スキャン結果 ", padding=5)
        table_box.pack(fill=tk.BOTH, expand=True)

        tool_bar = ttk.Frame(table_box)
        tool_bar.pack(fill=tk.X, pady=(0, 5))

        self.btn_quarantine_selected = ttk.Button(tool_bar, text="☣️ 選択項目を隔離", style="Danger.TButton", command=self.quarantine_selected_scan_item)
        self.btn_quarantine_selected.pack(side=tk.LEFT)

        self.btn_export_pdf = ttk.Button(tool_bar, text="📄 診断レポート(PDF)を出力", command=self.export_pdf_report, state=tk.DISABLED)
        self.btn_export_pdf.pack(side=tk.RIGHT)

        cols = ("file", "status", "reason", "sha256")
        self.tree_scan = ttk.Treeview(table_box, columns=cols, show="headings")
        self.tree_scan.heading("file", text="ファイルパス")
        self.tree_scan.heading("status", text="状態")
        self.tree_scan.heading("reason", text="判定理由")
        self.tree_scan.heading("sha256", text="SHA-256")

        self.tree_scan.column("file", width=340)
        self.tree_scan.column("status", width=120)
        self.tree_scan.column("reason", width=200)
        self.tree_scan.column("sha256", width=160)

        self.tree_scan.tag_configure("quarantined", foreground="#f44336", background="#2d1517")  # 赤（自動隔離済み）
        self.tree_scan.tag_configure("warning", foreground="#dcdcaa", background="#2a2a15")      # 黄（要確認・未隔離）
        self.tree_scan.tag_configure("detected", foreground="#4ec9b0", background="#1e2d27")     # 青緑

        vsb = ttk.Scrollbar(table_box, orient="vertical", command=self.tree_scan.yview)
        self.tree_scan.configure(yscrollcommand=vsb.set)

        self.tree_scan.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        vsb.pack(side=tk.RIGHT, fill=tk.Y)

    def browse_scan_folder(self):
        d = filedialog.askdirectory(title="スキャン対象フォルダを選択")
        if d:
            self.ent_scan_path.delete(0, tk.END)
            self.ent_scan_path.insert(0, d)

    def start_scan(self):
        target = self.ent_scan_path.get().strip()
        if not target or not Path(target).exists():
            messagebox.showerror("エラー", "有効なスキャン対象フォルダを指定してください。")
            return

        self.tree_scan.delete(*self.tree_scan.get_children())
        self.cancel_event.clear()
        self.btn_start_scan.config(state=tk.DISABLED)
        self.btn_cancel_scan.config(state=tk.NORMAL)
        self.btn_export_pdf.config(state=tk.DISABLED)
        self.progress.start(10)

        self.scan_thread = threading.Thread(target=self._run_scan_thread, args=(Path(target),), daemon=True)
        self.scan_thread.start()

    def cancel_scan(self):
        self.cancel_event.set()
        self.lbl_scan_info.config(text="スキャンキャンセルの要求中...")

    def _run_scan_thread(self, target_dir: Path):
        def on_finding(finding):
            d = finding.detection
            reasons_str = ", ".join(d.reasons)

            is_entropy_only = len(d.reasons) == 1 and ("高エントロピー" in d.reasons[0] or d.reasons[0].startswith("high_entropy"))

            if finding.record_id:
                status_str = "⚠️ 自動隔離済み"
                tag = "quarantined"
            elif is_entropy_only:
                status_str = "❓ 要確認 (高エントロピー)"
                tag = "warning"
            else:
                status_str = "検知 (未隔離)"
                tag = "detected"

            self.after(0, lambda: self.tree_scan.insert(
                "", tk.END, values=(str(d.path), status_str, reasons_str, d.sha256), tags=(tag,)
            ))

        def on_file(p):
            self.after(0, lambda: self.lbl_scan_info.config(text=f"スキャン中: {p.name}"))

        summary = self.core.scan(
            target_dir,
            on_file=on_file,
            on_finding=on_finding,
            cancel=self.cancel_event,
        )
        self.last_summary = summary

        def finish():
            self.progress.stop()
            self.btn_start_scan.config(state=tk.NORMAL)
            self.btn_cancel_scan.config(state=tk.DISABLED)
            self.btn_export_pdf.config(state=tk.NORMAL)

            status = "スキャン中断" if summary.cancelled else "スキャン完了"
            ok = max(0, summary.scanned - len(summary.findings) - summary.skipped)
            self.lbl_scan_info.config(
                text=(f"{status}: スキャン対象 {summary.scanned} 件 / 検出 {len(summary.findings)} 件 / "
                      f"該当なし {ok} 件 / 検査できなかった {summary.skipped} 件")
            )

            if summary.skipped > 0:
                first = summary.errors[0] if summary.errors else None
                detail = f"\n\n例: {first.path.name}\n理由: {str(first.reason)[:300]}" if first else ""
                messagebox.showwarning(
                    "一部のファイルを検査できませんでした",
                    f"{summary.skipped} 件のファイルを検査できませんでした。"
                    f"この件数は「安全」という意味ではありません。{detail}\n\n"
                    "すべての理由は scan.log に記録されています。",
                )

            if len(summary.findings) > 0:
                self.send_notification("脅威を検出しました", f"手動スキャンにより {len(summary.findings)} 件の検知アイテムがあります。")

            self.update_status_bar()

        self.after(0, finish)

    def quarantine_selected_scan_item(self):
        """スキャン結果テーブルで選択された「要確認」アイテムを手動で隔離する"""
        selected = self.tree_scan.selection()
        if not selected:
            messagebox.showwarning("選択エラー", "隔離する項目を一覧から選択してください。")
            return

        item = self.tree_scan.item(selected[0])
        f_path_str, status_str, reason, sha256_val = item["values"]
        f_path = Path(f_path_str)

        if "隔離済み" in status_str:
            messagebox.showinfo("お知らせ", "指定されたファイルは既に隔離済みです。")
            return

        if not f_path.exists():
            messagebox.showerror("エラー", f"ファイルが存在しないか移動されています:\n{f_path}")
            return

        ans = messagebox.askyesno(
            "隔離の確認",
            f"選択したファイルを隔離室へ移動しますか？\n\nファイル: {f_path.name}\n理由: {reason}",
            parent=self
        )
        if ans:
            try:
                rec_id = self.core.quarantine_file(f_path, sha256_val)
                self.tree_scan.item(selected[0], values=(str(f_path), f"⚠️ 手動隔離済み (ID: {rec_id})", reason, sha256_val), tags=("quarantined",))
                messagebox.showinfo("成功", f"ファイルを隔離しました:\nID: {rec_id}", parent=self)
                self.refresh_quarantine_list()
                self.update_status_bar()
            except Exception as e:
                messagebox.showerror("隔離失敗", f"隔離処理に失敗しました: {e}", parent=self)

    def export_pdf_report(self):
        """日本語対応の PDF 診断レポートを出力"""
        if not REPORTLAB_AVAILABLE:
            messagebox.showerror("エラー", "ReportLab がインストールされていません。\n`pip install reportlab` を実行してください。")
            return
        if not self.last_summary:
            messagebox.showwarning("警告", "出力可能なスキャン結果がありません。")
            return

        font_name = register_japanese_font()
        if not font_name:
            messagebox.showerror("エラー", "日本語フォントが見つかりませんでした。PDFを作成できません。")
            return

        save_path = filedialog.asksaveasfilename(
            defaultextension=".pdf",
            filetypes=[("PDF ドキュメント", "*.pdf")],
            title="診断レポートの保存場所を選択"
        )
        if not save_path:
            return

        try:
            doc = SimpleDocTemplate(save_path, pagesize=letter)
            story = []

            title_style = ParagraphStyle('JTitle', fontName=font_name, fontSize=18, leading=22, textColor=colors.HexColor("#0e639c"))
            normal_style = ParagraphStyle('JNormal', fontName=font_name, fontSize=10, leading=14, textColor=colors.black)

            story.append(Paragraph("Leukocyte セキュリティ診断レポート", title_style))
            story.append(Spacer(1, 12))

            now_str = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            info_text = f"""
            <b>実施日時:</b> {now_str}<br/>
            <b>スキャン済みファイル数:</b> {self.last_summary.scanned}<br/>
            <b>検出された脅威数:</b> {len(self.last_summary.findings)}<br/>
            <b>検査できなかったファイル数:</b> {self.last_summary.skipped}
            """
            story.append(Paragraph(info_text, normal_style))
            story.append(Spacer(1, 18))

            data = [[
                Paragraph("<b>ファイルパス</b>", normal_style),
                Paragraph("<b>判定理由</b>", normal_style),
                Paragraph("<b>SHA-256 (省略)</b>", normal_style)
            ]]

            for f in self.last_summary.findings:
                d = f.detection
                data.append([
                    Paragraph(str(d.path), normal_style),
                    Paragraph(", ".join(d.reasons), normal_style),
                    Paragraph(d.sha256[:16] + "...", normal_style)
                ])

            if len(self.last_summary.findings) == 0:
                data.append([Paragraph("検出された脅威はありません。", normal_style), Paragraph("-", normal_style), Paragraph("-", normal_style)])

            t = Table(data, colWidths=[220, 140, 140])
            t.setStyle(TableStyle([
                ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor("#0e639c")),
                ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
                ('BOTTOMPADDING', (0, 0), (-1, 0), 6),
                ('BACKGROUND', (0, 1), (-1, -1), colors.HexColor("#f8f9fa")),
                ('GRID', (0, 0), (-1, -1), 0.5, colors.grey)
            ]))
            story.append(t)

            doc.build(story)
            messagebox.showinfo("成功", f"日本語の診断レポートを出力しました:\n{save_path}", parent=self)
        except Exception as e:
            messagebox.showerror("エラー", f"PDFの作成に失敗しました: {e}", parent=self)

    # ------------------------------------------------------------------
    # 2. フォルダ監視 タブ (高エントロピー検知時のポップアップダイアログ対応)
    # ------------------------------------------------------------------
    def build_watch_tab(self):
        pnl = ttk.Frame(self.tab_watch, padding=10)
        pnl.pack(fill=tk.BOTH, expand=True)

        watch_box = ttk.LabelFrame(pnl, text=" フォルダ監視対象フォルダ ", padding=10)
        watch_box.pack(fill=tk.X, pady=(0, 10))

        self.ent_watch_path = ttk.Entry(watch_box, font=("Consolas", 10))
        self.ent_watch_path.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=(0, 5))
        self.ent_watch_path.insert(0, str(Path.home() / "Downloads"))

        btn_browse = ttk.Button(watch_box, text="参照...", command=self.browse_watch_folder)
        btn_browse.pack(side=tk.LEFT, padx=2)

        self.watch_banner = tk.Frame(pnl, bg="#2d2d2d", padx=15, pady=10, highlightthickness=1, highlightbackground="#3c3c3c")
        self.watch_banner.pack(fill=tk.X, pady=(0, 10))

        self.lbl_watch_status = tk.Label(self.watch_banner, text="● 監視停止中 (STANDBY)", font=("Yu Gothic UI", 11, "bold"), fg="#858585", bg="#2d2d2d")
        self.lbl_watch_status.pack(side=tk.LEFT)

        self.btn_toggle_watch = ttk.Button(self.watch_banner, text="常駐監視を開始", style="Accent.TButton", command=self.toggle_watch)
        self.btn_toggle_watch.pack(side=tk.RIGHT)

        log_box = ttk.LabelFrame(pnl, text=" 検知ログ ", padding=10)
        log_box.pack(fill=tk.BOTH, expand=True)

        self.txt_watch_log = tk.Text(log_box, bg="#1e1e1e", fg="#4ec9b0", font=("Consolas", 9), borderwidth=0)
        vsb = ttk.Scrollbar(log_box, command=self.txt_watch_log.yview)
        self.txt_watch_log.configure(yscrollcommand=vsb.set)

        self.txt_watch_log.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        vsb.pack(side=tk.RIGHT, fill=tk.Y)

    def browse_watch_folder(self):
        d = filedialog.askdirectory(title="監視対象フォルダを選択")
        if d:
            self.ent_watch_path.delete(0, tk.END)
            self.ent_watch_path.insert(0, d)

    def toggle_watch(self):
        if getattr(self.core, "watching", False):
            self.core.stop_watch()
            self.lbl_watch_status.config(text="● 監視停止中 (STANDBY)", fg="#858585")
            self.btn_toggle_watch.config(text="常駐監視を開始", style="Accent.TButton")
            self.ent_watch_path.config(state=tk.NORMAL)
            self.txt_watch_log.insert(tk.END, "[SYSTEM] フォルダ監視を停止しました。\n")
        else:
            target = Path(self.ent_watch_path.get().strip())
            if not target.exists() or not target.is_dir():
                messagebox.showerror("エラー", "有効な監視対象フォルダを指定してください。")
                return

            def on_detect(det, record_id):
                is_entropy_only = len(det.reasons) == 1 and (
                    "高エントロピー" in det.reasons[0] or det.reasons[0].startswith("high_entropy")
                )

                if record_id:
                    status_text = f"自動隔離完了 (ID: {record_id})"
                elif is_entropy_only:
                    status_text = "要確認 (未隔離)"
                else:
                    status_text = "検知"

                def _update_ui():
                    msg = f"[警告] 検出: {det.path.name} ({', '.join(det.reasons)}) -> 状態: {status_text}\n"
                    self.txt_watch_log.insert(tk.END, msg, "alert")
                    self.send_notification("監視での検知", f"ファイル: {det.path.name}\n理由: {', '.join(det.reasons)}")
                    self.update_status_bar()
                    self.refresh_quarantine_list()

                    # 高エントロピーかつ未隔離の場合、メインスレッド上でポップアップを表示
                    if is_entropy_only and not record_id:
                        self.prompt_quarantine_dialog(det)

                # UI操作・ダイアログ表示をまとめてメインスレッドで実行
                self.after(0, _update_ui)

            try:
                self.core.start_watch(target, on_detect=on_detect)
                self.lbl_watch_status.config(text=f"● 常駐監視中: {target.name}", fg="#4ec9b0")
                self.btn_toggle_watch.config(text="監視を停止", style="Danger.TButton")
                self.ent_watch_path.config(state=tk.DISABLED)
                self.txt_watch_log.insert(tk.END, f"[SYSTEM] フォルダの常駐監視を開始しました: {target}\n")
            except Exception as e:
                messagebox.showerror("エラー", f"監視の開始に失敗しました: {e}")

        self.txt_watch_log.tag_config("alert", foreground="#f44336")
        self.update_status_bar()

    def prompt_quarantine_dialog(self, det):
        """フォルダ監視中に高エントロピーを検知した際のダイアログ表示"""
        # ウィンドウを最前面にフォーカス
        self.deiconify()
        self.lift()
        self.focus_force()

        ans = messagebox.askyesno(
            "高エントロピー検知の確認",
            f"以下のファイルで高エントロピー（高圧縮・パッカー・暗号化等の可能性）が検出されました。\n\n"
            f"ファイル: {det.path.name}\n"
            f"詳細: {', '.join(det.reasons)}\n\n"
            f"隔離室へ移動しますか？\n"
            f"（自作アプリやビルド成果物の場合は「いいえ」を選択してください）",
            parent=self
        )
        if ans:
            try:
                rec_id = self.core.quarantine_file(det.path, det.sha256)
                self.txt_watch_log.insert(tk.END, f"[ACTION] ユーザー選択により手動隔離を実行: {det.path.name} (ID: {rec_id})\n")
                self.refresh_quarantine_list()
                self.update_status_bar()
            except Exception as e:
                messagebox.showerror("隔離失敗", f"隔離処理に失敗しました: {e}", parent=self)

    # ------------------------------------------------------------------
    # 3. 隔離室 タブ（個別・一括完全削除機能追加版）
    # ------------------------------------------------------------------
    def build_quarantine_tab(self):
        pnl = ttk.Frame(self.tab_quarantine, padding=10)
        pnl.pack(fill=tk.BOTH, expand=True)

        btn_bar = ttk.Frame(pnl)
        btn_bar.pack(fill=tk.X, pady=(0, 10))

        btn_refresh = ttk.Button(btn_bar, text="🔄 リスト再読み込み", command=self.refresh_quarantine_list)
        btn_refresh.pack(side=tk.LEFT, padx=(0, 5))

        btn_restore = ttk.Button(btn_bar, text="↩️ 元の場所へ復元", command=self.restore_selected)
        btn_restore.pack(side=tk.LEFT, padx=5)

        # --- 削除ボタンの追加 ---
        btn_delete = ttk.Button(btn_bar, text="🗑️️ 選択項目を削除", style="Danger.TButton", command=self.delete_selected_quarantine)
        btn_delete.pack(side=tk.LEFT, padx=5)

        btn_clear_all = ttk.Button(btn_bar, text="🔥 すべて完全削除", style="Danger.TButton", command=self.clear_all_quarantine)
        btn_clear_all.pack(side=tk.RIGHT)

        cols = ("id", "orig_path", "date", "sha256")
        self.tree_quarantine = ttk.Treeview(pnl, columns=cols, show="headings")
        self.tree_quarantine.heading("id", text="隔離ID")
        self.tree_quarantine.heading("orig_path", text="元のファイルパス")
        self.tree_quarantine.heading("date", text="隔離日時")
        self.tree_quarantine.heading("sha256", text="SHA-256")

        self.tree_quarantine.column("id", width=120)
        self.tree_quarantine.column("orig_path", width=350)
        self.tree_quarantine.column("date", width=150)
        self.tree_quarantine.column("sha256", width=150)

        vsb = ttk.Scrollbar(pnl, orient="vertical", command=self.tree_quarantine.yview)
        self.tree_quarantine.configure(yscrollcommand=vsb.set)

        self.tree_quarantine.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        vsb.pack(side=tk.RIGHT, fill=tk.Y)

        self.refresh_quarantine_list()

    def refresh_quarantine_list(self):
        self.tree_quarantine.delete(*self.tree_quarantine.get_children())
        records = self.core.list_quarantine()
        for r in records:
            self.tree_quarantine.insert("", tk.END, values=(
                r.id, str(r.original_path), str(r.quarantined_at), r.sha256
            ))

    def restore_selected(self):
        selected = self.tree_quarantine.selection()
        if not selected:
            messagebox.showwarning("選択エラー", "復元する項目をリストから選択してください。")
            return
        qid = self.tree_quarantine.item(selected[0], "values")[0]
        try:
            dest = self.core.restore(qid)
            messagebox.showinfo("成功", f"隔離ID {qid} を復元しました:\n{dest}", parent=self)
            self.refresh_quarantine_list()
            self.update_status_bar()
        except QuarantineError as e:
            messagebox.showerror("復元失敗", str(e), parent=self)

    def delete_selected_quarantine(self):
        """選択された隔離ファイルをディスクから完全に削除する"""
        selected = self.tree_quarantine.selection()
        if not selected:
            messagebox.showwarning("選択エラー", "削除する項目をリストから選択してください。", parent=self)
            return

        item = self.tree_quarantine.item(selected[0], "values")
        qid, orig_path = item[0], item[1]

        ans = messagebox.askyesno(
            "削除の確認",
            f"以下の隔離ファイルを PC から完全削除しますか？\n（この操作は取り消せません）\n\nID: {qid}\nパス: {orig_path}",
            parent=self
        )
        if ans:
            try:
                # バックエンド側にdeleteメソッドがあれば呼び出し、無ければ直接消去のフォールバック
                if hasattr(self.core, "delete_quarantined_file"):
                    self.core.delete_quarantined_file(qid)
                elif hasattr(self.core, "quarantine") and hasattr(self.core.quarantine, "delete"):
                    self.core.quarantine.delete(qid)
                else:
                    q_dir = getattr(self.core.config, "quarantine_dir", Path("quarantine"))
                    target_file = q_dir / qid
                    if target_file.exists():
                        target_file.unlink()

                messagebox.showinfo("成功", f"隔離ファイル (ID: {qid}) を削除しました。", parent=self)
                self.refresh_quarantine_list()
                self.update_status_bar()
            except Exception as e:
                messagebox.showerror("削除失敗", f"削除処理中にエラーが発生しました: {e}", parent=self)

    def clear_all_quarantine(self):
        """すべての隔離ファイルを完全削除する"""
        records = self.core.list_quarantine()
        if not records:
            messagebox.showinfo("お知らせ", "削除対象の隔離ファイルはありません。", parent=self)
            return

        ans = messagebox.askyesno(
            "一括削除の確認",
            f"現在隔離されている {len(records)} 件のファイルをすべて完全削除しますか？\n（復元できなくなります）",
            parent=self
        )
        if ans:
            count = 0
            q_dir = getattr(self.core.config, "quarantine_dir", Path("quarantine"))
            for r in records:
                try:
                    if hasattr(self.core, "delete_quarantined_file"):
                        self.core.delete_quarantined_file(r.id)
                    elif hasattr(self.core, "quarantine") and hasattr(self.core.quarantine, "delete"):
                        self.core.quarantine.delete(r.id)
                    else:
                        target_file = q_dir / r.id
                        if target_file.exists():
                            target_file.unlink()
                    count += 1
                except Exception:
                    pass

            messagebox.showinfo("完了", f"{count} 件の隔離ファイルを完全削除しました。", parent=self)
            self.refresh_quarantine_list()
            self.update_status_bar()

    # ------------------------------------------------------------------
    # 4. YARAルール管理 タブ
    # ------------------------------------------------------------------
    def build_rules_tab(self):
        pnl = ttk.Frame(self.tab_rules, padding=10)
        pnl.pack(fill=tk.BOTH, expand=True)

        top_bar = ttk.Frame(pnl)
        top_bar.pack(fill=tk.X, pady=(0, 10))

        btn_add_rule = ttk.Button(top_bar, text="➕ 新しいYARAルール (.yar) を追加", style="Accent.TButton", command=self.add_yara_rule)
        btn_add_rule.pack(side=tk.LEFT)

        rules_box = ttk.LabelFrame(pnl, text=" 読み込まれているYARAルール一覧 ", padding=10)
        rules_box.pack(fill=tk.BOTH, expand=True)

        self.lst_rules = tk.Listbox(rules_box, bg="#1e1e1e", fg="#d4d4d4", selectbackground="#04395e", borderwidth=0, font=("Consolas", 9))
        vsb = ttk.Scrollbar(rules_box, command=self.lst_rules.yview)
        self.lst_rules.configure(yscrollcommand=vsb.set)

        self.lst_rules.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        vsb.pack(side=tk.RIGHT, fill=tk.Y)

        self.refresh_rules_list()

    def refresh_rules_list(self):
        self.lst_rules.delete(0, tk.END)
        rules_dir = self.core.config.rules_dir
        if rules_dir.exists() and rules_dir.is_dir():
            for f in rules_dir.glob("*.yar*"):
                self.lst_rules.insert(tk.END, f.name)

    def add_yara_rule(self):
        file_paths = filedialog.askopenfilenames(
            title="YARAルールファイルを選択",
            filetypes=[("YARA Rules", "*.yar *.yara"), ("すべてのファイル", "*.*")]
        )
        if file_paths:
            rules_dir = self.core.config.rules_dir
            rules_dir.mkdir(parents=True, exist_ok=True)

            copied = 0
            for fp in file_paths:
                src = Path(fp)
                dst = rules_dir / src.name
                dst.write_bytes(src.read_bytes())
                copied += 1

            messagebox.showinfo("成功", f"{copied} 件のYARAルールを追加しました。", parent=self)
            self.refresh_rules_list()
            self.update_status_bar()

    # ------------------------------------------------------------------
    # ステータスバー更新
    # ------------------------------------------------------------------
    def update_status_bar(self):
        st = self.core.status()
        y_status = "有効" if st.yara_enabled else "無効"
        status_text = f" 抗原ハッシュ: {st.signature_count} 件  |  YARAルール: {st.yara_rule_files} 個 ({y_status})  |  現在隔離中: {st.quarantined} 件"
        self.lbl_status.config(text=status_text)


def main(config_path=None):
    from .config import DEFAULT_CONFIG_PATH, load_config
    from .core import Leukocyte

    path = config_path or DEFAULT_CONFIG_PATH
    config = load_config(path)
    core = Leukocyte(config)
    app = LeukocyteGUI(core)
    app.mainloop()
    return 0


if __name__ == "__main__":
    main()