"""S-DES 教学界面：位串、ASCII、穷举密钥与碰撞分析。"""

from __future__ import annotations

import base64
import importlib
import json
import sys
import time
from datetime import datetime
from pathlib import Path
from typing import Callable

from PyQt5.QtCore import QThread, pyqtSignal
from PyQt5.QtGui import QFont, QFontDatabase
from PyQt5.QtWidgets import (
    QApplication, QComboBox, QHBoxLayout, QLabel,
    QLineEdit, QMainWindow, QPlainTextEdit, QProgressBar, QPushButton,
    QTabWidget, QVBoxLayout, QWidget,
)


def _json(value: object) -> str:
    return json.dumps(value, ensure_ascii=False, indent=2, default=str)


def configure_application_fonts(app: QApplication):
    """Windows 的 offscreen 插件没有系统字体，显式加载本机字体。"""
    if app.platformName() == "offscreen":
        for path in (
            "C:/Windows/Fonts/msyh.ttc", "C:/Windows/Fonts/msyhbd.ttc",
            "C:/Windows/Fonts/consola.ttf", "C:/Windows/Fonts/consolab.ttf",
        ):
            if Path(path).exists():
                QFontDatabase.addApplicationFont(path)
    app.setFont(QFont("Microsoft YaHei", 10))


class AnalysisWorker(QThread):
    """计算在线程中执行；时间戳与耗时均在真实计算前后采集。"""

    progress = pyqtSignal(int, int, object, float)
    completed = pyqtSignal(object)
    failed = pyqtSignal(str)

    def __init__(self, kind: str, payload: object, schedule: str, parent=None):
        super().__init__(parent)
        self.kind = kind
        self.payload = payload
        self.schedule = schedule
        self.started_at = ""
        self.finished_at = ""
        self.elapsed_seconds = 0.0

    def run(self):
        self.started_at = datetime.now().astimezone().isoformat(timespec="milliseconds")
        started = time.perf_counter()
        try:
            analysis = importlib.import_module("analysis_tools")
            if self.kind == "brute":
                result = analysis.brute_force(
                    self.payload,
                    schedule=self.schedule,
                    # 每 32 个真实检查点更新一次，避免 1024 次 GUI 事件排队。
                    progress=lambda done, total, candidates, elapsed:
                        self.progress.emit(done, total, candidates, elapsed)
                        if done % 32 == 0 or done == total else None,
                )
            else:
                result = analysis.collision_analysis(
                    self.payload, schedule=self.schedule,
                )
            self.finished_at = datetime.now().astimezone().isoformat(timespec="milliseconds")
            self.elapsed_seconds = time.perf_counter() - started
            measured = {
                "kind": self.kind,
                "schedule": self.schedule,
                "started_at": result.get("started_at", self.started_at),
                "finished_at": result.get("finished_at", self.finished_at),
                "elapsed_seconds": result.get("elapsed_seconds", self.elapsed_seconds),
                "worker_elapsed_seconds": self.elapsed_seconds,
                "result": result,
            }
            self.completed.emit(measured)
        except Exception as error:
            self.finished_at = datetime.now().astimezone().isoformat(timespec="milliseconds")
            self.elapsed_seconds = time.perf_counter() - started
            self.failed.emit(str(error))


class SDESWindow(QMainWindow):
    taskStarted = pyqtSignal(str, object)
    taskProgress = pyqtSignal(str, int, int, object, float)
    taskCompleted = pyqtSignal(str, object)
    taskFailed = pyqtSignal(str, str)

    def __init__(self):
        super().__init__()
        self.setWindowTitle("S-DES 信息安全实验 · 加密与密钥分析")
        self.resize(1140, 860)
        self.setMinimumSize(850, 720)
        self.worker: AnalysisWorker | None = None
        self.last_task: dict | None = None
        self._action_controls: list[QWidget] = []
        self._build_ui()

    def _build_ui(self):
        central = QWidget()
        self.setCentralWidget(central)
        layout = QVBoxLayout(central)
        layout.setContentsMargins(18, 14, 18, 14)
        layout.setSpacing(10)
        title = QLabel("S-DES 加解密与密钥分析")
        title.setFont(QFont("Microsoft YaHei", 17, QFont.Bold))
        layout.addWidget(title)

        key_row = QHBoxLayout()
        key_row.addWidget(QLabel("10 位密钥"))
        self.key_input = QLineEdit("1010000010")
        self.key_input.setObjectName("keyInput")
        self.key_input.setMaximumWidth(180)
        self.key_input.setPlaceholderText("10 个 0 或 1")
        key_row.addWidget(self.key_input)
        key_row.addSpacing(18)
        key_row.addWidget(QLabel("子密钥生成"))
        self.schedule_combo = QComboBox()
        self.schedule_combo.setObjectName("scheduleCombo")
        self.schedule_combo.addItem("作业公式：P10 后累计左移 1 / 2 位（默认）", "assignment")
        self.schedule_combo.addItem("课件兼容：P10 后累计左移 1 / 3 位", "cumulative")
        self.schedule_combo.setMinimumWidth(390)
        key_row.addWidget(self.schedule_combo, 1)
        layout.addLayout(key_row)
        self.schedule_note = QLabel()
        self.schedule_note.setObjectName("scheduleNote")
        self.schedule_note.setWordWrap(True)
        layout.addWidget(self.schedule_note)
        self.schedule_combo.currentIndexChanged.connect(self._schedule_changed)

        self.tabs = QTabWidget()
        self.tabs.setObjectName("mainTabs")
        self.tabs.addTab(self._build_bits_tab(), "8 位加解密")
        self.tabs.addTab(self._build_ascii_tab(), "ASCII 字符串")
        self.tabs.addTab(self._build_brute_tab(), "暴力破解")
        self.tabs.addTab(self._build_collision_tab(), "密钥碰撞")
        layout.addWidget(self.tabs, 1)

        self.status_label = QLabel("就绪。输入数据后选择操作。")
        self.status_label.setObjectName("statusLabel")
        self.status_label.setWordWrap(True)
        self.status_label.setMinimumHeight(28)
        layout.addWidget(self.status_label)
        # 计算期间冻结输入，防止报告对应旧输入、界面却显示新输入。
        self._action_controls.extend([
            self.key_input, self.schedule_combo, self.bits_input,
            self.cipher_format, self.ascii_input, self.ascii_cipher,
            self.pairs_input, self.collision_input,
        ])
        self.setStyleSheet("""
            QMainWindow { background: #f3f6fb; }
            QTabWidget::pane { border: 1px solid #cbd5e1; background: white; }
            QTabBar::tab { padding: 9px 18px; }
            QLabel { color: #23364d; }
            QLineEdit, QPlainTextEdit { background: white; border: 1px solid #bdcadd;
                border-radius: 4px; padding: 6px; selection-background-color: #376bba; }
            QPushButton { background: #e6edf8; color: #183c70; border: 1px solid #a8bad5;
                border-radius: 4px; padding: 7px 15px; min-height: 20px; }
            QPushButton:hover { background: #d4e4fb; }
            QPushButton:disabled { color: #94a3b8; background: #f1f5f9; }
            QProgressBar { border: 1px solid #bdcadd; text-align: center; min-height: 20px; }
            QProgressBar::chunk { background: #5584c6; }
        """)
        self._schedule_changed()

    def _button(self, label: str, name: str, action: Callable) -> QPushButton:
        button = QPushButton(label)
        button.setObjectName(name)
        button.clicked.connect(action)
        self._action_controls.append(button)
        return button

    @staticmethod
    def _text(name: str, readonly: bool = False) -> QPlainTextEdit:
        editor = QPlainTextEdit()
        editor.setObjectName(name)
        editor.setReadOnly(readonly)
        editor.setFont(QFont("Consolas", 10))
        if readonly:
            editor.setLineWrapMode(QPlainTextEdit.NoWrap)
        return editor

    def _build_bits_tab(self) -> QWidget:
        tab = QWidget()
        layout = QVBoxLayout(tab)
        layout.setContentsMargins(14, 14, 14, 14)
        row = QHBoxLayout()
        row.addWidget(QLabel("8 位明文 / 密文"))
        self.bits_input = QLineEdit("10101010")
        self.bits_input.setObjectName("bitsInput")
        self.bits_input.setMaximumWidth(180)
        self.bits_input.setPlaceholderText("8 个 0 或 1")
        row.addWidget(self.bits_input)
        row.addWidget(self._button("加密", "bitsEncryptButton", lambda: self._bits(False)))
        row.addWidget(self._button("解密", "bitsDecryptButton", lambda: self._bits(True)))
        row.addStretch()
        layout.addLayout(row)
        result_row = QHBoxLayout()
        self.bits_output_label = QLabel("输出 8 位密文")
        result_row.addWidget(self.bits_output_label)
        self.bits_output = QLineEdit()
        self.bits_output.setObjectName("bitsOutput")
        self.bits_output.setReadOnly(True)
        self.bits_output.setFont(QFont("Consolas", 14, QFont.Bold))
        result_row.addWidget(self.bits_output, 1)
        layout.addLayout(result_row)
        note = QLabel("中间步骤：子密钥 → IP → 第一轮 fK → SW → 第二轮 fK → IP⁻¹；解密交换 K1、K2。")
        note.setWordWrap(True)
        layout.addWidget(note)
        self.trace_output = self._text("traceOutput", True)
        layout.addWidget(self.trace_output, 1)
        return tab

    def _build_ascii_tab(self) -> QWidget:
        tab = QWidget()
        layout = QVBoxLayout(tab)
        layout.setContentsMargins(14, 14, 14, 14)
        note = QLabel("每个 ASCII 字节独立进行 S-DES 运算。密文使用 Hex 或 Base64 保存；两种表示都保留原始字节。")
        note.setWordWrap(True)
        layout.addWidget(note)
        row = QHBoxLayout()
        row.addWidget(QLabel("密文表示"))
        self.cipher_format = QComboBox()
        self.cipher_format.setObjectName("cipherFormat")
        self.cipher_format.addItems(["Hex", "Base64"])
        row.addWidget(self.cipher_format)
        row.addWidget(self._button("明文 → 加密", "asciiEncryptButton", self._ascii_encrypt))
        row.addWidget(self._button("密文 → 解密", "asciiDecryptButton", self._ascii_decrypt))
        row.addStretch()
        layout.addLayout(row)
        layout.addWidget(QLabel("ASCII 明文（加密输入）"))
        self.ascii_input = self._text("asciiInput")
        self.ascii_input.setPlainText("Hello SDES!")
        layout.addWidget(self.ascii_input, 1)
        layout.addWidget(QLabel("密文（可粘贴后解密）"))
        self.ascii_cipher = self._text("asciiCipher")
        self.ascii_cipher.setPlaceholderText("Hex 示例：A1 02 FF；Base64 示例：oQL/")
        layout.addWidget(self.ascii_cipher, 1)
        layout.addWidget(QLabel("ASCII 解密结果"))
        self.ascii_output = self._text("asciiOutput", True)
        layout.addWidget(self.ascii_output, 1)
        self.ascii_count = QLabel("尚未运行")
        self.ascii_count.setWordWrap(True)
        layout.addWidget(self.ascii_count)
        return tab

    def _build_brute_tab(self) -> QWidget:
        tab = QWidget()
        layout = QVBoxLayout(tab)
        layout.setContentsMargins(14, 14, 14, 14)
        note = QLabel("穷举全部 1024 个 10 位密钥，保留同时满足全部已知明密文对的候选。每行填写一个“8 位明文 8 位密文”。")
        note.setWordWrap(True)
        layout.addWidget(note)
        self.pairs_input = self._text("pairsInput")
        self.pairs_input.setPlaceholderText("10101010 00000000\n00001111 11110000")
        self.pairs_input.setMaximumHeight(110)
        layout.addWidget(self.pairs_input)
        row = QHBoxLayout()
        row.addWidget(self._button("开始暴力破解", "bruteButton", self._start_brute))
        self.brute_summary = QLabel("候选密钥：等待计算")
        self.brute_summary.setObjectName("bruteSummary")
        self.brute_summary.setWordWrap(True)
        row.addWidget(self.brute_summary, 1)
        layout.addLayout(row)
        self.brute_progress = QProgressBar()
        self.brute_progress.setObjectName("bruteProgress")
        self.brute_progress.setRange(0, 1024)
        self.brute_progress.setValue(0)
        self.brute_progress.setFormat("%v / %m 个密钥")
        layout.addWidget(self.brute_progress)
        self.brute_timing = QLabel("开始时间：—\n结束时间：—\n实测耗时：—")
        self.brute_timing.setObjectName("bruteTiming")
        self.brute_timing.setWordWrap(True)
        layout.addWidget(self.brute_timing)
        self.brute_output = self._text("bruteOutput", True)
        layout.addWidget(self.brute_output, 1)
        return tab

    def _build_collision_tab(self) -> QWidget:
        tab = QWidget()
        layout = QVBoxLayout(tab)
        layout.setContentsMargins(14, 14, 14, 14)
        note = QLabel("固定一个 8 位明文，计算全部 1024 个密钥的输出，按相同密文分组。不同密钥可以产生相同密文；一个明密文对通常不能唯一确定密钥。")
        note.setWordWrap(True)
        layout.addWidget(note)
        row = QHBoxLayout()
        row.addWidget(QLabel("固定明文"))
        self.collision_input = QLineEdit("10101010")
        self.collision_input.setObjectName("collisionInput")
        self.collision_input.setMaximumWidth(180)
        row.addWidget(self.collision_input)
        row.addWidget(self._button("分析 1024 个密钥", "collisionButton", self._start_collision))
        row.addStretch()
        layout.addLayout(row)
        self.collision_summary = QLabel("碰撞分组：等待计算")
        self.collision_summary.setObjectName("collisionSummary")
        self.collision_summary.setWordWrap(True)
        layout.addWidget(self.collision_summary)
        self.collision_timing = QLabel("开始时间：—\n结束时间：—\n实测耗时：—")
        self.collision_timing.setObjectName("collisionTiming")
        self.collision_timing.setWordWrap(True)
        layout.addWidget(self.collision_timing)
        self.collision_output = self._text("collisionOutput", True)
        layout.addWidget(self.collision_output, 1)
        return tab

    @property
    def schedule(self) -> str:
        return self.schedule_combo.currentData()

    def _schedule_changed(self):
        if self.schedule == "assignment":
            note = "当前使用作业公式：K1、K2 分别来自 P10 后两半累计左移 1、2 位；K2 由原始两半左移 2 位生成。所有功能同步使用此模式。"
        else:
            note = "当前使用课件兼容：先左移 1 位生成 K1，再继续左移 2 位生成 K2，即相对 P10 累计左移 1、3 位。所有功能同步使用此模式。"
        self.schedule_note.setText(note)
        if hasattr(self, "trace_output"):
            self.bits_output.clear()
            self.trace_output.clear()
            self.ascii_cipher.clear()
            self.ascii_output.clear()
            self.ascii_count.setText("模式已切换，请重新运行。")
            self.brute_output.clear()
            self.brute_progress.setValue(0)
            self.brute_summary.setText("候选密钥：等待计算")
            self.brute_timing.setText("开始时间：—\n结束时间：—\n实测耗时：—")
            self.collision_output.clear()
            self.collision_summary.setText("碰撞分组：等待计算")
            self.collision_timing.setText("开始时间：—\n结束时间：—\n实测耗时：—")
            self.last_task = None
            self._status("就绪。所有功能已同步子密钥模式。")

    def _status(self, message: str, error: bool = False):
        self.status_label.setText(("输入 / 运行错误：" if error else "") + message)
        self.status_label.setStyleSheet("color: #b42318;" if error else "color: #24548b;")

    def _core_and_key(self):
        core = importlib.import_module("sdes")
        return core, core.parse_bits(self.key_input.text().strip(), 10)

    def _bits(self, decrypt: bool):
        try:
            core, key = self._core_and_key()
            block = core.parse_bits(self.bits_input.text().strip(), 8)
            output = (core.decrypt_block if decrypt else core.encrypt_block)(
                block, key, schedule=self.schedule,
            )
            trace = core.trace_block(block, key, decrypt=decrypt, schedule=self.schedule)
            self.bits_output_label.setText("输出 8 位明文" if decrypt else "输出 8 位密文")
            self.bits_output.setText(core.format_bits(output, 8))
            self.trace_output.setPlainText(_json(trace))
            self._status("解密完成；中间步骤已更新。" if decrypt else "加密完成；中间步骤已更新。")
        except Exception as error:
            self.bits_output.clear()
            self.trace_output.clear()
            self._status(str(error), True)

    def _ascii_encrypt(self):
        try:
            core, key = self._core_and_key()
            plaintext = self.ascii_input.toPlainText()
            cipher = core.encrypt_ascii(plaintext, key, schedule=self.schedule)
            rendered = cipher.hex(" ").upper() if self.cipher_format.currentText() == "Hex" else base64.b64encode(cipher).decode("ascii")
            self.ascii_cipher.setPlainText(rendered)
            self.ascii_output.clear()
            self.ascii_count.setText(f"加密 {len(cipher)} 个 ASCII 字节；密文表示：{self.cipher_format.currentText()}。")
            self._status("ASCII 加密完成。密文已编码为 " + self.cipher_format.currentText() + "。")
        except Exception as error:
            self.ascii_cipher.clear()
            self.ascii_output.clear()
            self.ascii_count.setText("加密失败；请修正输入后重试。")
            self._status(str(error), True)

    def _ascii_decrypt(self):
        try:
            core, key = self._core_and_key()
            encoded = self.ascii_cipher.toPlainText().strip()
            if self.cipher_format.currentText() == "Hex":
                cipher = bytes.fromhex(encoded)
            else:
                cipher = base64.b64decode("".join(encoded.split()), validate=True)
            plaintext = core.decrypt_ascii(cipher, key, schedule=self.schedule)
            self.ascii_output.setPlainText(plaintext)
            self.ascii_count.setText(f"解密 {len(cipher)} 个密文字节；还原 {len(plaintext)} 个 ASCII 字符。")
            self._status("ASCII 解密完成。")
        except Exception as error:
            self.ascii_output.clear()
            self.ascii_count.setText("解密失败；请检查密文、表示方式与密钥。")
            self._status(str(error), True)

    def _start_brute(self):
        if self.worker is not None:
            self._status("已有计算正在运行，请等待完成。", True)
            return
        try:
            core = importlib.import_module("sdes")
            pairs = []
            for number, line in enumerate(self.pairs_input.toPlainText().splitlines(), 1):
                if not line.strip():
                    continue
                fields = line.replace(",", " ").replace("，", " ").split()
                if len(fields) != 2:
                    raise ValueError(f"第 {number} 行须填写两个 8 位二进制串，用空格分隔。")
                pairs.append((core.parse_bits(fields[0].strip(), 8), core.parse_bits(fields[1].strip(), 8)))
            if not pairs:
                raise ValueError("至少输入一个已知明密文对。")
            self.brute_progress.setValue(0)
            self.brute_summary.setText(f"正在穷举；已知明密文对：{len(pairs)}")
            self.brute_output.clear()
            self._launch_analysis("brute", pairs)
        except Exception as error:
            self._clear_analysis_result("brute")
            self._status(str(error), True)

    def _start_collision(self):
        if self.worker is not None:
            self._status("已有计算正在运行，请等待完成。", True)
            return
        try:
            core = importlib.import_module("sdes")
            plaintext = core.parse_bits(self.collision_input.text().strip(), 8)
            self.collision_output.clear()
            self.collision_summary.setText("正在计算全部 1024 个密钥……")
            self._launch_analysis("collision", plaintext)
        except Exception as error:
            self._clear_analysis_result("collision")
            self._status(str(error), True)

    def _clear_analysis_result(self, kind: str):
        """拒绝新输入时撤下旧结果，避免把旧报告当成这次的输出。"""
        self.last_task = None
        if kind == "brute":
            self.brute_output.clear()
            self.brute_progress.setValue(0)
            self.brute_summary.setText("输入无效；请修正明密文对后重试。")
            self.brute_timing.setText("开始时间：—\n结束时间：—\n实测耗时：—")
        else:
            self.collision_output.clear()
            self.collision_summary.setText("输入无效；请修正固定明文后重试。")
            self.collision_timing.setText("开始时间：—\n结束时间：—\n实测耗时：—")

    def _launch_analysis(self, kind: str, payload: object):
        if self.worker is not None:
            self._status("已有计算正在运行，请等待完成。", True)
            return
        worker = AnalysisWorker(kind, payload, self.schedule, self)
        self.worker = worker
        self.last_task = None
        for control in self._action_controls:
            control.setEnabled(False)
        worker.progress.connect(self._on_progress)
        worker.completed.connect(self._on_completed)
        worker.failed.connect(self._on_failed)
        worker.finished.connect(self._worker_finished)
        started_text = datetime.now().astimezone().isoformat(timespec="milliseconds")
        timing = self.brute_timing if kind == "brute" else self.collision_timing
        timing.setText(f"提交时间：{started_text}\n结束时间：计算中\n实测耗时：计算中")
        self._status("正在穷举 1024 个密钥……" if kind == "brute" else "正在计算碰撞分组……")
        self.taskStarted.emit(kind, {"submitted_at": started_text, "schedule": self.schedule})
        worker.start()

    def _on_progress(self, done: int, total: int, candidates: object, elapsed: float):
        self.brute_progress.setMaximum(total)
        self.brute_progress.setValue(done)
        count = len(candidates) if hasattr(candidates, "__len__") else candidates
        self.brute_summary.setText(f"已检查 {done}/{total} 个密钥；目前候选：{count}；实际进度耗时：{elapsed:.6f} 秒")
        if self.worker is not None:
            self.brute_timing.setText(
                f"开始时间：{self.worker.started_at}\n结束时间：计算中\n实测进度耗时：{elapsed:.9f} 秒"
            )
        self.taskProgress.emit("brute", done, total, candidates, elapsed)

    @staticmethod
    def _candidate_keys(result: dict) -> list | None:
        for name in ("candidates", "candidate_keys", "keys"):
            value = result.get(name)
            if isinstance(value, list):
                return value
        return None

    @staticmethod
    def _key_text(key: object) -> str:
        if isinstance(key, int):
            return f"{key:010b}"
        if isinstance(key, dict):
            return SDESWindow._key_text(key.get("key", key.get("key_int", key))) if ("key" in key or "key_int" in key) else _json(key)
        return str(key)

    def _on_completed(self, report: dict):
        self.last_task = report
        result = report["result"]
        kind = report["kind"]
        timing = self.brute_timing if kind == "brute" else self.collision_timing
        timing.setText(f"开始时间：{report['started_at']}\n结束时间：{report['finished_at']}\n实测耗时：{report['elapsed_seconds']:.9f} 秒")
        if kind == "brute":
            self.brute_progress.setValue(self.brute_progress.maximum())
            candidates = self._candidate_keys(result) if isinstance(result, dict) else None
            if candidates is not None:
                candidate_text = "\n".join(self._key_text(key) for key in candidates) or "无候选密钥。请检查明密文对和子密钥模式。"
                self.brute_summary.setText(f"破解完成；满足全部明密文对的候选密钥：{len(candidates)} 个。")
                self.brute_output.setPlainText("全部候选密钥（10 位二进制）\n" + candidate_text + "\n\n完整计算报告\n" + _json(result))
            else:
                self.brute_summary.setText("破解完成；完整候选信息见下方报告。")
                self.brute_output.setPlainText(_json(result))
        else:
            if isinstance(result, dict):
                groups = result.get("groups", result.get("collision_groups", []))
                count = len(groups) if hasattr(groups, "__len__") else "详见报告"
                statistics = result.get("statistics", {})
                self.collision_summary.setText(
                    f"分析完成；密文分组数：{count}；有碰撞的分组：{statistics.get('collision_buckets', '详见报告')}；"
                    f"最大组：{statistics.get('max_bucket_size', '详见报告')} 个密钥。不同密钥可以产生同一密文。"
                )
            else:
                self.collision_summary.setText("分析完成。不同密钥可以产生同一密文，全部分组见报告。")
            lines = []
            if isinstance(result, dict) and isinstance(result.get("groups"), list):
                lines.append("全部密文分组：密文 | 密钥个数 | 10 位密钥")
                for group in result["groups"]:
                    keys = group.get("key_bits") or [self._key_text(key) for key in group.get("keys", [])]
                    lines.append(f"{group.get('ciphertext', '?')} | {group.get('count', len(keys)):>2} | " + "  ".join(keys))
                lines.append("\n完整计算报告")
            self.collision_output.setPlainText("\n".join(lines) + "\n" + _json(result))
        self._status("暴力破解完成。所有候选已显示。" if kind == "brute" else "碰撞分析完成。所有分组已显示。")
        self.taskCompleted.emit(kind, report)

    def _on_failed(self, error: str):
        worker = self.worker
        kind = worker.kind if worker is not None else "unknown"
        self.last_task = None
        if kind in ("brute", "collision"):
            output = self.brute_output if kind == "brute" else self.collision_output
            summary = self.brute_summary if kind == "brute" else self.collision_summary
            timing = self.brute_timing if kind == "brute" else self.collision_timing
            output.clear()
            summary.setText("计算失败；请修正问题后重试。")
            timing.setText(
                f"开始时间：{worker.started_at}\n结束时间：{worker.finished_at}\n"
                f"失败前实测耗时：{worker.elapsed_seconds:.9f} 秒"
            )
        self._status(error, True)
        self.taskFailed.emit(kind, error)

    def _worker_finished(self):
        worker = self.worker
        self.worker = None
        for control in self._action_controls:
            control.setEnabled(True)
        if worker is not None:
            worker.deleteLater()

    def closeEvent(self, event):
        # 避免仍在运行的 QThread 随窗口销毁；1024 次运算可很快完成。
        if self.worker is not None and self.worker.isRunning():
            self.worker.wait()
        event.accept()


def main() -> int:
    app = QApplication.instance() or QApplication(sys.argv)
    configure_application_fonts(app)
    window = SDESWindow()
    window.show()
    return app.exec_()


if __name__ == "__main__":
    raise SystemExit(main())
