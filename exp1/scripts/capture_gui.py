"""在 offscreen 模式测试本应用控件并保存真实窗口截图与进度记录。

运行：python scripts/capture_gui.py
窗口截图来自本应用 QWidget.grab；进度和计时来自真实 worker 信号。
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import sys
import time
from datetime import datetime
from pathlib import Path

os.environ["QT_QPA_PLATFORM"] = "offscreen"
PROJECT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT))

from PyQt5.QtCore import Qt
from PyQt5.QtTest import QTest
from PyQt5.QtWidgets import QApplication, QPushButton

from gui import SDESWindow, configure_application_fonts
from sdes import encrypt_block, encrypt_ascii, format_bits, parse_bits


def timestamp() -> str:
    return datetime.now().astimezone().isoformat(timespec="milliseconds")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, default=PROJECT / "artifacts" / "gui")
    args = parser.parse_args()
    output = args.output.resolve()
    output.mkdir(parents=True, exist_ok=True)
    app = QApplication.instance() or QApplication([])
    configure_application_fonts(app)
    window = SDESWindow()
    window.show()
    app.processEvents()
    tests = []
    screenshots = []
    screenshot_files = []
    progress_events = []

    def record(name: str, condition: bool, details: object = None):
        tests.append({"name": name, "passed": bool(condition), "details": details})
        if not condition:
            raise AssertionError(f"GUI 验证失败：{name}，{details}")

    def shot(name: str):
        app.processEvents()
        path = output / name
        if not window.grab().save(str(path), "PNG"):
            raise RuntimeError("无法保存截图：" + str(path))
        screenshots.append(path.relative_to(PROJECT).as_posix() if path.is_relative_to(PROJECT) else str(path))
        screenshot_files.append(path)
        return path

    def click(button):
        if button is None:
            raise AssertionError("未找到目标按钮。")
        QTest.mouseClick(button, Qt.LeftButton)
        app.processEvents()

    def fill_line(field, value: str):
        field.setFocus()
        field.selectAll()
        QTest.keyClicks(field, value)

    def wait_worker():
        deadline = time.perf_counter() + 30
        while window.worker is not None:
            # 只让 Qt 处理真实 worker 信号，不在计算线程中插入延时。
            app.processEvents()
            if time.perf_counter() > deadline:
                raise TimeoutError("后台计算未在 30 秒内结束。")
            QTest.qWait(1)
        app.processEvents()
        record("worker 成功返回", window.last_task is not None, window.status_label.text())
        return window.last_task

    def progress_event(state: str, done: int, total: int, candidates: object,
                       elapsed: float, metadata=None, report=None):
        event = {
            "state": state, "done": done, "total": total, "candidates": candidates,
            "signal_elapsed_seconds": elapsed, "observed_at": timestamp(),
        }
        if metadata is not None:
            event["submission"] = metadata
        if report is not None:
            event.update({
                "started_at": report["started_at"],
                "finished_at": report["finished_at"],
                "elapsed_seconds": report["elapsed_seconds"],
            })
        progress_events.append(event)

    key = parse_bits("1010000010", 10)
    plaintext = parse_bits("10101010", 8)
    ciphertext = encrypt_block(plaintext, key, "assignment")
    fill_line(window.key_input, "1010000010")
    fill_line(window.bits_input, "10101010")
    click(window.findChild(QPushButton, "bitsEncryptButton"))
    record("默认作业公式位串加密", window.bits_output.text() == format_bits(ciphertext, 8), window.bits_output.text())
    record("中间步骤可见", '"rounds"' in window.trace_output.toPlainText() and '"SBOX1"' in window.trace_output.toPlainText())
    shot("01_bits_encrypt.png")
    fill_line(window.bits_input, format_bits(ciphertext, 8))
    click(window.findChild(QPushButton, "bitsDecryptButton"))
    record("默认作业公式位串解密", window.bits_output.text() == "10101010")
    shot("02_bits_decrypt.png")

    window.tabs.setCurrentIndex(1)
    window.ascii_input.setPlainText("Hello SDES!\nASCII 123")
    click(window.findChild(QPushButton, "asciiEncryptButton"))
    record("ASCII Hex 密文无丢失", bytes.fromhex(window.ascii_cipher.toPlainText()) == encrypt_ascii("Hello SDES!\nASCII 123", key, "assignment"))
    click(window.findChild(QPushButton, "asciiDecryptButton"))
    record("ASCII Hex 往返", window.ascii_output.toPlainText() == window.ascii_input.toPlainText())
    shot("03_ascii_hex.png")
    window.cipher_format.setCurrentIndex(1)
    click(window.findChild(QPushButton, "asciiEncryptButton"))
    click(window.findChild(QPushButton, "asciiDecryptButton"))
    record("ASCII Base64 往返", window.ascii_output.toPlainText() == window.ascii_input.toPlainText())
    shot("04_ascii_base64.png")

    window.tabs.setCurrentIndex(2)
    window.pairs_input.setPlainText(f"{format_bits(plaintext, 8)} {format_bits(ciphertext, 8)}")

    def on_started(kind, metadata):
        if kind == "brute":
            progress_event("started", 0, 1024, 0, 0.0, metadata=metadata)

    def on_progress(kind, done, total, candidates, elapsed):
        if kind == "brute":
            progress_event("progress", done, total, candidates, elapsed)

    def on_completed(kind, report):
        if kind == "brute":
            progress_event("completed", 1024, 1024, report["result"]["candidate_count"],
                           report["elapsed_seconds"], report=report)

    window.taskStarted.connect(on_started)
    window.taskProgress.connect(on_progress)
    window.taskCompleted.connect(on_completed)
    click(window.findChild(QPushButton, "bruteButton"))
    report = wait_worker()
    brute_report = report
    record("单对破解显示全部候选", key in report["result"]["candidate_keys"] and all(bits in window.brute_output.toPlainText() for bits in report["result"]["candidate_key_bits"]))
    record("破解实测计时可见", report["elapsed_seconds"] > 0 and report["started_at"] in window.brute_timing.text() and report["finished_at"] in window.brute_timing.text())
    shot("05_brute_single_pair.png")
    window.taskStarted.disconnect(on_started)
    window.taskProgress.disconnect(on_progress)
    window.taskCompleted.disconnect(on_completed)

    pair_plaintexts = [0, 15, 85, 170, 255]
    window.pairs_input.setPlainText("\n".join(f"{format_bits(p, 8)} {format_bits(encrypt_block(p, key, 'assignment'), 8)}" for p in pair_plaintexts))
    click(window.findChild(QPushButton, "bruteButton"))
    multi_report = wait_worker()
    record("多对破解同时满足全部证据", key in multi_report["result"]["candidate_keys"] and all(all(encrypt_block(p, k, "assignment") == encrypt_block(p, key, "assignment") for p in pair_plaintexts) for k in multi_report["result"]["candidate_keys"]))
    shot("06_brute_multiple_pairs.png")

    window.tabs.setCurrentIndex(3)
    click(window.findChild(QPushButton, "collisionButton"))
    collision_report = wait_worker()
    record("碰撞分组覆盖全部 1024 个密钥", sum(group["count"] for group in collision_report["result"]["groups"]) == 1024)
    record("真实不同密钥同密文", any(group["count"] > 1 for group in collision_report["result"]["groups"]))
    shot("07_collision.png")

    window.tabs.setCurrentIndex(0)
    for bad_value in ("101", "101010102", "abcd0101"):
        fill_line(window.bits_input, bad_value)
        click(window.findChild(QPushButton, "bitsEncryptButton"))
        record("非法 8 位输入被拒绝 " + bad_value, window.bits_output.text() == "" and "错误" in window.status_label.text())
    fill_line(window.bits_input, "10101010")
    fill_line(window.key_input, "101000001")
    click(window.findChild(QPushButton, "bitsEncryptButton"))
    record("非法密钥长度被拒绝", window.bits_output.text() == "" and "错误" in window.status_label.text())
    shot("08_invalid_input.png")
    fill_line(window.key_input, "1010000010")

    window.tabs.setCurrentIndex(1)
    window.ascii_input.setPlainText("中文不是 ASCII")
    click(window.findChild(QPushButton, "asciiEncryptButton"))
    record("非 ASCII 输入被拒绝", "错误" in window.status_label.text() and window.ascii_cipher.toPlainText() == "")
    shot("09_invalid_ascii.png")
    window.ascii_cipher.setPlainText("NOT_VALID_BASE64??")
    click(window.findChild(QPushButton, "asciiDecryptButton"))
    record("非法 Base64 被拒绝", "错误" in window.status_label.text())
    window.cipher_format.setCurrentIndex(0)
    window.ascii_cipher.setPlainText("ZZ")
    click(window.findChild(QPushButton, "asciiDecryptButton"))
    record("非法 Hex 被拒绝", "错误" in window.status_label.text())

    window.tabs.setCurrentIndex(2)
    window.pairs_input.clear()
    click(window.findChild(QPushButton, "bruteButton"))
    record("空明密文对被拒绝", window.worker is None and "错误" in window.status_label.text())
    window.pairs_input.setPlainText("10101010 0")
    click(window.findChild(QPushButton, "bruteButton"))
    record("非法明密文对被拒绝", window.worker is None and "错误" in window.status_label.text())

    window.schedule_combo.setCurrentIndex(1)
    record("课件模式同步并清除旧结果", window.schedule == "cumulative" and window.brute_output.toPlainText() == "" and "1、3" in window.schedule_note.text())
    window.tabs.setCurrentIndex(0)
    fill_line(window.bits_input, "10101010")
    click(window.findChild(QPushButton, "bitsEncryptButton"))
    cumulative_ciphertext = encrypt_block(plaintext, key, "cumulative")
    record("课件模式位串加密", window.bits_output.text() == format_bits(cumulative_ciphertext, 8))
    fill_line(window.bits_input, format_bits(cumulative_ciphertext, 8))
    click(window.findChild(QPushButton, "bitsDecryptButton"))
    record("课件模式位串往返", window.bits_output.text() == "10101010")
    shot("10_cumulative_mode.png")

    manifest = {
        "schema": "sdes-gui-evidence-v3",
        "captured_at": timestamp(), "platform": os.environ["QT_QPA_PLATFORM"],
        "window_size": [window.width(), window.height()],
        "tests": tests, "screenshots": screenshots,
        "source_sha256": {
            name: hashlib.sha256((PROJECT / name).read_bytes()).hexdigest()
            for name in ("gui.py", "sdes.py", "analysis_tools.py", "scripts/capture_gui.py", "requirements.txt")
        },
        "files": {
            path.relative_to(output).as_posix(): {
                "size_bytes": path.stat().st_size,
                "sha256": hashlib.sha256(path.read_bytes()).hexdigest(),
            }
            for path in sorted(screenshot_files)
        },
        "brute_force": brute_report, "multiple_pairs": multi_report,
        "collision_statistics": collision_report["result"]["statistics"],
        "progress_events": progress_events,
    }
    manifest_path = output / "capture_manifest.json"
    manifest_path.write_text(json.dumps(manifest, ensure_ascii=False, indent=2), encoding="utf-8")
    window.close()
    print(json.dumps({
        "passed_tests": len(tests), "screenshots": len(screenshots),
        "progress_events": len(progress_events),
        "actual_brute_seconds": brute_report["elapsed_seconds"],
        "manifest": str(manifest_path),
    }, ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
