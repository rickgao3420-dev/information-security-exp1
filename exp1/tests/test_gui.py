"""GUI 错误状态与后台任务的回归测试；无 PyQt5 时跳过。"""

import os
import threading
import time
import unittest
from unittest.mock import patch

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

try:
    from PyQt5.QtTest import QTest
    from PyQt5.QtWidgets import QApplication
    from gui import SDESWindow
except ImportError:
    SDESWindow = None

import analysis_tools
import sdes


@unittest.skipIf(SDESWindow is None, "GUI 回归测试需要 PyQt5")
class GuiStateTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.app = QApplication.instance() or QApplication([])

    def setUp(self):
        self.window = SDESWindow()
        self.pair = (170, sdes.encrypt_block(170, 0b1010000010))

    def tearDown(self):
        self.window.close()
        self.app.processEvents()
        self.window.deleteLater()
        self.app.processEvents()

    def _valid_pairs(self):
        self.window.pairs_input.setPlainText(
            f"{self.pair[0]:08b} {self.pair[1]:08b}"
        )

    def _wait_finished(self):
        deadline = time.perf_counter() + 5
        while self.window.worker is not None:
            self.app.processEvents()
            if time.perf_counter() >= deadline:
                self.fail("GUI 后台任务未在 5 秒内结束")
            QTest.qWait(1)
        self.app.processEvents()

    def test_bad_ascii_input_replaces_successful_count(self):
        self.window._ascii_encrypt()
        self.window._ascii_decrypt()
        self.assertEqual(self.window.ascii_output.toPlainText(), "Hello SDES!")

        self.window.ascii_cipher.setPlainText("ZZ")
        self.window._ascii_decrypt()
        self.assertEqual(self.window.ascii_output.toPlainText(), "")
        self.assertIn("解密失败", self.window.ascii_count.text())

        self.window.ascii_input.setPlainText("中文")
        self.window._ascii_encrypt()
        self.assertEqual(self.window.ascii_cipher.toPlainText(), "")
        self.assertIn("加密失败", self.window.ascii_count.text())

    def test_bad_pairs_remove_previous_successful_report(self):
        self._valid_pairs()
        self.window._start_brute()
        self._wait_finished()
        self.assertIsNotNone(self.window.last_task)
        self.assertIn("全部候选密钥", self.window.brute_output.toPlainText())

        self.window.pairs_input.setPlainText("10101010 0")
        self.window._start_brute()
        self.assertIsNone(self.window.worker)
        self.assertIsNone(self.window.last_task)
        self.assertEqual(self.window.brute_output.toPlainText(), "")
        self.assertEqual(self.window.brute_progress.value(), 0)
        self.assertIn("输入无效", self.window.brute_summary.text())
        self.assertNotIn("结束时间：计算中", self.window.brute_timing.text())

    def test_bad_collision_input_removes_previous_report(self):
        self.window._start_collision()
        self._wait_finished()
        self.assertIn("全部密文分组", self.window.collision_output.toPlainText())

        self.window.collision_input.setText("123")
        self.window._start_collision()
        self.assertIsNone(self.window.worker)
        self.assertIsNone(self.window.last_task)
        self.assertEqual(self.window.collision_output.toPlainText(), "")
        self.assertIn("输入无效", self.window.collision_summary.text())

    def test_worker_failure_finishes_timing_and_restores_controls(self):
        self._valid_pairs()
        with patch.object(analysis_tools, "brute_force", side_effect=RuntimeError("测试计算故障")):
            self.window._start_brute()
            self._wait_finished()
        self.assertIsNone(self.window.last_task)
        self.assertIn("测试计算故障", self.window.status_label.text())
        self.assertIn("计算失败", self.window.brute_summary.text())
        self.assertNotIn("计算中", self.window.brute_timing.text())
        self.assertIn("失败前实测耗时", self.window.brute_timing.text())
        self.assertTrue(all(control.isEnabled() for control in self.window._action_controls))

        # 一次线程失败后仍可重新运行，不能把界面锁在失败状态。
        self.window._start_brute()
        self._wait_finished()
        self.assertEqual(self.window.last_task["result"]["tested_keys"], 1024)

    def test_running_task_freezes_inputs_and_rejects_duplicate_start(self):
        release = threading.Event()
        actual_brute_force = analysis_tools.brute_force

        def held_brute_force(*args, **kwargs):
            if not release.wait(2):
                raise RuntimeError("测试同步超时")
            return actual_brute_force(*args, **kwargs)

        self._valid_pairs()
        with patch.object(analysis_tools, "brute_force", side_effect=held_brute_force):
            try:
                self.window._start_brute()
                original_worker = self.window.worker
                self.assertTrue(all(not control.isEnabled() for control in self.window._action_controls))
                self.window.brute_output.setPlainText("正在计算的状态")
                self.window._start_brute()
                self.assertIs(self.window.worker, original_worker)
                self.assertEqual(self.window.brute_output.toPlainText(), "正在计算的状态")
                self.assertIn("已有计算正在运行", self.window.status_label.text())
            finally:
                release.set()
                self._wait_finished()
        self.assertIn(0b1010000010, self.window.last_task["result"]["candidate_keys"])
        self.assertTrue(all(control.isEnabled() for control in self.window._action_controls))


if __name__ == "__main__":
    unittest.main()
