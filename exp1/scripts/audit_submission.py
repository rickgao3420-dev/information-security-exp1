"""只读核对交付材料：文档链接、测试记录、源码和计算/GUI证据摘要。"""

from pathlib import Path
from datetime import datetime
import hashlib
import json
import math
import re
from urllib.parse import unquote


ROOT = Path(__file__).resolve().parents[1]
GUI_ROOT = ROOT / "artifacts/gui"


def main():
    errors = []

    def read_json(relative):
        try:
            data = json.loads((ROOT / relative).read_text(encoding="utf-8"))
            if not isinstance(data, dict):
                raise ValueError("顶层必须为 JSON 对象")
            return data
        except (OSError, ValueError) as error:
            errors.append(f"无法读取 {relative}：{error}")
            return {}

    def local_path(base, relative):
        if not isinstance(relative, str):
            raise ValueError("文件路径必须为字符串")
        candidate = (base / relative.replace("\\", "/")).resolve()
        if not candidate.is_relative_to(base.resolve()):
            raise ValueError("文件路径超出证据目录")
        return candidate

    def mapping_field(data, field):
        value = data.get(field, {})
        if not isinstance(value, dict):
            errors.append(f"{field} 字段必须为对象")
            return {}
        return value

    def list_field(data, field):
        value = data.get(field, [])
        if not isinstance(value, list):
            errors.append(f"{field} 字段必须为数组")
            return []
        return value

    def check_sources(label, entries, required):
        if not isinstance(entries, dict) or not entries:
            errors.append(f"{label} 缺少源码摘要；请重新生成证据")
            return 0
        for relative in sorted(required - entries.keys()):
            errors.append(f"{label} 缺少源码摘要：{relative}；请重新生成证据")
        checked = 0
        for relative, expected in entries.items():
            try:
                path = local_path(ROOT, relative)
                if hashlib.sha256(path.read_bytes()).hexdigest() != expected:
                    errors.append(f"{label} 生成后源码发生变化：{relative}")
                checked += 1
            except (OSError, ValueError) as error:
                errors.append(f"{label} 源码缺失或路径无效：{relative} ({error})")
        return checked

    def check_files(label, base, entries):
        if not isinstance(entries, dict) or not entries:
            errors.append(f"{label} 缺少文件摘要；请重新生成证据")
            return 0
        checked = 0
        for relative, expected in entries.items():
            try:
                path = local_path(base, relative)
                if not isinstance(expected, dict):
                    raise ValueError("摘要条目必须为对象")
                if path.stat().st_size != expected.get("size_bytes"):
                    errors.append(f"{label} 文件大小变化：{relative}")
                if hashlib.sha256(path.read_bytes()).hexdigest() != expected.get("sha256"):
                    errors.append(f"{label} 文件摘要变化：{relative}")
                checked += 1
            except (OSError, ValueError) as error:
                errors.append(f"{label} 文件缺失或路径无效：{relative} ({error})")
        return checked

    summary = read_json("results/summary.json")
    unit_tests = read_json("results/unit_tests.json")
    evidence = read_json("results/evidence_manifest.json")
    gui = read_json("artifacts/gui/capture_manifest.json")
    tests = mapping_field(summary, "unit_tests")
    names = list_field(tests, "test_names")
    count = tests.get("tests_run", 0)
    if not (tests.get("successful") is True and isinstance(count, int) and count > 0
            and isinstance(names, list) and all(isinstance(name, str) for name in names)
            and len(names) == count and len(set(names)) == count
            and all(tests.get(field) == 0 for field in ("failures", "errors", "skipped"))):
        errors.append("单元测试记录须全部通过、非零且 tests_run 与 test_names 对应")
    if tests != unit_tests:
        errors.append("summary.json 与 unit_tests.json 的测试记录不一致")
    if tests.get("exhaustive_test") not in names or tests.get("total_exhaustive_encryptions_compared") != 524288:
        errors.append("双模式完整覆盖记录缺失")
    gui_tests = list_field(gui, "tests")
    if len(gui_tests) != 26 or not all(
            isinstance(item, dict) and item.get("passed") is True for item in gui_tests):
        errors.append("GUI 测试记录须为 26 项且全部通过")
    if gui.get("schema") != "sdes-gui-evidence-v3":
        errors.append("GUI 证据版本不匹配；请重新生成证据")

    source_files = [*ROOT.glob("*.py"), *(ROOT / "scripts").glob("*.py"), *(ROOT / "tests").glob("*.py")]
    source_files.append(ROOT / "requirements.txt")
    required_sources = {path.relative_to(ROOT).as_posix() for path in source_files}
    source_count = check_sources("计算证据", summary.get("source_sha256"), required_sources)
    gui_source_count = check_sources("GUI 证据", gui.get("source_sha256"),
                                     {"gui.py", "sdes.py", "analysis_tools.py", "scripts/capture_gui.py", "requirements.txt"})
    result_files = mapping_field(evidence, "files")
    result_count = check_files("计算证据", ROOT / "results", result_files)
    gui_files = mapping_field(gui, "files")
    gui_file_count = check_files("GUI 证据", GUI_ROOT, gui_files)
    required_results = {"summary.json", "unit_tests.json", "unit_tests.txt", "hand_vectors.json",
                        "cross_vectors.json", "cross_vectors.csv", "ascii_vectors.json"}
    for schedule in ("assignment", "cumulative"):
        required_results.update(f"{prefix}_{schedule}.{suffix}" for prefix, suffix in (
            ("brute_force", "json"), ("collision_buckets", "json"), ("collision_examples", "json"),
            ("collision_scan", "json"), ("collision_scan", "csv"), ("equivalent_keys", "json"),
            ("full_mapping", "bin")))
    for relative in sorted(required_results):
        if relative not in result_files:
            errors.append(f"计算证据清单缺少：{relative}")

    progress_events = list_field(gui, "progress_events")
    if (len(progress_events) < 3
            or not isinstance(progress_events[0], dict)
            or progress_events[0].get("state") != "started"
            or not isinstance(progress_events[-1], dict)
            or progress_events[-1].get("state") != "completed"
            or not any(isinstance(event, dict) and event.get("state") == "progress"
                       for event in progress_events)):
        errors.append("GUI 破解进度须包含开始、真实进度信号和完成记录")
    previous_done = -1
    previous_elapsed = -1.0
    for event in progress_events:
        if not isinstance(event, dict):
            errors.append("GUI 破解进度条目必须为对象")
            continue
        try:
            observed_at = datetime.fromisoformat(event["observed_at"])
            done, total, elapsed = event["done"], event["total"], event["signal_elapsed_seconds"]
            candidates = event["candidates"]
            if (event.get("state") not in {"started", "progress", "completed"}
                    or observed_at.utcoffset() is None
                    or not isinstance(done, int) or total != 1024
                    or not previous_done <= done <= total
                    or not isinstance(candidates, int) or not 0 <= candidates <= done
                    or not isinstance(elapsed, (int, float)) or not math.isfinite(elapsed)
                    or not previous_elapsed <= elapsed):
                raise ValueError("进度、候选数、时间戳或实测耗时无效")
            previous_done, previous_elapsed = done, elapsed
        except (KeyError, TypeError, ValueError) as error:
            errors.append(f"GUI 破解进度记录无效：{error}")
    brute = mapping_field(gui, "brute_force")
    if progress_events and isinstance(progress_events[-1], dict):
        completed = progress_events[-1]
        if completed.get("done") != 1024 or any(
                completed.get(field) != brute.get(field)
                for field in ("started_at", "finished_at", "elapsed_seconds")):
            errors.append("GUI 破解完成记录与真实计算报告不一致")
    screenshots = list_field(gui, "screenshots")
    required_screenshots = {
        "01_bits_encrypt.png", "02_bits_decrypt.png", "03_ascii_hex.png",
        "04_ascii_base64.png", "05_brute_single_pair.png", "06_brute_multiple_pairs.png",
        "07_collision.png", "08_invalid_input.png", "09_invalid_ascii.png", "10_cumulative_mode.png",
    }
    if len(screenshots) != 10 or set(gui_files) != required_screenshots:
        errors.append("GUI 证据须包含 10 张功能截图及对应摘要")
    for relative in screenshots:
        try:
            path = local_path(ROOT, relative)
            if not path.is_file():
                errors.append(f"GUI 截图缺失：{relative}")
            if not path.is_relative_to(GUI_ROOT) or path.relative_to(GUI_ROOT).as_posix() not in gui_files:
                errors.append(f"GUI 截图缺少摘要：{relative}")
        except ValueError as error:
            errors.append(f"GUI 截图路径无效：{relative} ({error})")

    checked_links = 0
    documents = [*ROOT.glob("*.md"), *(ROOT / "docs").rglob("*.md")]
    for path in sorted(documents):
        for raw_target in re.findall(r"\]\(([^)]+)\)", path.read_text(encoding="utf-8")):
            target = raw_target.strip().strip("<>")
            if target.startswith(("https://", "http://", "#", "mailto:")):
                continue
            checked_links += 1
            target = unquote(target.split("#", 1)[0])
            if not (path.parent / target).exists():
                errors.append(f"链接缺失：{path.relative_to(ROOT)} -> {target}")
    result = {"passed": not errors, "local_links_checked": checked_links,
              "algorithm_tests": count, "gui_checks": len(gui_tests),
              "source_hashes_checked": source_count, "result_files_checked": result_count,
              "gui_source_hashes_checked": gui_source_count, "gui_files_checked": gui_file_count,
              "progress_events_checked": len(progress_events), "errors": errors}
    print(json.dumps(result, ensure_ascii=False, indent=2))
    return 0 if not errors else 1


if __name__ == "__main__":
    raise SystemExit(main())
