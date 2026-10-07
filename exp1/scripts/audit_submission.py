"""只读核对交付材料：文档链接、已保存的测试记录和源码摘要。"""

from pathlib import Path
import hashlib
import json
import re


ROOT = Path(__file__).resolve().parents[1]


def main():
    errors = []
    summary = json.loads((ROOT / "results/summary.json").read_text(encoding="utf-8"))
    gui = json.loads((ROOT / "artifacts/gui/capture_manifest.json").read_text(encoding="utf-8"))
    tests = summary["unit_tests"]
    if not (tests["successful"] and tests["tests_run"] == 29 and
            tests["failures"] == tests["errors"] == tests["skipped"] == 0):
        errors.append("算法测试保存记录不符合预期")
    if tests["total_exhaustive_encryptions_compared"] != 524288:
        errors.append("双模式完整覆盖记录缺失")
    if len(gui["tests"]) != 26 or not all(item["passed"] for item in gui["tests"]):
        errors.append("GUI 测试保存记录不符合预期")
    for relative, expected in summary["source_sha256"].items():
        if hashlib.sha256((ROOT / relative).read_bytes()).hexdigest() != expected:
            errors.append(f"测试后源码发生变化：{relative}")
    checked_links = 0
    for path in sorted(ROOT.rglob("*.md")):
        for target in re.findall(r"\]\(([^)]+)\)", path.read_text(encoding="utf-8")):
            if target.startswith(("https://", "http://", "#")):
                continue
            checked_links += 1
            target = target.split("#", 1)[0]
            if not (path.parent / target).exists():
                errors.append(f"链接缺失：{path.relative_to(ROOT)} -> {target}")
    for frame in gui["gif"]["frames"]:
        if not (ROOT / "artifacts/gui" / frame["screenshot"].replace("\\", "/")).is_file():
            errors.append(f"GIF 原始帧缺失：{frame['screenshot']}")
    result = {"passed": not errors, "local_links_checked": checked_links,
              "algorithm_tests": tests["tests_run"], "gui_checks": len(gui["tests"]),
              "source_hashes_checked": len(summary["source_sha256"]),
              "gif_frames_checked": len(gui["gif"]["frames"]), "errors": errors}
    print(json.dumps(result, ensure_ascii=False, indent=2))
    return 0 if not errors else 1


if __name__ == "__main__":
    raise SystemExit(main())
