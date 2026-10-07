"""S-DES 的已知明文穷举攻击、碰撞与等价密钥分析。"""

from __future__ import annotations

from collections import Counter, defaultdict
from collections.abc import Iterable
from datetime import datetime
from time import perf_counter
from typing import Any, Callable

try:
    from .sdes import encrypt_block, format_bits, generate_subkeys, _crypt_with_subkeys
except ImportError:
    from sdes import encrypt_block, format_bits, generate_subkeys, _crypt_with_subkeys

Progress = Callable[[int, int, int, float], None]
TOTAL_KEYS = 1024


def _timestamp() -> str:
    return datetime.now().astimezone().isoformat(timespec="milliseconds")


def _validate_schedule(schedule: str) -> None:
    generate_subkeys(0, schedule)


def brute_force(pairs: Iterable[tuple[int, int]], schedule: str = "assignment",
                progress: Progress | None = None) -> dict[str, Any]:
    """枚举全部 1024 个密钥，保留同时满足所有明密文对的全部候选。

    多个候选意味着当前证据不足以确定唯一密钥；零候选意味着输入对
    与选定调度不相容。progress(done,total,candidates,elapsed) 在开始
    及每个密钥检查结束时调用，GUI 可据此更新进度或主动取消。
    """
    _validate_schedule(schedule)
    checked_pairs = []
    try:
        pair_iterator = iter(pairs)
    except TypeError as error:
        raise ValueError("输入必须是 (明文整数, 密文整数) 对的可迭代对象。") from error
    for pair in pair_iterator:
        if not isinstance(pair, (tuple, list)) or len(pair) != 2:
            raise ValueError("每组输入必须是 (明文整数, 密文整数)。")
        plaintext, ciphertext = pair
        format_bits(plaintext, 8)
        format_bits(ciphertext, 8)
        checked_pairs.append((plaintext, ciphertext))
    # 迭代器本身始终为真，必须检查收集后的数据，避免空输入匹配全部密钥。
    if not checked_pairs:
        raise ValueError("至少需要一组已知的 8 位明文和密文。")
    started_at = _timestamp()
    start = perf_counter()
    candidates = []
    if progress is not None:
        progress(0, TOTAL_KEYS, 0, 0.0)
    for key in range(TOTAL_KEYS):
        first, second = generate_subkeys(key, schedule)
        if all(_crypt_with_subkeys(plain, first, second) == cipher for plain, cipher in checked_pairs):
            candidates.append(key)
        if progress is not None:
            progress(key + 1, TOTAL_KEYS, len(candidates), perf_counter() - start)
    elapsed = perf_counter() - start
    return {
        "schedule": schedule, "pairs": [{"plaintext": format_bits(p, 8), "ciphertext": format_bits(c, 8),
                                             "plaintext_int": p, "ciphertext_int": c} for p, c in checked_pairs],
        "candidate_keys": candidates, "candidate_key_bits": [format_bits(key, 10) for key in candidates],
        "candidate_count": len(candidates), "tested_keys": TOTAL_KEYS, "total_keys": TOTAL_KEYS,
        "elapsed_seconds": elapsed, "started_at": started_at, "finished_at": _timestamp(),
    }


def _bucket_summary(bucket_sizes: Iterable[int]) -> dict[str, Any]:
    """只按桶大小统计；全明文扫描不必为每个桶保留全部密钥。"""
    counts = list(bucket_sizes)
    histogram = Counter(counts)
    return {
        "distinct_ciphertexts": len(counts), "nonempty_buckets": len(counts),
        "empty_buckets": 256 - len(counts), "min_bucket_size": min(counts),
        "max_bucket_size": max(counts), "mean_bucket_size": TOTAL_KEYS / len(counts),
        "collision_buckets": sum(count > 1 for count in counts),
        "keys_in_collision_buckets": sum(count for count in counts if count > 1),
        "collision_key_pairs": sum(count * (count - 1) // 2 for count in counts),
        "bucket_size_histogram": {str(size): histogram[size] for size in sorted(histogram)},
    }


def collision_analysis(plaintext: int, schedule: str = "assignment") -> dict[str, Any]:
    """固定一个明文，用全部 1024 个密钥加密并按密文分桶。"""
    format_bits(plaintext, 8)
    _validate_schedule(schedule)
    started_at = _timestamp()
    start = perf_counter()
    buckets: dict[int, list[int]] = defaultdict(list)
    for key in range(TOTAL_KEYS):
        buckets[encrypt_block(plaintext, key, schedule)].append(key)
    groups = [{"ciphertext": format_bits(ciphertext, 8), "ciphertext_int": ciphertext,
               "count": len(keys), "keys": keys, "key_bits": [format_bits(key, 10) for key in keys]}
              for ciphertext, keys in sorted(buckets.items())]
    examples = [{"plaintext": format_bits(plaintext, 8), "ciphertext": group["ciphertext"],
                 "keys": group["keys"][:2], "key_bits": group["key_bits"][:2], "bucket_size": group["count"]}
                for group in groups if group["count"] > 1][:10]
    return {
        "plaintext": format_bits(plaintext, 8), "plaintext_int": plaintext, "schedule": schedule,
        "total_keys": TOTAL_KEYS, "groups": groups,
        "ciphertext_groups": {group["ciphertext"]: group["key_bits"] for group in groups},
        "collision_examples": examples, "statistics": _bucket_summary(len(keys) for keys in buckets.values()),
        "elapsed_seconds": perf_counter() - start, "started_at": started_at, "finished_at": _timestamp(),
    }


def scan_all_plaintexts(schedule: str = "assignment", progress: Progress | None = None) -> dict[str, Any]:
    """扫描全部 256 个明文；保存每个明文的桶统计，而非重复完整分组。"""
    _validate_schedule(schedule)
    started_at = _timestamp()
    start = perf_counter()
    subkeys = [generate_subkeys(key, schedule) for key in range(TOTAL_KEYS)]
    summaries = []
    collision_plaintexts = 0
    if progress is not None:
        progress(0, 256, 0, 0.0)
    for plaintext in range(256):
        bucket_sizes = Counter(_crypt_with_subkeys(plaintext, first, second) for first, second in subkeys)
        summary = _bucket_summary(bucket_sizes.values())
        summaries.append({"plaintext": format_bits(plaintext, 8), "plaintext_int": plaintext,
                          **summary})
        collision_plaintexts += summary["collision_buckets"] > 0
        if progress is not None:
            progress(plaintext + 1, 256, collision_plaintexts, perf_counter() - start)
    return {
        "schedule": schedule, "total_plaintexts": 256, "total_keys": TOTAL_KEYS,
        "encryptions": 256 * TOTAL_KEYS, "plaintexts": summaries,
        "all_plaintexts_have_collisions": all(item["collision_buckets"] > 0 for item in summaries),
        "min_distinct_ciphertexts": min(item["distinct_ciphertexts"] for item in summaries),
        "max_distinct_ciphertexts": max(item["distinct_ciphertexts"] for item in summaries),
        "largest_bucket_size": max(item["max_bucket_size"] for item in summaries),
        "elapsed_seconds": perf_counter() - start, "started_at": started_at, "finished_at": _timestamp(),
    }


def equivalent_key_analysis(schedule: str = "assignment", progress: Progress | None = None) -> dict[str, Any]:
    """按全部 256 个明文的加密置换分组，严格识别全局等价密钥。

    一个明文的碰撞不等于两个密钥完全等价。只有完整的 256 字节
    映射完全相同，才归入同一等价类。
    """
    _validate_schedule(schedule)
    started_at = _timestamp()
    start = perf_counter()
    signatures: dict[bytes, list[int]] = defaultdict(list)
    if progress is not None:
        progress(0, TOTAL_KEYS, 0, 0.0)
    for key in range(TOTAL_KEYS):
        first, second = generate_subkeys(key, schedule)
        signature = bytes(_crypt_with_subkeys(plaintext, first, second) for plaintext in range(256))
        signatures[signature].append(key)
        if progress is not None:
            progress(key + 1, TOTAL_KEYS, len(signatures), perf_counter() - start)
    groups = [{"keys": keys, "key_bits": [format_bits(key, 10) for key in keys], "count": len(keys)}
              for keys in signatures.values()]
    groups.sort(key=lambda group: group["keys"][0])
    equivalent_groups = [group for group in groups if group["count"] > 1]
    return {
        "schedule": schedule, "total_keys": TOTAL_KEYS, "plaintexts_per_key": 256,
        "encryptions": TOTAL_KEYS * 256, "distinct_permutations": len(groups),
        "equivalence_groups": groups, "equivalent_groups": equivalent_groups,
        "equivalent_group_count": len(equivalent_groups),
        "keys_in_equivalent_groups": sum(group["count"] for group in equivalent_groups),
        "largest_equivalence_group": max(group["count"] for group in groups),
        "elapsed_seconds": perf_counter() - start, "started_at": started_at, "finished_at": _timestamp(),
    }


# 保留直观别名，便于实验脚本与报告生成器调用。
all_plaintext_collision_analysis = scan_all_plaintexts
analyze_equivalent_keys = equivalent_key_analysis

__all__ = ["brute_force", "collision_analysis", "scan_all_plaintexts", "equivalent_key_analysis",
           "all_plaintext_collision_analysis", "analyze_equivalent_keys"]
