"""实验一：按作业参数实现的教学用 S-DES。

分组为 8 位，密钥为 10 位。这里使用石墨作业给出的 S 盒，
不能替换成其他教材中的同名 S 盒。只使用 Python 标准库。

assignment 调度按公式 K_i = P8(Shift^i(P10(K)))，从 P10 的状态
分别总左移 1、2 位。cumulative 调度兼容课件中先左移 1 位、
再额外左移 2 位的流程，其第二个子密钥的总左移量为 3 位。
"""

from __future__ import annotations

from functools import lru_cache
from typing import Any

P10 = (3, 5, 2, 7, 4, 10, 1, 9, 8, 6)
P8 = (6, 3, 7, 4, 8, 5, 10, 9)
IP = (2, 6, 3, 1, 4, 8, 5, 7)
IP_INV = (4, 1, 3, 5, 7, 2, 8, 6)
EP = (4, 1, 2, 3, 2, 3, 4, 1)
P4 = (2, 4, 3, 1)
SBOX1 = ((1, 0, 3, 2), (3, 2, 1, 0), (0, 2, 1, 3), (3, 1, 0, 2))
SBOX2 = ((0, 1, 2, 3), (2, 3, 1, 0), (3, 0, 1, 2), (2, 1, 0, 3))
SCHEDULES = ("assignment", "cumulative")


def _check_width(width: int) -> None:
    if not isinstance(width, int) or isinstance(width, bool) or width <= 0:
        raise ValueError("位宽必须是正整数。")


def _check_value(value: int, width: int, name: str = "数值") -> None:
    if not isinstance(value, int) or isinstance(value, bool):
        raise ValueError(f"{name}必须是整数。")
    if not 0 <= value < (1 << width):
        raise ValueError(f"{name}必须在 0 到 {(1 << width) - 1} 之间（{width} 位）。")


def _check_schedule(schedule: str) -> None:
    if schedule not in SCHEDULES:
        raise ValueError("密钥调度必须是 assignment 或 cumulative。")


def parse_bits(text: str, width: int) -> int:
    """严格解析二进制串；不接受空白、前缀、其他字符或错误位宽。"""
    _check_width(width)
    if not isinstance(text, str) or len(text) != width or any(c not in "01" for c in text):
        raise ValueError(f"请输入恰好 {width} 位的二进制串，只能含 0 和 1。")
    return int(text, 2)


def format_bits(value: int, width: int) -> str:
    """将合法整数格式化为保留前导零的二进制串。"""
    _check_width(width)
    _check_value(value, width)
    return f"{value:0{width}b}"


def permute(value: int, table: tuple[int, ...], input_width: int) -> int:
    """位置表从左侧第 1 位开始编号；输出位依次取 table 指定的位。"""
    result = 0
    for position in table:
        result = (result << 1) | ((value >> (input_width - position)) & 1)
    return result


def _rotate_half(value: int, count: int) -> int:
    """循环左移一个 5 位半块，保留移出位。"""
    count %= 5
    return ((value << count) | (value >> (5 - count))) & 0b11111


def _shift_halves(p10_value: int, count: int) -> int:
    return (_rotate_half(p10_value >> 5, count) << 5) | _rotate_half(p10_value & 31, count)


@lru_cache(maxsize=2048)
def _subkeys(key: int, schedule: str) -> tuple[int, int]:
    p10_value = permute(key, P10, 10)
    second_shift = 2 if schedule == "assignment" else 3
    return (
        permute(_shift_halves(p10_value, 1), P8, 10),
        permute(_shift_halves(p10_value, second_shift), P8, 10),
    )


def generate_subkeys(key: int, schedule: str = "assignment") -> tuple[int, int]:
    """生成 K1、K2；返回两个 8 位整数。"""
    _check_value(key, 10, "密钥")
    _check_schedule(schedule)
    return _subkeys(key, schedule)


def _sbox_lookup(nibble: int, box: tuple[tuple[int, ...], ...]) -> int:
    # 外侧两位构成行，内侧两位构成列；S 盒元素为十进制数。
    row = ((nibble >> 2) & 2) | (nibble & 1)
    column = (nibble >> 1) & 3
    return box[row][column]


def _f(right: int, subkey: int) -> int:
    expanded_xor = permute(right, EP, 4) ^ subkey
    combined = (_sbox_lookup(expanded_xor >> 4, SBOX1) << 2) | _sbox_lookup(expanded_xor & 15, SBOX2)
    return permute(combined, P4, 4)


# 查表仅缓存上述公式的结果，降低 1024×256 次穷举的开销。
# trace_block 仍逐项计算 EP、异或、S 盒、P4，便于学习和核对。
_IP_TABLE = tuple(permute(value, IP, 8) for value in range(256))
_IP_INV_TABLE = tuple(permute(value, IP_INV, 8) for value in range(256))
_F_TABLE = tuple(_f(right, subkey) for right in range(16) for subkey in range(256))


def _crypt_with_subkeys(block: int, first: int, second: int) -> int:
    state = _IP_TABLE[block]
    left, right = state >> 4, state & 15
    # f_k(L,R) = (L xor F(R,K), R)，首轮后交换两个半块。
    left ^= _F_TABLE[(right << 8) | first]
    left, right = right, left
    left ^= _F_TABLE[(right << 8) | second]
    return _IP_INV_TABLE[(left << 4) | right]


def encrypt_block(block: int, key: int, schedule: str = "assignment") -> int:
    """加密一个 8 位分组。"""
    _check_value(block, 8, "分组")
    first, second = generate_subkeys(key, schedule)
    return _crypt_with_subkeys(block, first, second)


def decrypt_block(block: int, key: int, schedule: str = "assignment") -> int:
    """解密同样使用两轮 Feistel 网络，只交换 K1、K2 的次序。"""
    _check_value(block, 8, "分组")
    first, second = generate_subkeys(key, schedule)
    return _crypt_with_subkeys(block, second, first)


def encrypt_bytes(data: bytes, key: int, schedule: str = "assignment") -> bytes:
    """逐字节独立加密；8 位分组无需填充。"""
    if not isinstance(data, bytes):
        raise TypeError("data 必须是 bytes。")
    first, second = generate_subkeys(key, schedule)
    return bytes(_crypt_with_subkeys(block, first, second) for block in data)


def decrypt_bytes(data: bytes, key: int, schedule: str = "assignment") -> bytes:
    if not isinstance(data, bytes):
        raise TypeError("data 必须是 bytes。")
    first, second = generate_subkeys(key, schedule)
    return bytes(_crypt_with_subkeys(block, second, first) for block in data)


def encrypt_ascii(text: str, key: int, schedule: str = "assignment") -> bytes:
    """严格 ASCII 编码后加密；非 ASCII 文本会抛出 UnicodeEncodeError。"""
    if not isinstance(text, str):
        raise TypeError("text 必须是 str。")
    return encrypt_bytes(text.encode("ascii", errors="strict"), key, schedule)


def decrypt_ascii(data: bytes, key: int, schedule: str = "assignment") -> str:
    """解密后严格按 ASCII 解码，避免默默丢弃错误密钥产生的字节。"""
    return decrypt_bytes(data, key, schedule).decode("ascii", errors="strict")


def trace_key_schedule(key: int, schedule: str = "assignment") -> dict[str, Any]:
    """返回密钥调度中间值，所有位串都保留前导零。"""
    first, second = generate_subkeys(key, schedule)
    p10_value = permute(key, P10, 10)
    shifts = (1, 2 if schedule == "assignment" else 3)
    rounds = []
    for number, (count, subkey) in enumerate(zip(shifts, (first, second)), 1):
        shifted = _shift_halves(p10_value, count)
        rounds.append({
            "number": number,
            "total_left_shift": count,
            "left": format_bits(shifted >> 5, 5),
            "right": format_bits(shifted & 31, 5),
            "shifted": format_bits(shifted, 10),
            "P8": format_bits(subkey, 8),
            "subkey_int": subkey,
        })
    return {
        "input": format_bits(key, 10),
        "input_int": key,
        "schedule": schedule,
        "P10": format_bits(p10_value, 10),
        "left": format_bits(p10_value >> 5, 5),
        "right": format_bits(p10_value & 31, 5),
        "rounds": rounds,
        "K1": format_bits(first, 8),
        "K2": format_bits(second, 8),
    }


def _trace_sbox(nibble: int, box: tuple[tuple[int, ...], ...]) -> dict[str, Any]:
    row = ((nibble >> 2) & 2) | (nibble & 1)
    column = (nibble >> 1) & 3
    result = box[row][column]
    return {"input": format_bits(nibble, 4), "row": row, "column": column,
            "output": format_bits(result, 2), "output_int": result}


def _trace_round(state: int, subkey: int, name: str, number: int) -> dict[str, Any]:
    left, right = state >> 4, state & 15
    expanded = permute(right, EP, 4)
    mixed = expanded ^ subkey
    box1 = _trace_sbox(mixed >> 4, SBOX1)
    box2 = _trace_sbox(mixed & 15, SBOX2)
    combined = (box1["output_int"] << 2) | box2["output_int"]
    p4_value = permute(combined, P4, 4)
    new_left = left ^ p4_value
    output = (new_left << 4) | right
    return {
        "number": number, "subkey_name": name, "subkey": format_bits(subkey, 8),
        "input": format_bits(state, 8), "left": format_bits(left, 4),
        "right": format_bits(right, 4), "EP": format_bits(expanded, 8),
        "xor": format_bits(mixed, 8), "SBOX1": box1, "SBOX2": box2,
        "SBOX_output": format_bits(combined, 4), "P4": format_bits(p4_value, 4),
        "newLeft": format_bits(new_left, 4), "output": format_bits(output, 8),
        "output_int": output,
    }


def trace_block(block: int, key: int, decrypt: bool = False,
                schedule: str = "assignment") -> dict[str, Any]:
    """返回可直接 JSON 序列化的完整逐步加密或解密轨迹。"""
    _check_value(block, 8, "分组")
    if not isinstance(decrypt, bool):
        raise ValueError("decrypt 必须是布尔值。")
    first, second = generate_subkeys(key, schedule)
    used = ((second, "K2"), (first, "K1")) if decrypt else ((first, "K1"), (second, "K2"))
    ip_value = permute(block, IP, 8)
    round1 = _trace_round(ip_value, used[0][0], used[0][1], 1)
    state = round1["output_int"]
    swapped = ((state & 15) << 4) | (state >> 4)
    round2 = _trace_round(swapped, used[1][0], used[1][1], 2)
    output = permute(round2["output_int"], IP_INV, 8)
    return {
        "input": format_bits(block, 8), "input_int": block,
        "key": format_bits(key, 10), "schedule": schedule, "decrypt": decrypt,
        "subkeys": {"K1": format_bits(first, 8), "K2": format_bits(second, 8),
                    "used": [item[1] for item in used]},
        "IP": format_bits(ip_value, 8), "rounds": [round1, round2],
        "SW": format_bits(swapped, 8), "IPinv": format_bits(output, 8),
        "output": format_bits(output, 8), "output_int": output,
        "key_schedule": trace_key_schedule(key, schedule),
    }


__all__ = ["P10", "P8", "IP", "IP_INV", "EP", "P4", "SBOX1", "SBOX2", "SCHEDULES",
           "parse_bits", "format_bits", "permute", "generate_subkeys", "encrypt_block",
           "decrypt_block", "encrypt_bytes", "decrypt_bytes", "encrypt_ascii", "decrypt_ascii",
           "trace_key_schedule", "trace_block"]
