"""Independent, literal bit-string implementation of the assignment's S-DES.

This module intentionally does not import ``sdes`` or use any of its constants,
helpers, tables, or algorithm code.  It uses character indexing and string XOR
so agreement with the integer implementation is useful independent evidence.
"""

from __future__ import annotations

P10 = (3, 5, 2, 7, 4, 10, 1, 9, 8, 6)
P8 = (6, 3, 7, 4, 8, 5, 10, 9)
IP = (2, 6, 3, 1, 4, 8, 5, 7)
IP_INVERSE = (4, 1, 3, 5, 7, 2, 8, 6)
EXPANSION = (4, 1, 2, 3, 2, 3, 4, 1)
P4 = (2, 4, 3, 1)
LEFT_BOX = ((1, 0, 3, 2), (3, 2, 1, 0), (0, 2, 1, 3), (3, 1, 0, 2))
RIGHT_BOX = ((0, 1, 2, 3), (2, 3, 1, 0), (3, 0, 1, 2), (2, 1, 0, 3))


def _bits(value: str, width: int, name: str) -> str:
    if not isinstance(value, str) or len(value) != width or any(c not in "01" for c in value):
        raise ValueError(f"{name} must be exactly {width} binary characters")
    return value


def _schedule(name: str) -> tuple[int, int]:
    if name == "assignment":
        return 1, 2
    if name == "cumulative":
        return 1, 3
    raise ValueError("schedule must be 'assignment' or 'cumulative'")


def _permute(bits: str, positions: tuple[int, ...]) -> str:
    return "".join(bits[position - 1] for position in positions)


def _rotate(bits: str, distance: int) -> str:
    return bits[distance:] + bits[:distance]


def _xor(first: str, second: str) -> str:
    return "".join("0" if a == b else "1" for a, b in zip(first, second))


def generate_subkeys_bits(key: str, schedule: str = "assignment") -> tuple[str, str]:
    """Return subkeys using total shifts from the original P10 halves."""
    first_shift, second_shift = _schedule(schedule)
    permuted = _permute(_bits(key, 10, "key"), P10)
    left, right = permuted[:5], permuted[5:]
    return tuple(
        _permute(_rotate(left, shift) + _rotate(right, shift), P8)
        for shift in (first_shift, second_shift)
    )


def _box(four_bits: str, table: tuple[tuple[int, ...], ...]) -> str:
    row = int(four_bits[0] + four_bits[3], 2)
    column = int(four_bits[1:3], 2)
    return f"{table[row][column]:02b}"


def _round(bits: str, subkey: str) -> str:
    left, right = bits[:4], bits[4:]
    mixed = _xor(_permute(right, EXPANSION), subkey)
    substituted = _box(mixed[:4], LEFT_BOX) + _box(mixed[4:], RIGHT_BOX)
    return _xor(left, _permute(substituted, P4)) + right


def crypt_with_subkeys_bits(block: str, subkeys: tuple[str, str]) -> str:
    """Encrypt with the supplied order; reverse the pair for decryption."""
    block = _bits(block, 8, "block")
    if len(subkeys) != 2:
        raise ValueError("two subkeys are required")
    _bits(subkeys[0], 8, "first subkey")
    _bits(subkeys[1], 8, "second subkey")
    state = _round(_permute(block, IP), subkeys[0])
    state = state[4:] + state[:4]
    return _permute(_round(state, subkeys[1]), IP_INVERSE)


def encrypt_bits(block: str, key: str, schedule: str = "assignment") -> str:
    return crypt_with_subkeys_bits(block, generate_subkeys_bits(key, schedule))


def decrypt_bits(block: str, key: str, schedule: str = "assignment") -> str:
    first, second = generate_subkeys_bits(key, schedule)
    return crypt_with_subkeys_bits(block, (second, first))


def _integer(value: int, width: int, name: str) -> str:
    if isinstance(value, bool) or not isinstance(value, int) or not 0 <= value < (1 << width):
        raise ValueError(f"{name} must be an integer in [0, {(1 << width) - 1}]")
    return f"{value:0{width}b}"


def generate_subkeys(key: int, schedule: str = "assignment") -> tuple[int, int]:
    return tuple(int(bits, 2) for bits in generate_subkeys_bits(_integer(key, 10, "key"), schedule))


def encrypt_block(block: int, key: int, schedule: str = "assignment") -> int:
    return int(encrypt_bits(_integer(block, 8, "block"), _integer(key, 10, "key"), schedule), 2)


def decrypt_block(block: int, key: int, schedule: str = "assignment") -> int:
    return int(decrypt_bits(_integer(block, 8, "block"), _integer(key, 10, "key"), schedule), 2)


def encrypt_bytes(data: bytes, key: int, schedule: str = "assignment") -> bytes:
    if not isinstance(data, bytes):
        raise ValueError("data must be bytes")
    subkeys = generate_subkeys_bits(_integer(key, 10, "key"), schedule)
    return bytes(int(crypt_with_subkeys_bits(f"{block:08b}", subkeys), 2) for block in data)


def decrypt_bytes(data: bytes, key: int, schedule: str = "assignment") -> bytes:
    if not isinstance(data, bytes):
        raise ValueError("data must be bytes")
    first, second = generate_subkeys_bits(_integer(key, 10, "key"), schedule)
    return bytes(int(crypt_with_subkeys_bits(f"{block:08b}", (second, first)), 2) for block in data)


def encrypt_ascii(text: str, key: int, schedule: str = "assignment") -> bytes:
    if not isinstance(text, str):
        raise ValueError("text must be a string")
    return encrypt_bytes(text.encode("ascii", errors="strict"), key, schedule)


def decrypt_ascii(data: bytes, key: int, schedule: str = "assignment") -> str:
    return decrypt_bytes(data, key, schedule).decode("ascii", errors="strict")


def trace_bits(block: str, key: str, schedule: str = "assignment", decrypt: bool = False) -> dict:
    """Expose intermediate strings for checking a hand calculation."""
    _bits(block, 8, "block")
    _bits(key, 10, "key")
    k1, k2 = generate_subkeys_bits(key, schedule)
    ordered_keys = (k2, k1) if decrypt else (k1, k2)
    initial = _permute(block, IP)
    after_first = _round(initial, ordered_keys[0])
    swapped = after_first[4:] + after_first[:4]
    after_second = _round(swapped, ordered_keys[1])
    return {
        "input": block,
        "key": key,
        "schedule": schedule,
        "p10": _permute(key, P10),
        "k1": k1,
        "k2": k2,
        "ip": initial,
        "round1": after_first,
        "swap": swapped,
        "round2": after_second,
        "output": _permute(after_second, IP_INVERSE),
    }
