"""S-DES 命令行入口：python cli.py --help。"""

from __future__ import annotations

import argparse
import base64
import binascii
import json
import sys
from pathlib import Path

try:
    from .sdes import (SCHEDULES, decrypt_ascii, decrypt_block, encrypt_ascii, encrypt_block,
                       format_bits, parse_bits, trace_block)
    from .analysis_tools import brute_force, collision_analysis, equivalent_key_analysis, scan_all_plaintexts
except ImportError:
    from sdes import (SCHEDULES, decrypt_ascii, decrypt_block, encrypt_ascii, encrypt_block,
                      format_bits, parse_bits, trace_block)
    from analysis_tools import brute_force, collision_analysis, equivalent_key_analysis, scan_all_plaintexts


def _schedule_argument(parser: argparse.ArgumentParser, *, root: bool = False) -> None:
    parser.add_argument("--schedule", choices=SCHEDULES,
                        default="assignment" if root else argparse.SUPPRESS,
                        help="assignment：分别总移 1/2 位（默认）；cumulative：总移 1/3 位")


def _make_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="实验一 S-DES：8 位分组、10 位密钥，作业指定的置换和 S 盒。")
    _schedule_argument(parser, root=True)
    commands = parser.add_subparsers(dest="command", required=True)

    bits = commands.add_parser("bits", help="8 位二进制分组加密或解密")
    _schedule_argument(bits)
    operations = bits.add_subparsers(dest="operation", required=True)
    for operation, help_text in (("encrypt", "加密"), ("decrypt", "解密")):
        child = operations.add_parser(operation, help=help_text)
        child.add_argument("data", help="恰好 8 位的二进制输入")
        child.add_argument("--key", required=True, help="恰好 10 位的二进制密钥")
        child.add_argument("--trace", action="store_true", help="输出包含中间值的 JSON 轨迹")
        _schedule_argument(child)

    ascii_parser = commands.add_parser("ascii", help="严格 ASCII 文本加密与解密")
    _schedule_argument(ascii_parser)
    ascii_operations = ascii_parser.add_subparsers(dest="operation", required=True)
    encode = ascii_operations.add_parser("encode", help="ASCII 文本加密，密文用 Hex 或 Base64 展示")
    encode.add_argument("data", help="ASCII 明文")
    encode.add_argument("--key", required=True, help="10 位二进制密钥")
    encode.add_argument("--format", choices=("hex", "base64"), default="hex", help="密文显示格式（默认 hex）")
    _schedule_argument(encode)
    decode = ascii_operations.add_parser("decode", help="Hex 或 Base64 密文解密为 ASCII")
    decode.add_argument("data", help="Hex 或 Base64 密文")
    decode.add_argument("--key", required=True, help="10 位二进制密钥")
    decode.add_argument("--format", choices=("hex", "base64"), default="hex", help="密文输入格式（默认 hex）")
    _schedule_argument(decode)

    attack = commands.add_parser("attack", help="对一组或多组已知明密文枚举全部 1024 个密钥")
    attack.add_argument("--pair", action="append", default=[], metavar="P:C", help="8 位明文:8 位密文；可以重复")
    attack.add_argument("--pairs", help="多行明密文；每行用冒号、逗号或空白分隔")
    attack.add_argument("--pairs-file", type=Path, help="UTF-8 明密文对文件（每行一组）")
    attack.add_argument("--stdin", action="store_true", help="从标准输入读取多行明密文对")
    _schedule_argument(attack)

    collision = commands.add_parser("collision", help="固定明文的密钥碰撞、全部明文扫描或等价密钥分析")
    mode = collision.add_mutually_exclusive_group(required=True)
    mode.add_argument("--plaintext", metavar="BITS", help="对指定的 8 位明文分析碰撞")
    mode.add_argument("--all", action="store_true", help="扫描全部 256 个明文")
    mode.add_argument("--equivalent", action="store_true", help="比较全部密钥的 256 明文置换，寻找等价密钥")
    _schedule_argument(collision)
    return parser


def _parse_pairs(text: str) -> list[tuple[int, int]]:
    pairs = []
    for number, line in enumerate(text.splitlines(), 1):
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        items = stripped.replace(":", " ").replace(",", " ").split()
        if len(items) != 2:
            raise ValueError(f"第 {number} 行必须包含一组 8 位明文和 8 位密文。")
        pairs.append((parse_bits(items[0], 8), parse_bits(items[1], 8)))
    return pairs


def _print_json(value: object) -> None:
    print(json.dumps(value, ensure_ascii=False, indent=2))


def main(argv: list[str] | None = None) -> int:
    parser = _make_parser()
    args = parser.parse_args(argv)
    try:
        if args.command == "bits":
            block, key = parse_bits(args.data, 8), parse_bits(args.key, 10)
            decrypt = args.operation == "decrypt"
            if args.trace:
                _print_json(trace_block(block, key, decrypt=decrypt, schedule=args.schedule))
            else:
                operation = decrypt_block if decrypt else encrypt_block
                print(format_bits(operation(block, key, args.schedule), 8))
        elif args.command == "ascii":
            key = parse_bits(args.key, 10)
            if args.operation == "encode":
                ciphertext = encrypt_ascii(args.data, key, args.schedule)
                print(ciphertext.hex().upper() if args.format == "hex" else base64.b64encode(ciphertext).decode("ascii"))
            else:
                ciphertext = bytes.fromhex(args.data) if args.format == "hex" else base64.b64decode(args.data, validate=True)
                print(decrypt_ascii(ciphertext, key, args.schedule))
        elif args.command == "attack":
            pairs = []
            for pair in args.pair:
                pairs.extend(_parse_pairs(pair))
            if args.pairs:
                pairs.extend(_parse_pairs(args.pairs))
            if args.pairs_file is not None:
                pairs.extend(_parse_pairs(args.pairs_file.read_text(encoding="utf-8-sig")))
            if args.stdin:
                pairs.extend(_parse_pairs(sys.stdin.read()))
            _print_json(brute_force(pairs, args.schedule))
        elif args.command == "collision":
            if args.plaintext is not None:
                result = collision_analysis(parse_bits(args.plaintext, 8), args.schedule)
            elif args.all:
                result = scan_all_plaintexts(args.schedule)
            else:
                result = equivalent_key_analysis(args.schedule)
            _print_json(result)
    except (ValueError, TypeError, OSError, UnicodeError, binascii.Error) as error:
        parser.error(str(error))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
