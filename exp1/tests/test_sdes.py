from __future__ import annotations

import unittest

import reference_sdes as reference
import sdes


# Fixed before consulting the integer implementation.  Derived by manually
# applying P10, the rotations, P8, EP, the stated S boxes, P4 and IP inverse.
HAND_KEY = 0b1010000010
HAND_PLAIN = 0b10011010
HAND_EXPECTED = {
    "assignment": ((0b10100100, 0b10010010), 0b11101111),
    "cumulative": ((0b10100100, 0b01000011), 0b01101011),
}


class HandVectorTests(unittest.TestCase):
    def test_fixed_subkeys_and_ciphertexts(self):
        for schedule, (subkeys, ciphertext) in HAND_EXPECTED.items():
            with self.subTest(schedule=schedule):
                self.assertEqual(sdes.generate_subkeys(HAND_KEY, schedule), subkeys)
                self.assertEqual(reference.generate_subkeys(HAND_KEY, schedule), subkeys)
                self.assertEqual(sdes.encrypt_block(HAND_PLAIN, HAND_KEY, schedule), ciphertext)
                self.assertEqual(reference.encrypt_block(HAND_PLAIN, HAND_KEY, schedule), ciphertext)
                self.assertEqual(sdes.decrypt_block(ciphertext, HAND_KEY, schedule), HAND_PLAIN)
                self.assertEqual(reference.decrypt_block(ciphertext, HAND_KEY, schedule), HAND_PLAIN)

    def test_assignment_hand_round_trace(self):
        trace = sdes.trace_block(HAND_PLAIN, HAND_KEY)
        self.assertEqual(trace["key_schedule"]["P10"], "1000001100")
        self.assertEqual(trace["IP"], "00011011")
        self.assertEqual(trace["rounds"][0]["EP"], "11010111")
        self.assertEqual(trace["rounds"][0]["xor"], "01110011")
        self.assertEqual(trace["rounds"][0]["SBOX_output"], "0011")
        self.assertEqual(trace["rounds"][0]["P4"], "0110")
        self.assertEqual(trace["rounds"][0]["output"], "01111011")
        self.assertEqual(trace["SW"], "10110111")
        self.assertEqual(trace["rounds"][1]["EP"], "10111110")
        self.assertEqual(trace["rounds"][1]["xor"], "00101100")
        self.assertEqual(trace["rounds"][1]["SBOX_output"], "0001")
        self.assertEqual(trace["rounds"][1]["P4"], "0100")
        self.assertEqual(trace["rounds"][1]["output"], "11110111")
        self.assertEqual(trace["output"], "11101111")

    def test_default_schedule_is_assignment(self):
        self.assertEqual(sdes.generate_subkeys(HAND_KEY), HAND_EXPECTED["assignment"][0])
        self.assertEqual(sdes.encrypt_block(HAND_PLAIN, HAND_KEY), 0b11101111)

    def test_decryption_trace_uses_reversed_keys(self):
        trace = sdes.trace_block(0b11101111, HAND_KEY, decrypt=True)
        self.assertEqual(trace["subkeys"]["used"], ["K2", "K1"])
        self.assertEqual(trace["output_int"], HAND_PLAIN)


class InputValidationTests(unittest.TestCase):
    def test_binary_input_rejects_invalid_values(self):
        for value in ("", "101", "000000000", "00000002", " 0000000", "0000000 ",
                      "0b000000", "００００００００", None, 0):
            with self.subTest(value=value), self.assertRaises(ValueError):
                sdes.parse_bits(value, 8)

    def test_binary_input_preserves_leading_zeros(self):
        self.assertEqual(sdes.parse_bits("00000001", 8), 1)
        self.assertEqual(sdes.format_bits(1, 8), "00000001")

    def test_invalid_widths(self):
        for width in (0, -1, True, 1.5, "8"):
            with self.subTest(width=width), self.assertRaises(ValueError):
                sdes.parse_bits("00000000", width)
            with self.subTest(width=width), self.assertRaises(ValueError):
                sdes.format_bits(0, width)

    def test_permutation_validates_values_widths_and_positions(self):
        self.assertEqual(sdes.permute(0b1001, sdes.EP, 4), 0b11000011)
        self.assertEqual(sdes.permute(0b1001, (), 4), 0)
        for value in (-1, 16, True, 1.0, None):
            with self.subTest(value=value), self.assertRaises(ValueError):
                sdes.permute(value, (1,), 4)
        for width in (0, -1, True, 1.5, "4"):
            with self.subTest(width=width), self.assertRaises(ValueError):
                sdes.permute(0, (1,), width)
        for table in ((0,), (5,), (True,), (1.0,), ("1",), "1", None, 1):
            with self.subTest(table=table), self.assertRaises(ValueError):
                sdes.permute(0, table, 4)

    def test_trace_rejects_non_boolean_decrypt_flags(self):
        for decrypt in (0, 1, "false", None, []):
            with self.subTest(decrypt=decrypt), self.assertRaises(ValueError):
                sdes.trace_block(HAND_PLAIN, HAND_KEY, decrypt=decrypt)
            with self.subTest(decrypt=decrypt), self.assertRaises(ValueError):
                reference.trace_bits(f"{HAND_PLAIN:08b}", f"{HAND_KEY:010b}", decrypt=decrypt)

    def test_invalid_keys(self):
        for key in (-1, 1024, True, 1.0, "1010000010", None):
            for function in (sdes.generate_subkeys,):
                with self.subTest(key=key), self.assertRaises(ValueError):
                    function(key)
            for function in (sdes.encrypt_block, sdes.decrypt_block):
                with self.subTest(key=key), self.assertRaises(ValueError):
                    function(0, key)

    def test_invalid_blocks(self):
        for block in (-1, 256, True, 1.0, "00000000", None):
            for function in (sdes.encrypt_block, sdes.decrypt_block):
                with self.subTest(block=block), self.assertRaises(ValueError):
                    function(block, 0)

    def test_unknown_schedule(self):
        for schedule in ("", "standard", None, 1):
            with self.subTest(schedule=schedule), self.assertRaises(ValueError):
                sdes.encrypt_block(0, 0, schedule)

    def test_bytes_and_text_types_are_strict(self):
        for value in ("abc", [1, 2], bytearray(b"abc"), None):
            with self.subTest(value=value), self.assertRaises(TypeError):
                sdes.encrypt_bytes(value, 0)
        for value in (b"abc", 1, None):
            with self.subTest(value=value), self.assertRaises(TypeError):
                sdes.encrypt_ascii(value, 0)


class ByteAndAsciiTests(unittest.TestCase):
    def test_all_128_ascii_characters(self):
        text = "".join(chr(value) for value in range(128))
        for schedule in HAND_EXPECTED:
            cipher = sdes.encrypt_ascii(text, HAND_KEY, schedule)
            self.assertEqual(len(cipher), 128)
            self.assertEqual(cipher, reference.encrypt_ascii(text, HAND_KEY, schedule))
            self.assertEqual(sdes.decrypt_ascii(cipher, HAND_KEY, schedule), text)
            self.assertEqual(reference.decrypt_ascii(cipher, HAND_KEY, schedule), text)

    def test_empty_and_control_and_normal_strings(self):
        for text in ("", "\0\t\n\r\x1b\x7f", "Hello S-DES!"):
            for schedule in HAND_EXPECTED:
                with self.subTest(text=repr(text), schedule=schedule):
                    cipher = sdes.encrypt_ascii(text, HAND_KEY, schedule)
                    self.assertEqual(cipher, reference.encrypt_ascii(text, HAND_KEY, schedule))
                    self.assertEqual(sdes.decrypt_ascii(cipher, HAND_KEY, schedule), text)

    def test_non_ascii_rejected(self):
        for text in ("中文", "é", "🙂", "ASCII\u0080"):
            with self.subTest(text=text), self.assertRaises(UnicodeEncodeError):
                sdes.encrypt_ascii(text, HAND_KEY)

    def test_decrypting_non_ascii_bytes_rejected(self):
        cipher = sdes.encrypt_bytes(b"\x80", HAND_KEY)
        with self.assertRaises(UnicodeDecodeError):
            sdes.decrypt_ascii(cipher, HAND_KEY)

    def test_all_256_bytes(self):
        data = bytes(range(256))
        for schedule in HAND_EXPECTED:
            cipher = sdes.encrypt_bytes(data, HAND_KEY, schedule)
            self.assertEqual(cipher, reference.encrypt_bytes(data, HAND_KEY, schedule))
            self.assertEqual(sdes.decrypt_bytes(cipher, HAND_KEY, schedule), data)
            self.assertEqual(reference.decrypt_bytes(cipher, HAND_KEY, schedule), data)


class CrossImplementationTests(unittest.TestCase):
    def test_all_subkeys_for_both_schedules(self):
        for schedule in HAND_EXPECTED:
            for key in range(1024):
                self.assertEqual(sdes.generate_subkeys(key, schedule), reference.generate_subkeys(key, schedule))

class ExhaustiveDomainTests(unittest.TestCase):
    def test_both_schedules_all_keys_all_blocks_and_bijections(self):
        for schedule in HAND_EXPECTED:
            for key in range(1024):
                subkeys = reference.generate_subkeys_bits(f"{key:010b}", schedule)
                outputs = []
                for block in range(256):
                    cipher = sdes.encrypt_block(block, key, schedule)
                    expected_bits = reference.crypt_with_subkeys_bits(f"{block:08b}", subkeys)
                    self.assertEqual(cipher, int(expected_bits, 2), (schedule, key, block))
                    self.assertEqual(sdes.decrypt_block(int(expected_bits, 2), key, schedule), block, (schedule, key, block))
                    self.assertEqual(reference.crypt_with_subkeys_bits(f"{cipher:08b}", subkeys[::-1]), f"{block:08b}")
                    outputs.append(cipher)
                self.assertEqual(len(set(outputs)), 256, (schedule, key))


if __name__ == "__main__":
    unittest.main()
