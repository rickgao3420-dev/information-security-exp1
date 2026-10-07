import unittest

import analysis_tools
import sdes


class AnalysisTests(unittest.TestCase):
    def test_single_and_multiple_pairs_keep_true_key(self):
        key = 0b1010000010
        pairs = [(p, sdes.encrypt_block(p, key)) for p in (215, 154, 0, 255, 85, 170)]
        single = analysis_tools.brute_force(pairs[:1])
        multiple = analysis_tools.brute_force(pairs)
        self.assertEqual(single["tested_keys"], 1024)
        self.assertEqual(multiple["tested_keys"], 1024)
        self.assertIn(key, single["candidate_keys"])
        self.assertIn(key, multiple["candidate_keys"])
        self.assertTrue(set(multiple["candidate_keys"]) <= set(single["candidate_keys"]))
        self.assertGreater(single["candidate_count"], multiple["candidate_count"])
        expected = [candidate for candidate in range(1024)
                    if all(sdes.encrypt_block(p, candidate) == c for p, c in pairs)]
        self.assertEqual(multiple["candidate_keys"], expected)

    def test_progress_covers_all_keys(self):
        events = []
        result = analysis_tools.brute_force([(154, 239)], progress=lambda *args: events.append(args))
        self.assertEqual(events[0][:3], (0, 1024, 0))
        self.assertEqual(events[-1][0:2], (1024, 1024))
        self.assertEqual(len(events), 1025)
        self.assertEqual(events[-1][2], result["candidate_count"])
        self.assertTrue(all(previous[3] <= current[3] for previous, current in zip(events, events[1:])))

    def test_inconsistent_pairs_produce_zero_candidates(self):
        self.assertEqual(analysis_tools.brute_force([(0, 0), (0, 1)])["candidate_keys"], [])

    def test_empty_or_invalid_pairs_rejected(self):
        for pairs in ([], [(256, 0)], [(0, -1)], [(0,)], ["00"], [(True, 0)]):
            with self.subTest(pairs=pairs), self.assertRaises(ValueError):
                analysis_tools.brute_force(pairs)

    def test_collision_buckets_really_partition_all_keys(self):
        result = analysis_tools.collision_analysis(154)
        groups = result["groups"]
        all_keys = [key for group in groups for key in group["keys"]]
        self.assertEqual(sorted(all_keys), list(range(1024)))
        self.assertEqual(len(set(group["ciphertext_int"] for group in groups)), len(groups))
        for group in groups:
            self.assertEqual(group["count"], len(group["keys"]))
            self.assertTrue(all(sdes.encrypt_block(154, key) == group["ciphertext_int"] for key in group["keys"]))
        stats = result["statistics"]
        self.assertGreaterEqual(stats["max_bucket_size"], 4)
        self.assertGreater(stats["collision_buckets"], 0)
        self.assertEqual(stats["collision_key_pairs"], sum(len(g["keys"]) * (len(g["keys"]) - 1) // 2 for g in groups))

    def test_collision_bad_plaintext_rejected(self):
        for plaintext in (-1, 256, True, None):
            with self.subTest(plaintext=plaintext), self.assertRaises(ValueError):
                analysis_tools.collision_analysis(plaintext)


if __name__ == "__main__":
    unittest.main()
