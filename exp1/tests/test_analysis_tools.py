from datetime import datetime
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
        for pairs in ([], None, 1, [(256, 0)], [(0, -1)], [(0,)], ["00"], [(True, 0)]):
            with self.subTest(pairs=pairs), self.assertRaises(ValueError):
                analysis_tools.brute_force(pairs)

    def test_pair_iterators_are_validated_before_search(self):
        with self.assertRaises(ValueError):
            analysis_tools.brute_force(iter(()))
        pairs = [(154, 239), (0, sdes.encrypt_block(0, 0b1010000010))]
        self.assertEqual(analysis_tools.brute_force(iter(pairs))["candidate_keys"],
                         analysis_tools.brute_force(pairs)["candidate_keys"])

    def test_attack_records_timezone_aware_timestamps_and_real_elapsed_time(self):
        result = analysis_tools.brute_force([(154, 239)])
        for field in ("started_at", "finished_at"):
            timestamp = datetime.fromisoformat(result[field])
            self.assertIsNotNone(timestamp.utcoffset())
        self.assertGreaterEqual(result["elapsed_seconds"], 0)

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

    def test_all_plaintext_scan_retains_consistent_histograms_and_progress(self):
        for schedule in sdes.SCHEDULES:
            events = []
            result = analysis_tools.scan_all_plaintexts(schedule, progress=lambda *event: events.append(event))
            self.assertEqual(result["encryptions"], 1024 * 256)
            self.assertEqual([row["plaintext_int"] for row in result["plaintexts"]], list(range(256)))
            self.assertEqual(events[0][:3], (0, 256, 0))
            self.assertEqual(len(events), 257)
            self.assertEqual(events[-1][:3], (256, 256, 256))
            self.assertTrue(result["all_plaintexts_have_collisions"])
            for row in result["plaintexts"]:
                histogram = row["bucket_size_histogram"]
                self.assertEqual(sum(histogram.values()), row["distinct_ciphertexts"])
                self.assertEqual(sum(int(size) * count for size, count in histogram.items()), 1024)
                self.assertEqual(sum(int(size) * (int(size) - 1) // 2 * count
                                     for size, count in histogram.items()), row["collision_key_pairs"])
            fixed = analysis_tools.collision_analysis(154, schedule)
            for field, expected in fixed["statistics"].items():
                self.assertEqual(result["plaintexts"][154][field], expected)

    def test_full_mapping_equivalence_matches_complete_known_plaintext_attack(self):
        key = 0b1010000010
        for schedule in sdes.SCHEDULES:
            result = analysis_tools.equivalent_key_analysis(schedule)
            groups = result["equivalence_groups"]
            self.assertEqual(sorted(key for group in groups for key in group["keys"]), list(range(1024)))
            events = []
            pairs = [(plain, sdes.encrypt_block(plain, key, schedule)) for plain in range(256)]
            attacked = analysis_tools.brute_force(pairs, schedule, progress=lambda *event: events.append(event))
            group = next(group for group in groups if key in group["keys"])
            self.assertEqual(attacked["candidate_keys"], group["keys"])
            self.assertEqual(events[-1][:2], (1024, 1024))
            if schedule == "assignment":
                # 该调度的 P8 两次都省略主密钥的第二位；它对应整数掩码 256。
                self.assertEqual(result["distinct_permutations"], 512)
                self.assertEqual(result["equivalent_group_count"], 512)
                self.assertTrue(all(group["count"] == 2 and group["keys"][0] ^ group["keys"][1] == 256
                                    for group in groups))
            else:
                self.assertEqual(result["distinct_permutations"], 1024)
                self.assertEqual(result["equivalent_group_count"], 0)
                self.assertTrue(all(group["count"] == 1 for group in groups))


if __name__ == "__main__":
    unittest.main()
