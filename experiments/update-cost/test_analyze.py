"""Observable integrity and overlap contracts for UPDATE metadata analysis."""
import copy
import json
import tempfile
import unittest
from pathlib import Path

from analyze import analyze, load_records


def rpc_records(request_id, start, sent, received, end):
    common = dict(peer=1, request_id=request_id, operation="fetch")
    return [
        dict(common, event="activity", phase="request_sent", time_ms=sent, application_bytes=10),
        dict(common, event="activity", phase="reply_received", time_ms=received, application_bytes=20),
        dict(common, event="complete", approx_start_ms=start, time_ms=end, elapsed_ms=end - start,
             application_request_bytes=10, application_response_bytes=20, succeeded=True),
    ]


def envelope(events):
    summary = dict(event="summary", case="two_shard_update", elapsed_ms=10,
                   event_count=len(events), event_limit=4096, truncated=False)
    return summary, [summary, *events]


class UpdateObservationTests(unittest.TestCase):
    def test_overlapping_rpc_intervals_count_wall_time_once(self):
        summary, records = envelope(rpc_records(1, 1, 2, 6, 7) + rpc_records(2, 3, 4, 8, 9))

        report = analyze(summary, records)

        self.assertEqual(report["completed_rpcs"], 2)
        self.assertEqual(report["rpc_covered_wall_ms"], 8)
        self.assertEqual(report["no_owner_rpc_inflight_wall_ms"], 2)
        self.assertEqual(report["operations"][0]["rpc_elapsed_sum_ms"], 12)
        self.assertEqual(report["operations"][0]["application_response_bytes"], 40)

    def test_missing_or_truncated_envelope_is_rejected(self):
        summary, records = envelope(rpc_records(1, 1, 2, 6, 7))
        truncated = copy.deepcopy(records)
        truncated[0]["truncated"] = True
        with tempfile.TemporaryDirectory() as directory:
            log = Path(directory) / "run.log"
            for invalid in (records[1:], truncated, [summary, *records]):
                with self.subTest(records=invalid):
                    log.write_text("".join("rpc_observation=" + json.dumps(record) + "\n"
                                           for record in invalid), encoding="utf-8")
                    with self.assertRaises(ValueError):
                        load_records(log)

    def test_successful_rpc_requires_both_frame_callbacks(self):
        for missing in ("request_sent", "reply_received"):
            with self.subTest(missing=missing):
                events = [record for record in rpc_records(1, 1, 2, 6, 7)
                          if record.get("phase") != missing]
                with self.assertRaisesRegex(ValueError, "successful RPC requires"):
                    analyze(*envelope(events))

    def test_failed_rpc_allows_missing_frame_callbacks(self):
        events = rpc_records(1, 1, 2, 6, 7)[-1:]
        events[0]["succeeded"] = False

        report = analyze(*envelope(events))

        self.assertEqual(report["failed_rpcs"], 1)
        self.assertIsNone(report["rpcs"][0]["sent_to_received_ms"])

    def test_frame_bytes_operation_and_order_must_match_completion(self):
        for field, value in (("application_bytes", 11), ("operation", "store"), ("time_ms", 8)):
            with self.subTest(field=field):
                events = rpc_records(1, 1, 2, 6, 7)
                events[0][field] = value
                with self.assertRaisesRegex(ValueError, "frame order, operation or byte count"):
                    analyze(*envelope(events))

    def test_duplicate_and_uncompleted_activity_are_rejected(self):
        events = rpc_records(1, 1, 2, 6, 7)
        for invalid in (events + [events[0]], events[:-1]):
            with self.subTest(events=invalid):
                with self.assertRaises(ValueError):
                    analyze(*envelope(invalid))

    def test_nonfinite_negative_or_outside_intervals_are_rejected(self):
        for field in ("time_ms", "approx_start_ms", "elapsed_ms"):
            for value in (float("nan"), float("inf"), -1):
                with self.subTest(field=field, value=value):
                    events = rpc_records(1, 1, 2, 6, 7)
                    events[-1][field] = value
                    with self.assertRaises(ValueError):
                        analyze(*envelope(events))
        for field in ("time_ms", "approx_start_ms", "elapsed_ms"):
            with self.subTest(field=field):
                events = rpc_records(1, 1, 2, 6, 7)
                events[-1][field] = 11
                with self.assertRaises(ValueError):
                    analyze(*envelope(events))


if __name__ == "__main__":
    unittest.main()
