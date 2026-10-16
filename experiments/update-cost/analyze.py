"""Analyze bounded metadata from the opt-in genuine UPDATE process fixture."""
import argparse
import json
from collections import defaultdict
from pathlib import Path

MAX_EVENTS = 4096
MAX_LINE_CHARS = 8192
MAX_LINES = 2 * MAX_EVENTS + 64


def load_records(log):
    records = []
    with log.open(encoding="utf-8") as stream:
        for _ in range(MAX_LINES):
            line = stream.readline(MAX_LINE_CHARS + 1)
            if not line:
                break
            if len(line) > MAX_LINE_CHARS:
                raise ValueError("observation log line exceeds the bounded reader")
            if "rpc_observation=" in line:
                if len(records) == MAX_EVENTS + 1:
                    raise ValueError("observation log exceeds the event budget")
                records.append(json.loads(line.split("rpc_observation=", 1)[1]))
        else:
            if stream.read(1):
                raise ValueError("observation log exceeds the line budget")
    summaries = [record for record in records if record["event"] == "summary"]
    if len(summaries) != 1:
        raise ValueError("expected one complete UPDATE observation envelope")
    summary = summaries[0]
    if summary["truncated"] or summary["event_count"] != len(records) - 1:
        raise ValueError("incomplete or truncated observation cannot explain a full query")
    return summary, records


def covered_wall(intervals):
    total, end = 0.0, 0.0
    for start, stop in sorted(intervals):
        total += max(0.0, stop - max(start, end))
        end = max(end, stop)
    return total


def local_gaps(rpcs, elapsed_ms):
    gaps, previous, cursor = [], [], 0.0
    for rpc in sorted(rpcs, key=lambda rpc: rpc["approx_start_ms"]):
        start, end = rpc["approx_start_ms"], rpc["time_ms"]
        if start > cursor:
            gaps.append(dict(start_ms=cursor, end_ms=start, duration_ms=start - cursor,
                             preceding=previous, following=rpc["operation"]))
        if end > cursor:
            cursor, previous = end, [rpc["operation"]]
    if elapsed_ms > cursor:
        gaps.append(dict(start_ms=cursor, end_ms=elapsed_ms, duration_ms=elapsed_ms - cursor,
                         preceding=previous, following="complete"))
    return sorted(gaps, key=lambda gap: gap["duration_ms"], reverse=True)[:10]


def analyze(summary, records):
    activity, rpcs, by_operation = {}, [], defaultdict(list)
    for record in records:
        if record["event"] == "activity":
            key = (record["peer"], record["request_id"])
            activity.setdefault(key, {})[record["phase"]] = record["time_ms"]
    for record in records:
        if record["event"] != "complete":
            continue
        rpc = dict(record)
        phases = activity.get((rpc["peer"], rpc["request_id"]), {})
        start, end = rpc["approx_start_ms"], rpc["time_ms"]
        sent, received = phases.get("request_sent"), phases.get("reply_received")
        rpc["encode_connect_write_ms"] = max(0.0, sent - start) if sent is not None else None
        rpc["sent_to_received_ms"] = (max(0.0, received - sent)
                                      if sent is not None and received is not None else None)
        rpc["decode_tail_ms"] = max(0.0, end - received) if received is not None else None
        rpcs.append(rpc)
        by_operation[rpc["operation"]].append(rpc)

    operations = []
    for operation, calls in by_operation.items():
        operations.append(dict(
            operation=operation,
            count=len(calls),
            failed=sum(not call["succeeded"] for call in calls),
            rpc_elapsed_sum_ms=sum(call["elapsed_ms"] for call in calls),
            rpc_covered_wall_ms=covered_wall(
                (call["approx_start_ms"], call["time_ms"]) for call in calls),
            encode_connect_write_sum_ms=sum(call["encode_connect_write_ms"] or 0 for call in calls),
            sent_to_received_sum_ms=sum(call["sent_to_received_ms"] or 0 for call in calls),
            decode_tail_sum_ms=sum(call["decode_tail_ms"] or 0 for call in calls),
            application_request_bytes=sum(call["application_request_bytes"] for call in calls),
            application_response_bytes=sum(call["application_response_bytes"] for call in calls),
        ))
    rpc_wall = covered_wall((rpc["approx_start_ms"], rpc["time_ms"]) for rpc in rpcs)
    return dict(
        summary=summary,
        completed_rpcs=len(rpcs),
        failed_rpcs=sum(not rpc["succeeded"] for rpc in rpcs),
        rpc_covered_wall_ms=rpc_wall,
        no_owner_rpc_inflight_wall_ms=summary["elapsed_ms"] - rpc_wall,
        operations=sorted(operations, key=lambda operation: operation["rpc_elapsed_sum_ms"],
                          reverse=True),
        largest_no_owner_rpc_inflight_gaps=local_gaps(rpcs, summary["elapsed_ms"]),
        rpcs=rpcs,
        interpretation=("RPC phases combine client codec/TLS/write and server/read work. "
                        "Gaps combine local verification/staging/request construction. "
                        "Overlapping RPC elapsed sums are not exclusive critical-path costs."),
    )


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("log", type=Path, help="one complete process-fixture output log")
    log = parser.parse_args().log
    summary, records = load_records(log)
    result = analyze(summary, records)
    log.with_name("trace.jsonl").write_text(
        "\n".join(json.dumps(record) for record in records) + "\n", encoding="utf-8")
    log.with_name("analysis.json").write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")
    print(json.dumps({key: value for key, value in result.items() if key != "rpcs"}, indent=2))


if __name__ == "__main__":
    main()
