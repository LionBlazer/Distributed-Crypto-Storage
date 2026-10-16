"""Analyze bounded metadata from the opt-in genuine UPDATE process fixture."""
import argparse
import json
import math
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
    validate_envelope(summary, records)
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


def nonnegative_number(value, field):
    if type(value) not in (int, float) or not math.isfinite(value) or value < 0:
        raise ValueError(f"{field} must be finite and nonnegative")
    return value


def nonnegative_integer(value, field):
    if type(value) is not int or value < 0:
        raise ValueError(f"{field} must be a nonnegative integer")
    return value


def validate_envelope(summary, records):
    if [record for record in records if record["event"] == "summary"] != [summary]:
        raise ValueError("expected one complete UPDATE observation envelope")
    nonnegative_number(summary["elapsed_ms"], "UPDATE elapsed_ms")
    count = nonnegative_integer(summary["event_count"], "event_count")
    if (summary["truncated"] is not False or summary["event_limit"] != MAX_EVENTS
            or count > MAX_EVENTS or count != len(records) - 1):
        raise ValueError("incomplete or truncated observation cannot explain a full query")


def checked_rpcs(summary, records):
    validate_envelope(summary, records)
    activity, complete = {}, {}
    for record in records:
        event = record["event"]
        if event == "summary":
            continue
        if event not in ("activity", "complete"):
            raise ValueError("unknown observation event")
        key = tuple(nonnegative_integer(record[field], field) for field in ("peer", "request_id"))
        if not isinstance(record["operation"], str) or not record["operation"]:
            raise ValueError("RPC operation must be a nonempty string")
        time = nonnegative_number(record["time_ms"], "RPC time_ms")
        if time > summary["elapsed_ms"]:
            raise ValueError("RPC lies outside the UPDATE envelope")
        if event == "activity":
            phase = record["phase"]
            if phase not in ("request_sent", "reply_received"):
                raise ValueError("unknown RPC activity phase")
            phases = activity.setdefault(key, {})
            if phase in phases:
                raise ValueError("duplicate RPC activity phase")
            nonnegative_integer(record["application_bytes"], "application_bytes")
            phases[phase] = record
        else:
            if key in complete:
                raise ValueError("duplicate RPC completion")
            complete[key] = record
    if activity.keys() - complete.keys():
        raise ValueError("RPC activity has no completion")

    rpcs = []
    for key, record in complete.items():
        rpc = dict(record)
        start, end = nonnegative_number(rpc["approx_start_ms"], "RPC start"), rpc["time_ms"]
        nonnegative_number(rpc["elapsed_ms"], "RPC elapsed_ms")
        if start > end or rpc["elapsed_ms"] > end or type(rpc["succeeded"]) is not bool:
            raise ValueError("invalid RPC interval or success marker")
        phases = activity.get(key, {})
        if rpc["succeeded"] and set(phases) != {"request_sent", "reply_received"}:
            raise ValueError("successful RPC requires sent and received frames")
        previous = start
        for phase, field in (("request_sent", "application_request_bytes"),
                             ("reply_received", "application_response_bytes")):
            size = nonnegative_integer(rpc[field], field)
            if phase in phases:
                frame = phases[phase]
                if (frame["operation"] != rpc["operation"] or frame["application_bytes"] != size
                        or not previous <= frame["time_ms"] <= end):
                    raise ValueError("RPC frame order, operation or byte count disagrees with Trace")
                previous = frame["time_ms"]
        sent = phases.get("request_sent", {}).get("time_ms")
        received = phases.get("reply_received", {}).get("time_ms")
        rpc["encode_connect_write_ms"] = sent - start if sent is not None else None
        rpc["sent_to_received_ms"] = (received - sent
                                      if sent is not None and received is not None else None)
        rpc["decode_tail_ms"] = end - received if received is not None else None
        rpcs.append(rpc)
    return rpcs


def analyze(summary, records):
    rpcs, by_operation = checked_rpcs(summary, records), defaultdict(list)
    for rpc in rpcs:
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
