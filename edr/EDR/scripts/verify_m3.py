#!/usr/bin/env python3
import argparse
import json
import os
import resource
import sys
from datetime import datetime, time
from pathlib import Path


def load_json(path):
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)


def contains(haystack, needle):
    return needle in haystack


def match(rule_match, subject, obj):
    checks = [
        ("process_name", lambda v: v.lower() == subject.get("process_name", "").lower()),
        ("process_path", lambda v: v == subject.get("process_path", "")),
        ("cmdline_contains", lambda v: contains(subject.get("cmdline", ""), v)),
        ("user", lambda v: v == subject.get("user", "")),
        ("file_path", lambda v: v == obj.get("file_path", "")),
        ("file_path_prefix", lambda v: obj.get("file_path", "").startswith(v)),
        ("remote_addr", lambda v: v == obj.get("remote_addr", "")),
        ("local_port", lambda v: int(v) == int(obj.get("local_port", 0))),
        ("protocol", lambda v: v.lower() == obj.get("protocol", "").lower()),
    ]
    for key, pred in checks:
        if key in rule_match and not pred(rule_match[key]):
            return False
    return True


def in_window(rule):
    tw = rule.get("time_window")
    if not tw:
        return True
    now = datetime.now().time()
    start = time.fromisoformat(tw["start"])
    end = time.fromisoformat(tw["end"])
    if start <= end:
        return start <= now <= end
    return now >= start or now <= end


def evaluate_process_access(policy, sample):
    pa = policy.get("process_access", {})
    if not pa:
        return None
    subject = sample.get("subject", {})
    for wl in pa.get("whitelist", []):
        if match(wl, subject, sample.get("object", {})):
            return {"detected": False, "decision": "allow", "rule_id": "process-access-whitelist"}
    for bl in pa.get("blacklist", []):
        if match(bl, subject, sample.get("object", {})):
            mode = pa.get("mode", "monitor")
            return {"detected": True, "decision": "block" if mode == "enforce" else "alert", "rule_id": "process-access-blacklist"}
    if pa.get("mode") == "enforce" and pa.get("whitelist"):
        return {"detected": True, "decision": "block", "rule_id": "process-access-default-deny"}
    return None


def evaluate(policy, sample):
    access = evaluate_process_access(policy, sample)
    if access is not None:
        return access
    subject = sample.get("subject", {})
    obj = sample.get("object", {})
    for rule in policy.get("rules", []):
        if rule.get("enabled", True) is False:
            continue
        if not in_window(rule):
            continue
        if not match(rule.get("match", {}), subject, obj):
            continue
        for wl in rule.get("whitelist", []):
            if match(wl, subject, obj):
                return {"detected": False, "decision": "allow", "rule_id": rule["id"]}
        return {"detected": rule.get("decision") != "allow", "decision": rule.get("decision"), "rule_id": rule["id"]}
    return {"detected": False, "decision": "none", "rule_id": ""}


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--policy", default="configs/policy.json")
    ap.add_argument("--samples", default="testdata/samples/m3_samples.json")
    ap.add_argument("--out", default="audit/verify-m3-report.json")
    ap.add_argument("--min-detections", type=int, default=6)
    ap.add_argument("--max-fp", type=int, default=2)
    args = ap.parse_args()

    policy = load_json(args.policy)
    samples = load_json(args.samples)["samples"]
    if policy.get("schema_version") != "v0.1":
        raise SystemExit("policy schema_version must be v0.1")

    results = []
    detections = 0
    false_positives = 0
    malicious_total = 0
    benign_total = 0
    for sample in samples:
        res = evaluate(policy, sample)
        malicious = bool(sample.get("malicious"))
        malicious_total += 1 if malicious else 0
        benign_total += 0 if malicious else 1
        if malicious and res["detected"]:
            detections += 1
        if not malicious and res["detected"]:
            false_positives += 1
        results.append({"sample_id": sample["id"], "malicious": malicious, **res})

    process_access_ok = all(
        (item["sample_id"] != "S09" or (item["detected"] and item["rule_id"] == "process-access-blacklist"))
        and (item["sample_id"] != "F09" or (not item["detected"] and item["decision"] == "allow"))
        for item in results
    )

    usage = resource.getrusage(resource.RUSAGE_SELF)
    report = {
        "schema_version": "v0.1",
        "gate": "verify-m3",
        "passed": detections >= args.min_detections and false_positives <= args.max_fp and process_access_ok,
        "thresholds": {"min_detections": args.min_detections, "max_false_positives": args.max_fp},
        "metrics": {
            "detections": detections,
            "malicious_total": malicious_total,
            "false_positives": false_positives,
            "benign_total": benign_total,
            "max_rss_kb": usage.ru_maxrss,
            "user_cpu_sec": usage.ru_utime,
            "sys_cpu_sec": usage.ru_stime,
            "process_access_ok": process_access_ok,
        },
        "results": results,
    }
    Path(args.out).parent.mkdir(parents=True, exist_ok=True)
    with open(args.out, "w", encoding="utf-8") as f:
        json.dump(report, f, indent=2)
        f.write("\n")
    print(json.dumps(report["metrics"], indent=2))
    print("PASS" if report["passed"] else "FAIL")
    return 0 if report["passed"] else 1

if __name__ == "__main__":
    raise SystemExit(main())
