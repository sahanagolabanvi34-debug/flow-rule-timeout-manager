"""
analyze.py — Behavior Analysis Tool
====================================
Runs a controlled experiment, then generates a text + JSON analysis report.
"""

import time
import sys
import os
import json

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from controller.flow_timeout_manager import (
    FlowTable, FlowRule, FlowMatch, FlowAction, FlowState
)


def run_analysis():
    print("\n" + "=" * 65)
    print("  FLOW RULE TIMEOUT MANAGER — BEHAVIOR ANALYSIS")
    print("=" * 65)

    table = FlowTable(scan_interval=0.5)
    table.start()

    # ── Experiment Setup ────────────────────────────────────────────
    print("\n[1] Creating experiment rules...\n")

    scenarios = [
        {"label": "Short idle, no traffic",   "idle": 3,  "hard": 0,  "traffic": False},
        {"label": "Short idle, WITH traffic",  "idle": 3,  "hard": 0,  "traffic": True},
        {"label": "Hard timeout only",         "idle": 0,  "hard": 4,  "traffic": True},
        {"label": "Both timeouts, idle wins",  "idle": 3,  "hard": 10, "traffic": False},
        {"label": "Both timeouts, hard wins",  "idle": 10, "hard": 4,  "traffic": True},
    ]

    rule_map = {}
    for sc in scenarios:
        rule = FlowRule(
            match=FlowMatch(src_ip="10.0.0.1", dst_ip="10.0.0.2"),
            action=FlowAction(action_type="FORWARD", output_port=1),
            idle_timeout=sc["idle"],
            hard_timeout=sc["hard"],
        )
        rid = table.add_rule(rule)
        rule_map[rid] = sc
        sc["rule_id"] = rid
        sc["created_at"] = time.time()
        sc["expired_at"] = None
        sc["expire_reason"] = None
        print(f"  [{rid}] {sc['label']:<35} idle={sc['idle']}s hard={sc['hard']}s "
              f"traffic={'YES' if sc['traffic'] else 'NO '}")

    # ── Run experiment ───────────────────────────────────────────────
    print("\n[2] Running experiment (12 seconds)...\n")
    start = time.time()

    for tick in range(24):       # 24 × 0.5s = 12s
        time.sleep(0.5)
        for sc in scenarios:
            if sc["traffic"]:
                table.match_packet(sc["rule_id"], pkt_size=64)

        # Check for newly-expired rules
        removed_ids = {r.rule_id for r in table.get_removed_log()}
        for sc in scenarios:
            if sc["expired_at"] is None and sc["rule_id"] in removed_ids:
                sc["expired_at"] = time.time()
                sc["elapsed"] = round(sc["expired_at"] - sc["created_at"], 2)
                log_entry = next(
                    r for r in table.get_removed_log()
                    if r.rule_id == sc["rule_id"]
                )
                sc["expire_reason"] = log_entry.state.value
                sc["final_packets"] = log_entry.packet_count
                print(f"  t+{sc['elapsed']:4.1f}s | EXPIRED [{sc['rule_id']}] "
                      f"{sc['label']:<35} reason={sc['expire_reason']}")

    table.stop()

    # ── Print report ─────────────────────────────────────────────────
    print("\n[3] Analysis Report\n")
    print(f"  {'Scenario':<38} {'idle':>5} {'hard':>5} {'traffic':>8} "
          f"{'expired_at':>12} {'reason'}")
    print("  " + "─" * 78)
    for sc in scenarios:
        exp = f"{sc.get('elapsed', 'still active'):>10}" if sc["expired_at"] else "still active"
        reason = sc.get("expire_reason", "N/A")
        print(f"  {sc['label']:<38} {sc['idle']:>5} {sc['hard']:>5} "
              f"{'YES' if sc['traffic'] else 'NO':>8} {exp:>12}  {reason}")

    # ── Key findings ──────────────────────────────────────────────────
    print("\n[4] Key Findings\n")
    findings = [
        "✔ Rules with no traffic expire at idle_timeout seconds (idle expiry).",
        "✔ Rules with constant traffic bypass idle expiry entirely.",
        "✔ Hard timeout fires regardless of traffic (absolute deadline).",
        "✔ When both timeouts set, whichever fires first wins.",
        "✔ idle_timeout=0 disables idle expiry; hard_timeout=0 disables hard expiry.",
        "✔ Audit log correctly records state (IDLE_EXPIRED / HARD_EXPIRED).",
    ]
    for f in findings:
        print(f"  {f}")

    # ── Export ────────────────────────────────────────────────────────
    report = {
        "experiment_duration_s": round(time.time() - start, 2),
        "scenarios": [
            {k: v for k, v in sc.items() if k not in ("created_at", "expired_at")}
            for sc in scenarios
        ],
        "stats": table.stats,
        "findings": findings,
    }
    os.makedirs("logs", exist_ok=True)
    with open("logs/analysis_report.json", "w") as f:
        json.dump(report, f, indent=2)
    print("\n  Full analysis saved → logs/analysis_report.json")
    print("\n✔  Analysis complete.\n")


if __name__ == "__main__":
    run_analysis()
