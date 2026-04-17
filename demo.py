"""
demo.py — Flow Rule Timeout Manager: Full Lifecycle Demonstration
=================================================================
Demonstrates:
  1. Adding rules with different idle/hard timeouts
  2. Simulating packet traffic
  3. Watching idle-timeout expiry (rule with no traffic)
  4. Watching hard-timeout expiry (rule expires regardless of traffic)
  5. Manual rule removal
  6. Behavior analysis & statistics
  7. Audit log export
"""

import time
import sys
import os

# Make sure controller module is importable
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from controller.flow_timeout_manager import (
    FlowTable, FlowRule, FlowMatch, FlowAction, FlowState
)

# ─────────────────────────────────────────────────────────────────────────────
def separator(title: str):
    print(f"\n{'─'*70}")
    print(f"  {title}")
    print(f"{'─'*70}")


# ─────────────────────────────────────────────────────────────────────────────
def demo_section_1_basic_add(table: FlowTable):
    """Add several rules with varied timeout settings."""
    separator("SECTION 1 — Adding Flow Rules")

    rules = [
        FlowRule(
            match=FlowMatch(src_ip="10.0.0.1", dst_ip="10.0.0.2",
                            src_port=5000, dst_port=80, protocol="TCP"),
            action=FlowAction(action_type="FORWARD", output_port=2),
            priority=200,
            idle_timeout=5,    # expires after 5s inactivity
            hard_timeout=30,
        ),
        FlowRule(
            match=FlowMatch(src_ip="10.0.0.3", dst_ip="10.0.0.4",
                            protocol="UDP"),
            action=FlowAction(action_type="FORWARD", output_port=3),
            priority=150,
            idle_timeout=8,    # expires after 8s inactivity
            hard_timeout=20,
        ),
        FlowRule(
            match=FlowMatch(src_ip="192.168.1.0", dst_ip="0.0.0.0",
                            protocol="ICMP"),
            action=FlowAction(action_type="DROP"),
            priority=300,
            idle_timeout=0,    # idle timeout DISABLED
            hard_timeout=12,   # hard expires in 12s regardless
        ),
        FlowRule(
            match=FlowMatch(src_ip="10.0.0.5", dst_ip="10.0.0.6",
                            dst_port=443, protocol="TCP"),
            action=FlowAction(action_type="FORWARD", output_port=4),
            priority=100,
            idle_timeout=15,
            hard_timeout=0,    # hard timeout DISABLED (lives until idle)
        ),
    ]

    ids = []
    for r in rules:
        ids.append(table.add_rule(r))

    print("\n  Rules added successfully.")
    table.print_table()
    return ids


# ─────────────────────────────────────────────────────────────────────────────
def demo_section_2_packet_simulation(table: FlowTable, rule_ids: list):
    """Simulate packets hitting some rules to refresh their idle timers."""
    separator("SECTION 2 — Simulating Packet Traffic")

    # Rules 0, 3 receive traffic → idle timer refreshed
    # Rules 1, 2 receive NO traffic → will idle-expire / hard-expire
    active_rules = [rule_ids[0], rule_ids[3]]

    print(f"\n  Sending 3 rounds of packets to rules: {active_rules}")
    for rnd in range(3):
        for rid in active_rules:
            table.match_packet(rid, pkt_size=512)
        print(f"  Round {rnd+1}: packets sent → idle timers refreshed for {active_rules}")
        time.sleep(1)

    print("\n  Rules 1 and 2 received NO packets.")
    table.print_table()


# ─────────────────────────────────────────────────────────────────────────────
def demo_section_3_watch_idle_expiry(table: FlowTable, rule_ids: list):
    """Wait and watch rule 1 idle-expire (8s idle timeout)."""
    separator("SECTION 3 — Watching Idle-Timeout Expiry")
    print("\n  Waiting ~9 seconds for rule[1] (idle_timeout=8s) to expire...")
    print("  (Rule[0] keeps receiving traffic so it stays alive)\n")

    for i in range(9):
        # Keep refreshing rule[0] with traffic
        table.match_packet(rule_ids[0], pkt_size=128)
        time.sleep(1)
        rule1 = table.get_rule(rule_ids[1])
        status = rule1.state.value if rule1 else "REMOVED from table"
        print(f"  t+{i+1}s | rule[1] status: {status}")

    table.print_table()


# ─────────────────────────────────────────────────────────────────────────────
def demo_section_4_watch_hard_expiry(table: FlowTable, rule_ids: list):
    """Wait and watch rule 2 hard-expire (hard_timeout=12s)."""
    separator("SECTION 4 — Watching Hard-Timeout Expiry")
    print("\n  Waiting for rule[2] (hard_timeout=12s, no idle_timeout) to hard-expire...")
    print("  Even though rule[2] could receive traffic, hard timeout is absolute.\n")

    for i in range(5):
        table.match_packet(rule_ids[0], pkt_size=64)
        time.sleep(1)
        rule2 = table.get_rule(rule_ids[2])
        status = rule2.state.value if rule2 else "REMOVED from table"
        print(f"  t+{i+1}s | rule[2] status: {status}")

    table.print_table()


# ─────────────────────────────────────────────────────────────────────────────
def demo_section_5_manual_removal(table: FlowTable, rule_ids: list):
    """Manually remove a rule."""
    separator("SECTION 5 — Manual Rule Removal")
    rid = rule_ids[3]
    rule = table.get_rule(rid)
    if rule:
        print(f"\n  Manually removing rule[3] ({rid}) — {rule.summary()}")
        table.remove_rule(rid, reason="manual")
        print("  Rule removed.")
    else:
        print(f"\n  Rule[3] ({rid}) already expired or removed.")

    table.print_table()


# ─────────────────────────────────────────────────────────────────────────────
def demo_section_6_analysis(table: FlowTable):
    """Print statistics and analysis."""
    separator("SECTION 6 — Behavior Analysis & Statistics")
    table.print_stats()

    removed = table.get_removed_log()
    print(f"\n  Removed Rules Audit Log ({len(removed)} entries):")
    print(f"  {'Rule ID':12} {'Reason':20} {'Pkts':>6} {'Bytes':>8} {'Age(s)':>8}")
    print(f"  {'─'*60}")
    for r in removed:
        print(f"  {r.rule_id:12} {r.state.value:20} "
              f"{r.packet_count:6} {r.byte_count:8} {r.age():8.1f}")

    table.export_log("logs/audit_log.json")
    print("\n  Full audit log saved → logs/audit_log.json")


# ─────────────────────────────────────────────────────────────────────────────
def main():
    print("\n" + "=" * 70)
    print("   FLOW RULE TIMEOUT MANAGER — LIFECYCLE DEMONSTRATION")
    print("=" * 70)

    # Create and start the flow table with 1-second scanner interval
    table = FlowTable(scan_interval=1.0)
    table.start()

    try:
        ids = demo_section_1_basic_add(table)
        demo_section_2_packet_simulation(table, ids)
        demo_section_3_watch_idle_expiry(table, ids)
        demo_section_4_watch_hard_expiry(table, ids)
        demo_section_5_manual_removal(table, ids)
        demo_section_6_analysis(table)
    finally:
        table.stop()

    print("\n✔  Demo complete. Check logs/ directory for output files.\n")


if __name__ == "__main__":
    main()
