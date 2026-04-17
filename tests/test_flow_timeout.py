"""
tests/test_flow_timeout.py — Regression Tests
=============================================
Ensures timeout behavior remains consistent across changes.

Run with:
    python -m pytest tests/ -v
or:
    python tests/test_flow_timeout.py
"""

import time
import sys
import os
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from controller.flow_timeout_manager import (
    FlowTable, FlowRule, FlowMatch, FlowAction, FlowState
)


def make_rule(idle=5, hard=10, priority=100):
    return FlowRule(
        match=FlowMatch(src_ip="10.0.0.1", dst_ip="10.0.0.2"),
        action=FlowAction(action_type="FORWARD", output_port=1),
        priority=priority,
        idle_timeout=idle,
        hard_timeout=hard,
    )


# ─────────────────────────────────────────────────────────────────────────────
class TestFlowRuleTimeoutDetection(unittest.TestCase):
    """Unit tests for individual FlowRule timeout logic."""

    def test_newly_created_rule_is_not_expired(self):
        rule = make_rule(idle=5, hard=10)
        self.assertFalse(rule.is_idle_expired())
        self.assertFalse(rule.is_hard_expired())

    def test_idle_timeout_zero_never_expires(self):
        rule = make_rule(idle=0, hard=10)
        rule.last_matched = time.time() - 999  # far in the past
        self.assertFalse(rule.is_idle_expired())

    def test_hard_timeout_zero_never_expires(self):
        rule = make_rule(idle=5, hard=0)
        rule.created_at = time.time() - 999
        self.assertFalse(rule.is_hard_expired())

    def test_idle_timeout_triggers(self):
        rule = make_rule(idle=2, hard=30)
        rule.last_matched = time.time() - 3   # 3 seconds ago (> 2s timeout)
        self.assertTrue(rule.is_idle_expired())

    def test_hard_timeout_triggers(self):
        rule = make_rule(idle=30, hard=2)
        rule.created_at = time.time() - 3   # created 3 seconds ago (> 2s timeout)
        self.assertTrue(rule.is_hard_expired())

    def test_packet_match_resets_idle_timer(self):
        rule = make_rule(idle=2, hard=30)
        rule.last_matched = time.time() - 1.5  # nearly expired
        rule.on_packet_match(pkt_size=100)
        self.assertFalse(rule.is_idle_expired())

    def test_packet_match_does_not_reset_hard_timer(self):
        rule = make_rule(idle=30, hard=2)
        rule.created_at = time.time() - 3
        rule.on_packet_match(pkt_size=100)
        self.assertTrue(rule.is_hard_expired())

    def test_packet_count_increments(self):
        rule = make_rule()
        for _ in range(5):
            rule.on_packet_match(pkt_size=64)
        self.assertEqual(rule.packet_count, 5)
        self.assertEqual(rule.byte_count, 320)

    def test_remaining_time_decreases(self):
        rule = make_rule(idle=10, hard=20)
        r1 = rule.idle_remaining()
        time.sleep(0.1)
        r2 = rule.idle_remaining()
        self.assertLess(r2, r1)


# ─────────────────────────────────────────────────────────────────────────────
class TestFlowTableOperations(unittest.TestCase):
    """Integration tests for FlowTable with background scanner."""

    def setUp(self):
        self.table = FlowTable(scan_interval=0.5)
        self.table.start()

    def tearDown(self):
        self.table.stop()

    def test_rule_added_and_retrievable(self):
        rule = make_rule(idle=30, hard=60)
        rid = self.table.add_rule(rule)
        fetched = self.table.get_rule(rid)
        self.assertIsNotNone(fetched)
        self.assertEqual(fetched.rule_id, rid)

    def test_manual_removal(self):
        rule = make_rule(idle=30, hard=60)
        rid = self.table.add_rule(rule)
        self.table.remove_rule(rid)
        self.assertIsNone(self.table.get_rule(rid))

    def test_idle_expiry_removes_rule(self):
        rule = make_rule(idle=1, hard=60)    # 1s idle timeout
        rid = self.table.add_rule(rule)
        time.sleep(2.5)                       # wait for scan + expiry
        self.assertIsNone(self.table.get_rule(rid),
                          "Rule should have been idle-expired and removed")

    def test_hard_expiry_removes_rule(self):
        rule = make_rule(idle=0, hard=1)     # 1s hard timeout, no idle
        rid = self.table.add_rule(rule)
        # Keep sending packets so idle timer won't trigger
        for _ in range(4):
            self.table.match_packet(rid, pkt_size=64)
            time.sleep(0.3)
        time.sleep(1.0)                       # total ~2.2s > 1s hard timeout
        self.assertIsNone(self.table.get_rule(rid),
                          "Rule should have been hard-expired and removed")

    def test_traffic_prevents_idle_expiry(self):
        rule = make_rule(idle=2, hard=60)    # 2s idle timeout
        rid = self.table.add_rule(rule)
        # Refresh every 1s for 3 rounds → should NOT expire
        for _ in range(3):
            time.sleep(1.0)
            self.table.match_packet(rid, pkt_size=64)
        self.assertIsNotNone(self.table.get_rule(rid),
                             "Rule should still be active after repeated traffic")

    def test_stats_track_idle_expired(self):
        before = self.table.stats["total_idle_expired"]
        rule = make_rule(idle=1, hard=30)
        self.table.add_rule(rule)
        time.sleep(2.5)
        after = self.table.stats["total_idle_expired"]
        self.assertGreater(after, before)

    def test_stats_track_hard_expired(self):
        before = self.table.stats["total_hard_expired"]
        rule = make_rule(idle=0, hard=1)
        self.table.add_rule(rule)
        time.sleep(2.5)
        after = self.table.stats["total_hard_expired"]
        self.assertGreater(after, before)

    def test_audit_log_records_removed_rules(self):
        rule = make_rule(idle=1, hard=30)
        rid = self.table.add_rule(rule)
        time.sleep(2.5)
        log = self.table.get_removed_log()
        ids_in_log = [r.rule_id for r in log]
        self.assertIn(rid, ids_in_log)

    def test_multiple_rules_independent_timeouts(self):
        """Rules should expire independently of each other."""
        r1 = make_rule(idle=1, hard=30)    # expires fast
        r2 = make_rule(idle=30, hard=60)   # should stay alive
        rid1 = self.table.add_rule(r1)
        rid2 = self.table.add_rule(r2)

        time.sleep(2.5)

        self.assertIsNone(self.table.get_rule(rid1), "r1 should have expired")
        self.assertIsNotNone(self.table.get_rule(rid2), "r2 should still be active")

    def test_packet_match_returns_false_for_nonexistent_rule(self):
        result = self.table.match_packet("nonexistent_id")
        self.assertFalse(result)


# ─────────────────────────────────────────────────────────────────────────────
class TestRegressionConsistency(unittest.TestCase):
    """
    Regression tests — ensure timeout behavior remains consistent.
    These tests verify exact timing windows to catch regressions.
    """

    def setUp(self):
        self.table = FlowTable(scan_interval=0.5)
        self.table.start()

    def tearDown(self):
        self.table.stop()

    def test_regression_idle_timeout_window(self):
        """Rule must NOT expire before idle_timeout, MUST expire after."""
        rule = make_rule(idle=2, hard=60)
        rid = self.table.add_rule(rule)

        time.sleep(1.0)
        self.assertIsNotNone(
            self.table.get_rule(rid),
            "REGRESSION: Rule expired too early (before idle_timeout)"
        )

        time.sleep(2.0)
        self.assertIsNone(
            self.table.get_rule(rid),
            "REGRESSION: Rule did not expire after idle_timeout elapsed"
        )

    def test_regression_hard_timeout_window(self):
        """Hard timeout must fire even with continuous traffic."""
        rule = make_rule(idle=0, hard=2)
        rid = self.table.add_rule(rule)

        # Send traffic to prevent any idle expiry
        for _ in range(5):
            self.table.match_packet(rid, pkt_size=64)
            time.sleep(0.3)

        time.sleep(1.5)

        self.assertIsNone(
            self.table.get_rule(rid),
            "REGRESSION: Hard timeout did not fire despite elapsed hard_timeout"
        )

    def test_regression_state_transitions(self):
        """Verify correct state value in audit log after expiry."""
        rule = make_rule(idle=1, hard=30)
        rid = self.table.add_rule(rule)
        time.sleep(2.5)

        log = self.table.get_removed_log()
        entry = next((r for r in log if r.rule_id == rid), None)
        self.assertIsNotNone(entry)
        self.assertEqual(
            entry.state, FlowState.IDLE_EXPIRED,
            "REGRESSION: Rule state should be IDLE_EXPIRED in audit log"
        )


# ─────────────────────────────────────────────────────────────────────────────
if __name__ == "__main__":
    unittest.main(verbosity=2)
