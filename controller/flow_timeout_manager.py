"""
Flow Rule Timeout Manager
=========================
Implements timeout-based flow rule management in a simulated SDN environment.
Supports:
  - Idle timeout configuration
  - Hard timeout configuration
  - Expired rule removal
  - Rule lifecycle demonstration
  - Behavior analysis and logging
"""

import time
import threading
import logging
import json
import uuid
from enum import Enum
from dataclasses import dataclass, field, asdict
from typing import Optional, Dict, List

# ─────────────────────────────────────────────
# Setup Logging
# ─────────────────────────────────────────────
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    handlers=[
        logging.StreamHandler(),
        logging.FileHandler("logs/flow_manager.log", mode="w"),
    ],
)
logger = logging.getLogger(__name__)


# ─────────────────────────────────────────────
# Enums & Data Structures
# ─────────────────────────────────────────────
class FlowState(Enum):
    ACTIVE = "ACTIVE"
    IDLE_EXPIRED = "IDLE_EXPIRED"
    HARD_EXPIRED = "HARD_EXPIRED"
    REMOVED = "REMOVED"


@dataclass
class FlowMatch:
    """Represents the match fields of a flow rule."""
    src_ip: str = "0.0.0.0"
    dst_ip: str = "0.0.0.0"
    src_port: Optional[int] = None
    dst_port: Optional[int] = None
    protocol: str = "TCP"

    def __str__(self):
        return (f"{self.protocol} {self.src_ip}:{self.src_port or '*'} "
                f"-> {self.dst_ip}:{self.dst_port or '*'}")


@dataclass
class FlowAction:
    """Represents the action(s) for a flow rule."""
    action_type: str = "FORWARD"   # FORWARD, DROP, FLOOD
    output_port: Optional[int] = None

    def __str__(self):
        if self.output_port:
            return f"{self.action_type} -> port {self.output_port}"
        return self.action_type


@dataclass
class FlowRule:
    """
    A single flow rule with timeout management.

    Attributes:
        rule_id       : Unique identifier
        match         : Match fields
        action        : Action to apply
        priority      : Rule priority (higher = matched first)
        idle_timeout  : Seconds of inactivity before expiry (0 = never)
        hard_timeout  : Absolute lifetime in seconds (0 = never)
        created_at    : Unix timestamp of creation
        last_matched  : Unix timestamp of last packet match
        state         : Current lifecycle state
        packet_count  : Total packets matched
        byte_count    : Total bytes matched
    """
    match: FlowMatch
    action: FlowAction
    priority: int = 100
    idle_timeout: int = 10       # seconds; 0 = disabled
    hard_timeout: int = 60       # seconds; 0 = disabled
    rule_id: str = field(default_factory=lambda: str(uuid.uuid4())[:8])
    created_at: float = field(default_factory=time.time)
    last_matched: float = field(default_factory=time.time)
    state: FlowState = FlowState.ACTIVE
    packet_count: int = 0
    byte_count: int = 0

    # ── Timeout checks ──────────────────────────────────────────────────────
    def is_idle_expired(self) -> bool:
        if self.idle_timeout == 0:
            return False
        return (time.time() - self.last_matched) >= self.idle_timeout

    def is_hard_expired(self) -> bool:
        if self.hard_timeout == 0:
            return False
        return (time.time() - self.created_at) >= self.hard_timeout

    def idle_remaining(self) -> float:
        if self.idle_timeout == 0:
            return float("inf")
        return max(0.0, self.idle_timeout - (time.time() - self.last_matched))

    def hard_remaining(self) -> float:
        if self.hard_timeout == 0:
            return float("inf")
        return max(0.0, self.hard_timeout - (time.time() - self.created_at))

    def age(self) -> float:
        return time.time() - self.created_at

    # ── Packet hit ──────────────────────────────────────────────────────────
    def on_packet_match(self, pkt_size_bytes: int = 64, pkt_size: int = None):
        """Called whenever a packet matches this rule."""
        if pkt_size is not None:
            pkt_size_bytes = pkt_size
        self.last_matched = time.time()
        self.packet_count += 1
        self.byte_count += pkt_size_bytes

    def summary(self) -> str:
        return (f"[{self.rule_id}] {self.match} | {self.action} "
                f"| state={self.state.value} "
                f"| pkts={self.packet_count} bytes={self.byte_count} "
                f"| idle_rem={self.idle_remaining():.1f}s "
                f"| hard_rem={self.hard_remaining():.1f}s")


# ─────────────────────────────────────────────
# Flow Table (simulated switch flow table)
# ─────────────────────────────────────────────
class FlowTable:
    """
    Simulates an OpenFlow-style flow table with timeout enforcement.
    A background thread scans rules every `scan_interval` seconds.
    """

    def __init__(self, scan_interval: float = 1.0):
        self._rules: Dict[str, FlowRule] = {}
        self._lock = threading.Lock()
        self._scan_interval = scan_interval
        self._running = False
        self._removed_rules: List[FlowRule] = []   # audit log
        self._thread: Optional[threading.Thread] = None

        # Statistics
        self.stats = {
            "total_added": 0,
            "total_idle_expired": 0,
            "total_hard_expired": 0,
            "total_removed_manually": 0,
        }

    # ── Lifecycle ────────────────────────────────────────────────────────────
    def start(self):
        """Start the background timeout-checker thread."""
        self._running = True
        self._thread = threading.Thread(
            target=self._scan_loop, daemon=True, name="TimeoutScanner"
        )
        self._thread.start()
        logger.info("FlowTable started — timeout scanner active (interval=%.1fs)",
                    self._scan_interval)

    def stop(self):
        """Gracefully stop the scanner."""
        self._running = False
        if self._thread:
            self._thread.join(timeout=3)
        logger.info("FlowTable stopped.")

    # ── Rule management ──────────────────────────────────────────────────────
    def add_rule(self, rule: FlowRule) -> str:
        with self._lock:
            self._rules[rule.rule_id] = rule
            self.stats["total_added"] += 1
        logger.info("ADDED   rule %s | idle=%ds hard=%ds | %s -> %s",
                    rule.rule_id, rule.idle_timeout, rule.hard_timeout,
                    rule.match, rule.action)
        return rule.rule_id

    def remove_rule(self, rule_id: str, reason: str = "manual") -> bool:
        with self._lock:
            rule = self._rules.pop(rule_id, None)
            if rule:
                # Only overwrite state if it hasn't been set to a specific expiry reason
                if rule.state == FlowState.ACTIVE:
                    rule.state = FlowState.REMOVED
                self._removed_rules.append(rule)
                if reason == "manual":
                    self.stats["total_removed_manually"] += 1
                logger.info("REMOVED rule %s (reason=%s)", rule_id, reason)
                return True
        return False

    def get_rule(self, rule_id: str) -> Optional[FlowRule]:
        with self._lock:
            return self._rules.get(rule_id)

    def match_packet(self, rule_id: str, pkt_size: int = 64):
        """Simulate a packet arriving that matches a specific rule."""
        with self._lock:
            rule = self._rules.get(rule_id)
            if rule and rule.state == FlowState.ACTIVE:
                rule.on_packet_match(pkt_size)
                logger.debug("MATCH   rule %s pkt_size=%dB", rule_id, pkt_size)
                return True
        return False

    def list_rules(self) -> List[FlowRule]:
        with self._lock:
            return list(self._rules.values())

    def get_removed_log(self) -> List[FlowRule]:
        return list(self._removed_rules)

    # ── Background scanner ───────────────────────────────────────────────────
    def _scan_loop(self):
        """Periodically check all rules for timeout expiry."""
        while self._running:
            time.sleep(self._scan_interval)
            self._enforce_timeouts()

    def _enforce_timeouts(self):
        expired_ids = []
        with self._lock:
            for rule_id, rule in self._rules.items():
                if rule.state != FlowState.ACTIVE:
                    continue
                if rule.is_hard_expired():
                    rule.state = FlowState.HARD_EXPIRED
                    expired_ids.append((rule_id, "hard_timeout"))
                elif rule.is_idle_expired():
                    rule.state = FlowState.IDLE_EXPIRED
                    expired_ids.append((rule_id, "idle_timeout"))

        # Remove outside lock to avoid deadlock
        for rule_id, reason in expired_ids:
            if reason == "hard_timeout":
                self.stats["total_hard_expired"] += 1
            else:
                self.stats["total_idle_expired"] += 1
            self.remove_rule(rule_id, reason=reason)

    # ── Display ──────────────────────────────────────────────────────────────
    def print_table(self):
        rules = self.list_rules()
        print("\n" + "=" * 80)
        print(f"  FLOW TABLE  ({len(rules)} active rules)")
        print("=" * 80)
        if not rules:
            print("  (empty)")
        for r in sorted(rules, key=lambda x: x.priority, reverse=True):
            print(f"  {r.summary()}")
        print("=" * 80 + "\n")

    def print_stats(self):
        print("\n── Flow Table Statistics ──────────────────────────────────")
        for k, v in self.stats.items():
            print(f"  {k:30s}: {v}")
        print(f"  {'currently_active':30s}: {len(self._rules)}")
        print(f"  {'total_in_audit_log':30s}: {len(self._removed_rules)}")
        print("──────────────────────────────────────────────────────────\n")

    def export_log(self, filepath: str = "logs/audit_log.json"):
        """Export removed-rule audit log to JSON."""
        data = []
        for r in self._removed_rules:
            d = {
                "rule_id": r.rule_id,
                "state": r.state.value,
                "match": str(r.match),
                "action": str(r.action),
                "priority": r.priority,
                "idle_timeout": r.idle_timeout,
                "hard_timeout": r.hard_timeout,
                "age_seconds": round(r.age(), 2),
                "packet_count": r.packet_count,
                "byte_count": r.byte_count,
            }
            data.append(d)
        with open(filepath, "w") as f:
            json.dump(data, f, indent=2)
        logger.info("Audit log exported → %s (%d entries)", filepath, len(data))
