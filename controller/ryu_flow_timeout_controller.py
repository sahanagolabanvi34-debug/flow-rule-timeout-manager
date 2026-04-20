"""
ryu_flow_timeout_controller.py
==============================
SDN Flow Rule Timeout Manager — Ryu OpenFlow 1.3 Controller

Implements:
  - Learning switch with MAC address table
  - Explicit flow rule installation with idle_timeout and hard_timeout
  - packet_in event handling with match+action logic
  - Flow removal notifications (EventOFPFlowRemoved) for lifecycle tracking
  - Firewall / blocking rules (drop by src_ip)
  - Logging of all rule additions, expirations, and removals

Author: Kushal G (PES1UG24AM145)
Course: Computer Networks — UE24CS252B
"""

from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER, DEAD_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib.packet import packet, ethernet, ipv4, icmp, tcp, udp
from ryu.lib import hub

import logging
import json
import time
import os

# ─────────────────────────────────────────────
# Logging Setup
# ─────────────────────────────────────────────
os.makedirs("logs", exist_ok=True)

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    handlers=[
        logging.StreamHandler(),
        logging.FileHandler("logs/controller.log", mode="w"),
    ],
)
logger = logging.getLogger("FlowTimeoutController")


# ─────────────────────────────────────────────
# Timeout Constants (seconds)
# ─────────────────────────────────────────────
DEFAULT_IDLE_TIMEOUT = 10   # Rule removed after 10s of no matching traffic
DEFAULT_HARD_TIMEOUT = 30   # Rule removed after 30s regardless of traffic
FIREWALL_IDLE_TIMEOUT = 0   # Firewall rules never idle-expire
FIREWALL_HARD_TIMEOUT = 0   # Firewall rules never hard-expire (permanent block)

# IP to block in Scenario 2 (firewall demo)
BLOCKED_IP = "10.0.0.4"


# ─────────────────────────────────────────────
# Controller Application
# ─────────────────────────────────────────────
class FlowTimeoutController(app_manager.RyuApp):
    """
    A Ryu OpenFlow 1.3 controller that:
      1. Acts as a learning switch (learns src MAC → port mapping)
      2. Installs unicast forwarding rules with configurable idle/hard timeouts
      3. Installs DROP rules for blocked hosts (firewall scenario)
      4. Requests flow-removed notifications to log rule lifecycle events
    """

    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(FlowTimeoutController, self).__init__(*args, **kwargs)

        # MAC learning table: { dpid: { mac_addr: port } }
        self.mac_to_port = {}

        # Audit log: records every installed and removed flow rule
        self.flow_audit_log = []

        # Statistics counters
        self.stats = {
            "total_installed": 0,
            "total_idle_expired": 0,
            "total_hard_expired": 0,
            "total_manually_removed": 0,
            "packet_in_count": 0,
        }

        logger.info("=" * 60)
        logger.info("  Flow Rule Timeout Manager — Ryu Controller Started")
        logger.info("  Idle Timeout  : %ds  |  Hard Timeout : %ds", DEFAULT_IDLE_TIMEOUT, DEFAULT_HARD_TIMEOUT)
        logger.info("  Blocked IP    : %s (firewall rule)", BLOCKED_IP)
        logger.info("=" * 60)

    # ──────────────────────────────────────────────────────────────────────────
    # SWITCH HANDSHAKE — install table-miss entry on connect
    # ──────────────────────────────────────────────────────────────────────────
    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        """
        Called when a switch connects.
        Installs a table-miss flow entry so unmatched packets are sent to
        the controller via packet_in.
        Also installs a permanent DROP rule for the blocked IP (firewall).
        """
        datapath = ev.msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        dpid = datapath.id

        logger.info("Switch connected — DPID: %016x", dpid)

        # ── Table-miss: send all unmatched packets to controller (priority=0) ──
        match = parser.OFPMatch()
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER,
                                          ofproto.OFPCML_NO_BUFFER)]
        self._add_flow(datapath,
                       priority=0,
                       match=match,
                       actions=actions,
                       idle_timeout=0,
                       hard_timeout=0,
                       label="table-miss")

        # ── Firewall: permanently DROP traffic FROM the blocked IP (priority=200) ──
        firewall_match = parser.OFPMatch(eth_type=0x0800,
                                         ipv4_src=BLOCKED_IP)
        self._add_flow(datapath,
                       priority=200,
                       match=firewall_match,
                       actions=[],          # empty actions = DROP
                       idle_timeout=FIREWALL_IDLE_TIMEOUT,
                       hard_timeout=FIREWALL_HARD_TIMEOUT,
                       label=f"FIREWALL DROP src={BLOCKED_IP}")

        logger.info("Firewall rule installed: DROP all traffic from %s", BLOCKED_IP)

    # ──────────────────────────────────────────────────────────────────────────
    # PACKET_IN — learning switch + flow rule installation
    # ──────────────────────────────────────────────────────────────────────────
    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def packet_in_handler(self, ev):
        """
        Handles packets sent to the controller (table-miss or explicit).

        Logic:
          1. Parse Ethernet frame; learn src MAC → ingress port.
          2. If dst MAC is known, install a unicast forwarding rule with
             idle_timeout=DEFAULT_IDLE_TIMEOUT and hard_timeout=DEFAULT_HARD_TIMEOUT.
          3. If dst MAC is unknown, FLOOD the packet.
        """
        msg = ev.msg
        datapath = msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        in_port = msg.match["in_port"]
        dpid = datapath.id

        self.stats["packet_in_count"] += 1

        # Parse the incoming packet
        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocol(ethernet.ethernet)
        if eth is None:
            return  # not an Ethernet frame, ignore

        dst_mac = eth.dst
        src_mac = eth.src

        # Initialise MAC table for this switch if needed
        self.mac_to_port.setdefault(dpid, {})

        # ── Step 1: Learn src MAC → in_port ──────────────────────────────────
        if src_mac not in self.mac_to_port[dpid]:
            logger.info("[dpid=%016x] Learned: %s → port %d", dpid, src_mac, in_port)
        self.mac_to_port[dpid][src_mac] = in_port

        # ── Step 2: Determine output port ────────────────────────────────────
        if dst_mac in self.mac_to_port[dpid]:
            out_port = self.mac_to_port[dpid][dst_mac]
        else:
            out_port = ofproto.OFPP_FLOOD   # unknown dst → flood

        actions = [parser.OFPActionOutput(out_port)]

        # ── Step 3: Install flow rule if dst is known (not a flood) ──────────
        if out_port != ofproto.OFPP_FLOOD:
            # Match on Ethernet src+dst to be specific
            match = parser.OFPMatch(in_port=in_port,
                                    eth_dst=dst_mac,
                                    eth_src=src_mac)
            self._add_flow(datapath,
                           priority=100,
                           match=match,
                           actions=actions,
                           idle_timeout=DEFAULT_IDLE_TIMEOUT,
                           hard_timeout=DEFAULT_HARD_TIMEOUT,
                           label=f"{src_mac}->{dst_mac} port{in_port}→port{out_port}")

        # ── Step 4: Forward the current buffered packet ───────────────────────
        data = None
        if msg.buffer_id == ofproto.OFP_NO_BUFFER:
            data = msg.data

        out = parser.OFPPacketOut(datapath=datapath,
                                  buffer_id=msg.buffer_id,
                                  in_port=in_port,
                                  actions=actions,
                                  data=data)
        datapath.send_msg(out)

    # ──────────────────────────────────────────────────────────────────────────
    # FLOW REMOVED — lifecycle tracking
    # ──────────────────────────────────────────────────────────────────────────
    @set_ev_cls(ofp_event.EventOFPFlowRemoved, MAIN_DISPATCHER)
    def flow_removed_handler(self, ev):
        """
        Called when a flow rule is removed from the switch.
        Reasons:
          OFPRR_IDLE_TIMEOUT (0) — idle timeout expired
          OFPRR_HARD_TIMEOUT (1) — hard timeout expired
          OFPRR_DELETE        (2) — explicitly deleted
        """
        msg = ev.msg
        ofproto = msg.datapath.ofproto

        reason_map = {
            ofproto.OFPRR_IDLE_TIMEOUT: "IDLE_TIMEOUT",
            ofproto.OFPRR_HARD_TIMEOUT: "HARD_TIMEOUT",
            ofproto.OFPRR_DELETE:       "DELETED",
        }
        reason_str = reason_map.get(msg.reason, f"UNKNOWN({msg.reason})")

        # Update statistics
        if msg.reason == ofproto.OFPRR_IDLE_TIMEOUT:
            self.stats["total_idle_expired"] += 1
        elif msg.reason == ofproto.OFPRR_HARD_TIMEOUT:
            self.stats["total_hard_expired"] += 1
        else:
            self.stats["total_manually_removed"] += 1

        logger.info(
            "FLOW REMOVED | reason=%-14s | priority=%d | "
            "duration=%ds | pkts=%d | bytes=%d | match=%s",
            reason_str,
            msg.priority,
            msg.duration_sec,
            msg.packet_count,
            msg.byte_count,
            msg.match,
        )

        # Append to audit log
        self.flow_audit_log.append({
            "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
            "reason": reason_str,
            "priority": msg.priority,
            "duration_sec": msg.duration_sec,
            "packet_count": msg.packet_count,
            "byte_count": msg.byte_count,
            "match": str(msg.match),
        })

        # Periodically export the audit log
        self._export_audit_log()

    # ──────────────────────────────────────────────────────────────────────────
    # HELPER — send FlowMod to install a rule
    # ──────────────────────────────────────────────────────────────────────────
    def _add_flow(self, datapath, priority, match, actions,
                  idle_timeout=0, hard_timeout=0, label=""):
        """
        Install a flow rule on the given switch.

        Parameters
        ----------
        datapath     : Switch datapath object
        priority     : Rule priority (higher = matched first)
        match        : OFPMatch object defining match fields
        actions      : List of OFPAction objects (empty list = DROP)
        idle_timeout : Seconds of inactivity before removal (0 = never)
        hard_timeout : Absolute lifetime in seconds (0 = never)
        label        : Human-readable label for logging
        """
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        # Wrap actions in an Apply-Actions instruction
        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actions)]

        # Request flow-removed notification so we can log lifecycle events
        flags = ofproto.OFPFF_SEND_FLOW_REM

        flow_mod = parser.OFPFlowMod(
            datapath=datapath,
            priority=priority,
            match=match,
            instructions=inst,
            idle_timeout=idle_timeout,
            hard_timeout=hard_timeout,
            flags=flags,
        )
        datapath.send_msg(flow_mod)

        self.stats["total_installed"] += 1

        action_str = "DROP" if not actions else f"OUTPUT→port {actions[0].port}"
        logger.info(
            "FLOW INSTALLED | %-45s | priority=%d | idle=%ds hard=%ds | action=%s",
            label, priority, idle_timeout, hard_timeout, action_str,
        )

    # ──────────────────────────────────────────────────────────────────────────
    # HELPER — export audit log to JSON
    # ──────────────────────────────────────────────────────────────────────────
    def _export_audit_log(self):
        """Write the flow removal audit log to logs/audit_log.json."""
        path = "logs/audit_log.json"
        with open(path, "w") as f:
            json.dump(self.flow_audit_log, f, indent=2)

    # ──────────────────────────────────────────────────────────────────────────
    # SWITCH DISCONNECT — print final statistics
    # ──────────────────────────────────────────────────────────────────────────
    @set_ev_cls(ofp_event.EventOFPStateChange, DEAD_DISPATCHER)
    def switch_disconnected(self, ev):
        datapath = ev.datapath
        logger.info("Switch disconnected — DPID: %016x", datapath.id)
        logger.info("=" * 60)
        logger.info("  Final Statistics")
        logger.info("=" * 60)
        for k, v in self.stats.items():
            logger.info("  %-30s: %d", k, v)
        logger.info("=" * 60)
        self._export_audit_log()
        logger.info("Audit log saved → logs/audit_log.json")
