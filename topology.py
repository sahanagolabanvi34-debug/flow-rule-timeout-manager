"""
topology.py
===========
Mininet topology for the Flow Rule Timeout Manager project.

Topology:
                        [ Ryu Controller ]
                               |
                            [ s1 ]
                          /   |   \   \
                        h1   h2   h3   h4

  h1 = 10.0.0.1  (normal host — sends traffic, rules age and expire)
  h2 = 10.0.0.2  (normal host — receives traffic)
  h3 = 10.0.0.3  (normal host — used for iperf throughput test)
  h4 = 10.0.0.4  (BLOCKED host — firewall DROP rule installed by controller)

Run:
  sudo python3 topology.py

Make sure the Ryu controller is already running:
  ryu-manager controller/ryu_flow_timeout_controller.py

Author: Kushal G (PES1UG24AM145)
"""

from mininet.net import Mininet
from mininet.node import RemoteController, OVSSwitch
from mininet.cli import CLI
from mininet.log import setLogLevel, info
from mininet.link import TCLink
import time


def build_topology():
    """
    Create and return a Mininet network with:
      - 1 OVS switch (OpenFlow 1.3)
      - 4 hosts with static IPs
      - Remote Ryu controller (localhost:6633)
    """
    net = Mininet(
        controller=RemoteController,
        switch=OVSSwitch,
        link=TCLink,
        autoSetMacs=True,
    )

    info("*** Creating controller connection (Ryu on localhost:6633)\n")
    c0 = net.addController("c0",
                            controller=RemoteController,
                            ip="127.0.0.1",
                            port=6633)

    info("*** Adding switch\n")
    s1 = net.addSwitch("s1", protocols="OpenFlow13")

    info("*** Adding hosts\n")
    h1 = net.addHost("h1", ip="10.0.0.1/24")
    h2 = net.addHost("h2", ip="10.0.0.2/24")
    h3 = net.addHost("h3", ip="10.0.0.3/24")
    h4 = net.addHost("h4", ip="10.0.0.4/24")   # This host is BLOCKED by firewall rule

    info("*** Creating links\n")
    net.addLink(h1, s1)
    net.addLink(h2, s1)
    net.addLink(h3, s1)
    net.addLink(h4, s1)

    return net, [h1, h2, h3, h4], s1


def run_scenario_1(net, hosts):
    """
    Scenario 1 — Idle Timeout Demonstration
    ─────────────────────────────────────────
    1. h1 pings h2 → flow rules are installed with idle_timeout=10s
    2. We stop traffic and wait > 10 seconds
    3. The idle timer fires and the flow rule is removed by the switch
    4. h1 pings h2 again → new packet_in → new rule installed

    Expected: First ping batch succeeds, rules are installed.
              After idle period, flow table shows rules removed.
              Second ping batch triggers fresh rule installation.
    """
    h1, h2, h3, h4 = hosts
    info("\n" + "=" * 60 + "\n")
    info("SCENARIO 1: Idle Timeout Demonstration\n")
    info("=" * 60 + "\n")

    # Step 1 — establish connectivity and install flow rules
    info("\n[Step 1] h1 → h2: ping to install flow rules\n")
    result = h1.cmd("ping -c 4 10.0.0.2")
    info(result)

    info("\n[Step 1] Dump flow table (rules should be installed):\n")
    info(h1.cmd("ovs-ofctl -O OpenFlow13 dump-flows s1"))

    # Step 2 — wait for idle timeout to fire (10s + buffer)
    info("\n[Step 2] Waiting 13 seconds for idle timeout (10s) to expire...\n")
    time.sleep(13)

    info("\n[Step 2] Dump flow table (forwarding rules should now be gone):\n")
    info(h1.cmd("ovs-ofctl -O OpenFlow13 dump-flows s1"))

    # Step 3 — new traffic installs fresh rules
    info("\n[Step 3] h1 → h2: ping again (new rules will be installed)\n")
    result = h1.cmd("ping -c 4 10.0.0.2")
    info(result)

    info("\n[Step 3] Flow table after re-installation:\n")
    info(h1.cmd("ovs-ofctl -O OpenFlow13 dump-flows s1"))


def run_scenario_2(net, hosts):
    """
    Scenario 2 — Firewall (Blocked vs Allowed)
    ────────────────────────────────────────────
    The controller installs a permanent DROP rule for h4 (10.0.0.4).

    1. h1 pings h2 → ALLOWED (should succeed)
    2. h4 pings h1 → BLOCKED (should fail — 100% packet loss)
    3. h1 pings h4 → packets from h4 are dropped on return path

    Expected: h1↔h2 connectivity works; h4 cannot reach any other host.
    """
    h1, h2, h3, h4 = hosts
    info("\n" + "=" * 60 + "\n")
    info("SCENARIO 2: Firewall — Allowed vs Blocked\n")
    info("=" * 60 + "\n")

    info("\n[Test A] h1 → h2 (ALLOWED — should succeed):\n")
    result = h1.cmd("ping -c 4 10.0.0.2")
    info(result)

    info("\n[Test B] h4 → h1 (BLOCKED — should fail):\n")
    result = h4.cmd("ping -c 4 10.0.0.1")
    info(result)

    info("\n[Test C] h4 → h2 (BLOCKED — should fail):\n")
    result = h4.cmd("ping -c 4 10.0.0.2")
    info(result)

    info("\n[Firewall Rule in Flow Table]:\n")
    info(h1.cmd("ovs-ofctl -O OpenFlow13 dump-flows s1 | grep -i 'drop\\|10.0.0.4'"))


def run_iperf_test(net, hosts):
    """
    Performance Test — iperf throughput between h1 and h3.
    Used to satisfy the 'Performance Observation' rubric criteria.
    """
    h1, h2, h3, h4 = hosts
    info("\n" + "=" * 60 + "\n")
    info("PERFORMANCE TEST: iperf h1 → h3\n")
    info("=" * 60 + "\n")

    info("\n[iperf] Starting server on h3...\n")
    h3.cmd("iperf -s &")
    time.sleep(1)

    info("[iperf] Running client on h1 (10s test)...\n")
    result = h1.cmd("iperf -c 10.0.0.3 -t 10")
    info(result)

    h3.cmd("kill %iperf 2>/dev/null")


def main():
    setLogLevel("info")

    info("*** Building topology\n")
    net, hosts, s1 = build_topology()

    info("*** Starting network\n")
    net.start()

    # Force OpenFlow 1.3 on the switch
    s1.cmd("ovs-vsctl set bridge s1 protocols=OpenFlow13")

    info("*** Waiting for controller to connect...\n")
    time.sleep(3)

    info("\n*** Running automated test scenarios...\n")

    run_scenario_2(net, hosts)   # Firewall first (rules are static)
    run_scenario_1(net, hosts)   # Then idle timeout demo
    run_iperf_test(net, hosts)   # Performance measurement

    info("\n*** Automated tests complete. Dropping into Mininet CLI.\n")
    info("*** You can run: pingall, h1 ping h4, ovs-ofctl dump-flows s1, etc.\n")
    CLI(net)

    info("*** Stopping network\n")
    net.stop()


if __name__ == "__main__":
    main()
