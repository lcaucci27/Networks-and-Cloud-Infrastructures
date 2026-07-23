# Networks and Cloud Infrastructures, Designing a Monitoring and Mitigation System for DoS Attacks

Project work for the Networks and Cloud Infrastructures course (MSc in Computer Engineering, University of Naples Federico II, prof. Ventre, academic year 2023/2024, exam sustained on 12/09/2024).

Authors: Francesco Altiero ([@checcoalt](https://github.com/checcoalt)), Luigi Caucci ([@lcaucci27](https://github.com/lcaucci27)), Simone Cecere ([@simocecere](https://github.com/simocecere)).

## What this project is about

We built an SDN controller on top of Ryu that detects and mitigates a Denial of Service attack in a Mininet-simulated network. The controller acts as an L2 learning switch (standard MAC-learning + flow install logic) and, on top of that, polls OpenFlow port statistics every few seconds to compute per-port throughput. When the outgoing throughput on a port crosses a threshold, it treats it as a possible attack in progress and cross-checks the incoming ARP traffic on the host-facing port that is the suspected source. If that is also over threshold, the controller installs a flow rule that drops all traffic from that port, effectively cutting the attacker off, and later re-checks the port periodically to lift the block once traffic drops back down.

The full writeup (topology design, threshold tuning, simulation results, the "minimize impact on legitimate hosts" extension, and the dynamic unblocking mechanism) is in [`NCIs_Altiero_Caucci_Cecere.pdf`](NCIs_Altiero_Caucci_Cecere.pdf).

## Tech stack

- Python 3.9
- [Ryu](https://ryu-sdn.org/) SDN framework, OpenFlow 1.3
- [Mininet](http://mininet.org/) for the simulated network (Open vSwitch, `RemoteController`, `TCLink`)
- `hub` (Ryu's own greenlet-based cooperative scheduler) for the background monitor/unlocker threads

## Repository structure

The project went through three iterations, kept as separate folders since each one corresponds to a stage described in the report:

```
V1/     first working version: monitor + block, no automatic unblock
V2/     same logic, refactored to share helpers via utils.py
Final/  final version: adds a dedicated unlocker thread, thread-safe
        access to blocked_ports (threading.Lock), and richer
        per-port blocked-state tracking
```

Each of the three folders is self-contained and has the same layout:

```
controller.py   Ryu app: L2 switch + throughput monitoring + DoS mitigation
topology.py     Mininet topology (4 hosts, 4 switches) and CLI entry point
utils.py        helper functions shared by controller.py (Final, V2 only)
*.txt           log files the controller appends to at runtime (not versioned, see .gitignore)
```

`NCIs_Altiero_Caucci_Cecere.pdf` at the repo root is the full report.

## How it works (Final, the final version)

- `_state_change_handler` registers switches as they connect and, on the first one, spawns two background greenlets: `_monitor` and `_unlocker`.
- `_monitor` polls `OFPPortStatsRequest` on all registered switches every 5s, computes throughput in `calculate_stats`, and calls `check_threshold_out` / `check_threshold_in` to decide whether to raise an alarm and block a port.
- `check_threshold_out` scans all switches for a port whose outgoing throughput is above `threshold_out` (550000 B/s).
- `check_threshold_in` then looks at the incoming ARP traffic on the corresponding host-facing port; if that is also above `threshold_in` (500000 B/s), `block_port` installs a priority-2 flow rule with an empty action list on that `in_port`, which drops all its traffic.
- `_unlocker` runs independently (15s initial delay, then a 10s poll loop via `search_blocked_port`), and for each blocked port calls `check_single_port`, which re-samples RX throughput once per second for up to 40s: if it ever spikes back above `threshold_in` the port stays locked and the check exits immediately, but if it stays below threshold for 30 consecutive seconds `unlock_port` removes the drop rule (an `OFPFlowMod` with `OFPFC_DELETE`) and clears the port's blocked-state entry.
- `mac_to_port` / ARP snooping in `_packet_in_handler` build the switch/host topology used to decide which port belongs to which host. `switch_ports` is keyed by switch id (`datapath.id`); in V1 each entry is a single `{ip, mac, port, type}` dict, which silently gets overwritten if a second host talks through the same switch. The extended topology (Sec. 3.1 of the report, H4 added behind S1) exposed exactly that: it was generalized in V2/Final to a list of per-host dicts under each switch id, and factored into `utils.add_switch_port_entry`, so H1's (malicious) and H4's (legitimate) ARP-derived port info can both be tracked on the same switch instead of one clobbering the other.

`V1` and `V2` implement the same idea without the automatic unlock step (blocked ports stay blocked until the controller is restarted).

## Report highlights (from `NCIs_Altiero_Caucci_Cecere.pdf`)

- **Base topology**: 3 hosts (H1-H3) and 4 switches (S1-S4) in Mininet, `S4` as the core switch, 10 Mbit/s links (`TCLink`, `max_queue_size=500` on the core links), `RemoteController` talking OpenFlow 1.3 to a Ryu app (`SimpleSwitch13` subclass). Connectivity is verified with `pingall` and inspected in Wireshark before any attack traffic is generated.
- **Attack simulation**: H1 (attacker) floods UDP traffic toward H3 while H2 sends legitimate TCP traffic to the same destination, both generated with `iPerf`. In the recorded run, H1's requested 15 Mbps UDP stream was throttled to ~9.18 Mbps by the shared 10 Mbit/s link, H2's TCP throughput collapsed from an expected 2 Mbps down to ~720 Kbps (and later ~263 Kbps under sustained congestion) since TCP backs off while UDP does not, and the UDP flow itself degraded to ~611 Kbps with 3706 ms of jitter and 47 out-of-order datagrams, the concrete evidence used to justify adding mitigation.
- **Threshold tuning**: `threshold_out = 550000 B/s` and `threshold_in = 500000 B/s` were picked empirically so that normal iPerf/ping traffic on these 10 Mbit/s links stays under both, while the simulated attack (which pushes a switch port toward its link capacity) reliably trips them; `check_threshold_out` scans every switch port for an outbound spike, and only then does `check_threshold_in` walk the host-facing ports to find which sender's incoming ARP-associated throughput is also over threshold, before `block_port` installs the priority-2 drop rule.
- **Minimizing impact on legitimate hosts** (Sec. 3.1): adding a 4th host (H4, also behind S1) exposed a bug where the switch-port bookkeeping only tracked one host per port; it was generalized to a per-IP dictionary and factored into `utils.py` so the controller can tell H1's (malicious) traffic apart from H4's (legitimate) traffic on the same switch, and block only the offending port rather than the whole switch-to-switch trunk (blocking the S1-S3 trunk instead was shown in the report to cut off H4 too, which is why the per-port approach was kept).
- **Dynamic remediation** (Sec. 3.2-3.4): the `UNLOCKER` thread was added specifically so blocked ports don't stay blocked forever; the report's simulation runs `iperf -c 10.0.0.2 -t 30 -p 5002 -u -b 15M` from H1 to H2, started and stopped at intervals so RX oscillates around `threshold_in`. The captured log shows the exact timing the code implements: at t=24.98s the unlocker logs "Port remains locked due to high traffic" (RX still above threshold), and at t=34.98s, once RX has stayed below `threshold_in` for the required 30 consecutive seconds, it logs "Port 1 on switch 1 has been successfully unlocked" and calls `unlock_port`. `sudo ovs-ofctl dump-flows s1` is used throughout to confirm, at the OVS level, both that the priority-2 drop rule is actually installed while blocked (`actions=drop`) and that it is gone after `unlock_port` issues its `OFPFC_DELETE`.
- **Conclusions / discussion**: the ARP-based sender/receiver identification only tells the controller who initiated a flow, not who is malicious for its whole lifetime, since a host's "sender" role isn't fixed once assigned. The report discusses two alternatives it didn't implement: moving detection to TCP SYN-based flow identification (works at the OSI transport layer without hardcoding a sender/receiver role, but says nothing about non-TCP traffic), and, since UDP has no equivalent handshake and ICMP floods (ping flooding) sit below layer 4 entirely, falling back to a source/destination IP-address-level virtual flow so any transport protocol can be covered, at the cost of only being as good as the IP address is stable (dynamic ISP-assigned addresses make a block temporary at best). The report draws a parallel with AGCOM's real-world *Piracy Shield* system, which uses exactly this IP-level approach against illegal sports-streaming (an estimated EUR330M/year loss to broadcast-rights holders) and fully blocks a flagged IP within 30 minutes of a ticket being raised.

## Implementation notes

A few things worth calling out for anyone reading the code closely:

- The port-stats reply handler filters out `ofproto_v1_3.OFPP_LOCAL` (OVS's own management pseudo-port, present in every `OFPPortStatsReply` alongside the real switch ports) so it doesn't get counted as a monitored link.
- In V1/V2, `check_threshold_in`'s five-sample loop (`for _ in range(5): ... hub.sleep(0.5)`) is meant to smooth out single-reading spikes before deciding to block a port; the throughput has to be re-read from `stats_elaborate` on every iteration of that loop for the sampling to mean anything, otherwise it just checks the same stale number five times. Final gets this right; V1/V2 originally didn't (V2 even referenced a variable that no longer existed in that scope after the switch to per-host lists, an outright `NameError` waiting for the code path where a blocked port is reached via `switch_id in self.switch_ports`).
- `check_single_port` (the unlocker's 40s re-check window) runs inside a Ryu `hub` greenlet like everything else in this file, so it uses `hub.sleep`, not the blocking `time.sleep`, to yield control back to the scheduler between samples.
- `blocked_ports` is shared between the `_monitor` thread (which blocks a port) and the `_unlocker` thread (which unblocks it); Final protects writes to it with `threading.Lock` because both are separate `hub` greenlets that can, in principle, be scheduled in the middle of the same dict mutation.
- The 550000/500000 B/s thresholds are not derived from a formula, they were picked empirically against the 10 Mbit/s links used throughout: normal `iperf`/`ping` traffic stays comfortably under both, while a link pushed toward its nominal capacity by the simulated attack reliably crosses them. They'd need retuning for a different link speed.

## Getting started

### Requirements

- Mininet with Open vSwitch (typically run inside the [Mininet VM](http://mininet.org/download/) or a Linux box with Mininet installed)
- Ryu (`pip install ryu`, tested with the OpenFlow 1.3 API)
- Python 3.9 (the committed `__pycache__` folders were generated with cpython-39, any 3.x should work)

### Running a simulation

From inside one of the three folders (`Final` is the one to use unless you specifically want to reproduce an earlier stage from the report):

```bash
# terminal 1: start the Ryu controller
ryu-manager controller.py

# terminal 2: start the Mininet topology and drop into the Mininet CLI
sudo python3 topology.py
```

The topology creates 4 hosts (`h1`-`h4`) and 4 switches (`s1`-`s4`), with `s4` acting as the core switch connecting `s1`, `s2`, `s3`. From the Mininet CLI you can generate traffic between hosts (e.g. `iperf`, `ping`, or a flood tool) to trigger the monitoring/blocking logic; `controller.py` logs its decisions to stdout and appends to `Datapaths.txt`, `BlockedPort.txt`, `host_ports.txt`, `switch_ports.txt` in the working directory (these are regenerated on every run and are gitignored).

