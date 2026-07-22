# Networks and Cloud Infrastructures, Designing a Monitoring and Mitigation System for DoS Attacks

Project work for the Networks and Cloud Infrastructures course (MSc in Computer Engineering, University of Naples Federico II, prof. Ventre, academic year 2023/2024).

Authors: Francesco Altiero (@checcoalt), Luigi Caucci (@lcaucci27), Simone Cecere (@simocecere).

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
PrimaParte/     first working version: monitor + block, no automatic unblock
SecondaParte/   same logic, refactored to share helpers via utils.py
Definitivo/     final version: adds a dedicated unlocker thread, thread-safe
                access to blocked_ports (threading.Lock), and richer
                per-port blocked-state tracking
```

Each of the three folders is self-contained and has the same layout:

```
controller.py   Ryu app: L2 switch + throughput monitoring + DoS mitigation
topology.py     Mininet topology (4 hosts, 4 switches) and CLI entry point
utils.py        helper functions shared by controller.py (Definitivo, SecondaParte only)
*.txt           log files the controller appends to at runtime (not versioned, see .gitignore)
```

`NCIs_Altiero_Caucci_Cecere.pdf` at the repo root is the full report.

## How it works (Definitivo, the final version)

- `_state_change_handler` registers switches as they connect and, on the first one, spawns two background greenlets: `_monitor` and `_unlocker`.
- `_monitor` polls `OFPPortStatsRequest` on all registered switches every 5s, computes throughput in `calculate_stats`, and calls `check_threshold_out` / `check_threshold_in` to decide whether to raise an alarm and block a port.
- `check_threshold_out` scans all switches for a port whose outgoing throughput is above `threshold_out` (550000 B/s).
- `check_threshold_in` then looks at the incoming ARP traffic on the corresponding host-facing port; if that is also above `threshold_in` (500000 B/s), `block_port` installs a priority-2 flow rule with an empty action list on that `in_port`, which drops all its traffic.
- `_unlocker` runs independently, checks every 10s whether any port is currently blocked, and if its RX throughput has stayed under `threshold_in` for 30 consecutive seconds (`check_single_port`), calls `unlock_port` to remove the drop rule.
- `mac_to_port` / ARP snooping in `_packet_in_handler` build the switch/host topology used to decide which port belongs to which host.

`PrimaParte` and `SecondaParte` implement the same idea without the automatic unlock step (blocked ports stay blocked until the controller is restarted).

## Getting started

### Requirements

- Mininet with Open vSwitch (typically run inside the [Mininet VM](http://mininet.org/download/) or a Linux box with Mininet installed)
- Ryu (`pip install ryu`, tested with the OpenFlow 1.3 API)
- Python 3.9 (the committed `__pycache__` folders were generated with cpython-39, any 3.x should work)

### Running a simulation

From inside one of the three folders (`Definitivo` is the one to use unless you specifically want to reproduce an earlier stage from the report):

```bash
# terminal 1: start the Ryu controller
ryu-manager controller.py

# terminal 2: start the Mininet topology and drop into the Mininet CLI
sudo python3 topology.py
```

The topology creates 4 hosts (`h1`-`h4`) and 4 switches (`s1`-`s4`), with `s4` acting as the core switch connecting `s1`, `s2`, `s3`. From the Mininet CLI you can generate traffic between hosts (e.g. `iperf`, `ping`, or a flood tool) to trigger the monitoring/blocking logic; `controller.py` logs its decisions to stdout and appends to `Datapaths.txt`, `BlockedPort.txt`, `host_ports.txt`, `switch_ports.txt` in the working directory (these are regenerated on every run and are gitignored).

## Notes

- The two throughput thresholds (`threshold_out = 550000`, `threshold_in = 500000` bytes/s) were picked empirically against the traffic profile used in our own simulations, see the report for how they were tuned and for the mitigation-effectiveness numbers.
