from ryu.lib import hub

def get_time_elapsed(switch_times, switch_id, port_no, current_time):
    previous_time = switch_times[switch_id].get(port_no)

    if previous_time is None:
        return 0  # no previous reading for this port yet, treat elapsed time as 0 instead of raising

    return current_time - previous_time

def add_switch_port_entry(switch_ports, datapath_id, ip, mac, port, arp_type):
    if datapath_id not in switch_ports:
        switch_ports[datapath_id] = []

    switch_ports[datapath_id].append({
        'ip': ip,
        'mac': mac,
        'port': port,
        'type': arp_type
    })

    with open("switch_ports.txt", 'a') as file:
        file.write(f"Switch: [{datapath_id}]\n Port:[{port}]\n Host-IP: [{ip}]\n Type: {arp_type}\n\n")

def _initialize_blocked_ports(blocked_ports, switch_id, port):
    if switch_id not in blocked_ports:
        blocked_ports[switch_id] = {}

    if port not in blocked_ports[switch_id]:
        blocked_ports[switch_id][port] = {
            'blocked': False,
            'blocked_time': 0,
            'rx': 0
        }

def search_blocked_port(blocked_ports):
    """Returns the first (switch_id, port_no) currently marked as blocked, or None."""
    for switch_id, switch_data in blocked_ports.items():
        for port_no, port_data in switch_data.items():
            if port_data.get('blocked'):
                return switch_id, port_no
    return None
