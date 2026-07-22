def get_time_elapsed(switch_times, switch_id, port_no, current_time):
    previous_time = switch_times[switch_id].get(port_no)

    if previous_time is None:
        raise ValueError(f"Il tempo dell'ultimo evento per il porto {port_no} dello switch {switch_id} non è stato trovato.")

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
        blocked_ports[switch_id][port] = False
