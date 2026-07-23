from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER, DEAD_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib.packet import packet, ethernet, arp, ether_types
from ryu.lib import hub
import time
import threading
import utils

class SimpleSwitch13(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(SimpleSwitch13, self).__init__(*args, **kwargs)

        self.mac_to_port = {}
        self.datapaths = {}
        self.port_stats = {}
        self.switch_times = {}
        self.stats_elaborate = {}

        # thresholds tuned against the traffic profile used in our Mininet topology, see the report for the sizing
        self.threshold_out = 550000
        self.threshold_in = 500000

        self.alarm = False
        self.switch_ports = {}
        self.host_ports = {}
        self.blocked_ports = {}

        # blocked_ports is read by the monitor thread and written by the unlocker thread
        self.lock = threading.Lock()

        self.monitor_thread = None
        self.unlocker_thread = None

    @set_ev_cls(ofp_event.EventOFPStateChange, [MAIN_DISPATCHER, DEAD_DISPATCHER])
    def _state_change_handler(self, ev):
        datapath = ev.datapath

        if ev.state == MAIN_DISPATCHER:
            if datapath.id not in self.datapaths:
                self.logger.info('New Switch Registered! ID: %016x', datapath.id)
                self.datapaths[datapath.id] = datapath

                with open("Datapaths.txt", 'a') as file:
                    file.write(f"Switch registered: {datapath.id}\n")

                # both threads only need to run once, start them on the first switch that connects
                if self.monitor_thread is None:
                    self.monitor_thread = hub.spawn(self._monitor)
                    self.unlocker_thread = hub.spawn(self._unlocker)

        elif ev.state == DEAD_DISPATCHER:
            if datapath.id in self.datapaths:
                self.logger.info('Switch Unregistered! ID: %016x', datapath.id)
                del self.datapaths[datapath.id]

    def _monitor(self):
        self.logger.info("Monitor Thread: Activated.\n")
        hub.sleep(15)  # give the switches time to finish OpenFlow negotiation before polling

        while True:
            for dp in self.datapaths.values():
                self._request_ports_stats(dp)

            hub.sleep(5)

            switch_id = self.check_threshold_out()

            if self.alarm:
                self.logger.info("THRESHOLD ALERT! Switch ID: %016x", switch_id)
                self.check_threshold_in(switch_id=switch_id)

    def _unlocker(self):
        self.logger.info("[UNLOCKER THREAD] Activated and running...\n")
        hub.sleep(15)

        while True:
            if self.blocked_ports:
                result = utils.search_blocked_port(self.blocked_ports)

                if result is not None:
                    switch_id, port_to_check = result

                    if switch_id is not None:
                        self.check_single_port(switch_id, port_to_check)
                else:
                    self.logger.info("[UNLOCKER] No blocked ports found.")

            hub.sleep(10)

    def check_single_port(self, switch_id, port_no):
        # a port stays blocked until traffic on it has stayed under the incoming threshold for 30s straight
        start_time = self.blocked_ports[switch_id][port_no].get('blocked_time')
        elapsed_time = 0
        self.logger.info(f"[UNLOCKER] Checking port: {port_no} on switch: {switch_id}")

        while elapsed_time < 40:
            elapsed_time = time.time() - start_time

            self.logger.info(f"[UNLOCKER] Elapsed time: {elapsed_time:.2f} seconds.")
            rx = self.stats_elaborate[switch_id][port_no]['rx']

            if rx >= self.threshold_in:
                self.logger.info("[UNLOCKER] Port remains locked due to high traffic.")
                return False

            if elapsed_time >= 30:
                self.logger.info(f"[UNLOCKER] Port {port_no} on switch {switch_id} has been successfully unlocked.")
                self.unlock_port(switch_id, port_no)
                return True

            hub.sleep(1)  # this runs inside a hub greenlet, never block it with a raw time.sleep


    def _request_ports_stats(self, datapath):
        self.logger.info('Sending statistics request to switch: [%016x]', datapath.id)
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        req = parser.OFPPortStatsRequest(datapath, 0, ofproto.OFPP_ANY)
        datapath.send_msg(req)

    @set_ev_cls(ofp_event.EventOFPPortStatsReply, MAIN_DISPATCHER)
    def _port_stats_reply_handler(self, ev):
        body = ev.msg.body
        switch_id = ev.msg.datapath.id

        self.logger.info('_____________________________________________________________________________')
        self.logger.info('Switch ID: %016x', switch_id)
        self.logger.info(' Port   RX-Packets   TX-Packets   RX-Bytes   TX-Bytes   Throughput_RX   Throughput_TX')
        self.logger.info('----------------------------------------------------------------------------')

        for stat in body:
            port_no = stat.port_no
            if port_no != ofproto_v1_3.OFPP_LOCAL:  # OVS always reports this pseudo-port too, skip it, it's not a real link
                tx_bytes = stat.tx_bytes
                rx_bytes = stat.rx_bytes
                throughput_tx, throughput_rx = self.calculate_stats(switch_id, port_no, tx_bytes, rx_bytes)

                self.logger.info('%8x %9d %9d %10d %10d %14.2f %14.2f',
                                 port_no, stat.rx_packets, stat.tx_packets,
                                 stat.rx_bytes, stat.tx_bytes, throughput_rx, throughput_tx)

        self.logger.info('____________________________________________________________________________________')

    def calculate_stats(self, switch_id, port_no, new_tx_bytes, new_rx_bytes):
        """Derives tx/rx throughput for a port from the byte counters of two consecutive polls."""
        current_time = time.time()

        if switch_id not in self.port_stats:
            self.port_stats[switch_id] = {}
            self.switch_times[switch_id] = {}
            self.stats_elaborate[switch_id] = {}

        if port_no not in self.port_stats[switch_id]:
            self.port_stats[switch_id][port_no] = {
                'new_tx_bytes': new_tx_bytes,
                'new_rx_bytes': new_rx_bytes
            }
            self.stats_elaborate[switch_id][port_no] = {'tx': 0, 'rx': 0}
            self.switch_times[switch_id][port_no] = current_time
            return 0, 0  # first reading for this port, no delta to compute throughput from yet

        old_tx_bytes = self.port_stats[switch_id][port_no]['new_tx_bytes']
        old_rx_bytes = self.port_stats[switch_id][port_no]['new_rx_bytes']

        time_elapsed = utils.get_time_elapsed(
            self.switch_times, switch_id=switch_id, current_time=current_time, port_no=port_no
        )

        rx_diff = new_rx_bytes - old_rx_bytes
        tx_diff = new_tx_bytes - old_tx_bytes

        self.port_stats[switch_id][port_no]['new_tx_bytes'] = new_tx_bytes
        self.port_stats[switch_id][port_no]['new_rx_bytes'] = new_rx_bytes
        self.switch_times[switch_id][port_no] = current_time

        throughput_tx = tx_diff / time_elapsed
        throughput_rx = rx_diff / time_elapsed

        self.stats_elaborate[switch_id][port_no]['tx'] = throughput_tx
        self.stats_elaborate[switch_id][port_no]['rx'] = throughput_rx

        return throughput_tx, throughput_rx

    def check_threshold_out(self):
        """Returns the switch id of the first port found over threshold_out, or None."""
        for switch_id, ports in self.stats_elaborate.items():
            for port_no in ports:
                throughput = self.stats_elaborate[switch_id][port_no]['tx']

                if throughput > self.threshold_out:
                    if not self.alarm:
                        self.alarm = True
                        self.logger.info("ALERT TRIGGERED Port %s on Switch %s exceeded the outgoing threshold!",
                                            port_no, switch_id)
                        return switch_id

        return None

    def check_threshold_in(self, switch_id):
        """
        Confirms the DoS suspicion raised by check_threshold_out by looking at incoming ARP
        traffic on the switch's host facing port, and blocks it if it is also over threshold.
        """
        self.logger.info(f"Checking incoming threshold - Switch ID: {switch_id}")

        if switch_id not in self.switch_ports:
            self.logger.info(f"Checking switches directly connected to hosts.")

            for id, switch_info_list in self.switch_ports.items():
                for switch_info in switch_info_list:
                    self.logger.info(f"Inspecting switch: {id}")

                    if switch_info.get('type') == arp.ARP_REQUEST:
                        port = switch_info.get('port')

                        utils._initialize_blocked_ports(self.blocked_ports, id, port)
                        throughput_in = self.stats_elaborate[id][port]['rx']
                        self.logger.info(f"Switch[{id}][{port}] - RX: {throughput_in} bps")

                        if throughput_in > self.threshold_in and not self.blocked_ports[id][port].get('blocked'):
                            self.block_port(switch_id=id, port_to_block=port, rx=throughput_in)
                            self.logger.info(f"PORT [{port}] on SWITCH [{id}] BLOCKED - RX: {throughput_in} bps.")
                            self.alarm = False
                            return port
        else:
            self.logger.info(f"Switch {switch_id} is directly connected to a host as SENDER.")
            switch_info_list = self.switch_ports[switch_id]

            self.logger.info(switch_info_list)

            for switch_info in switch_info_list:
                port = switch_info.get('port')

                if switch_info.get('type') == arp.ARP_REQUEST:
                    utils._initialize_blocked_ports(self.blocked_ports, switch_id, port)

                    for _ in range(5):  # sample a few times before deciding, one reading can be a spike
                        throughput_in = self.stats_elaborate[switch_id][port]['rx']
                        hub.sleep(0.5)

                        if throughput_in > self.threshold_in and not self.blocked_ports[switch_id][port].get('blocked'):
                            self.logger.info(f"\nPORT [{port}] ON SWITCH [{switch_id}] BLOCKED - RX: {throughput_in} bytes/s\n")
                            self.block_port(switch_id=switch_id, port_to_block=port, rx=throughput_in)
                            self.alarm = False
                            return port

        self.alarm = False
        return None

    def block_port(self, switch_id, port_to_block, rx):
        with self.lock:
            self.blocked_ports[switch_id][port_to_block] = {
                'blocked': True,
                'blocked_time': time.time(),
                'rx': rx
            }

        with open("BlockedPort.txt", 'a') as file:
            file.write(f"Porta [{port_to_block}] dello switch [{switch_id}] bloccata --> rx:{rx}  tempo: {time.time()}\n")

        datapath = self.datapaths.get(switch_id)
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        match = parser.OFPMatch(in_port=port_to_block)
        actions = []  # empty actions list means matching traffic gets silently dropped

        self.add_flow(datapath=datapath, priority=2, match=match, actions=actions)

    def unlock_port(self, switch_id, port_to_unlock):
        with self.lock:
            if switch_id in self.blocked_ports and port_to_unlock in self.blocked_ports[switch_id]:
                self.blocked_ports[switch_id][port_to_unlock] = {'blocked': False, 'blocked_time': 0}

        with open("BlockedPort.txt", 'a') as file:
            file.write(f"Port [{port_to_unlock}] on switch [{switch_id}] unlocked\n")

        datapath = self.datapaths.get(switch_id)

        if datapath is not None:
            ofproto = datapath.ofproto
            parser = datapath.ofproto_parser

            match = parser.OFPMatch(in_port=port_to_unlock)
            self.remove_flow(datapath=datapath, match=match)

    def remove_flow(self, datapath, match):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        mod = parser.OFPFlowMod(
            datapath=datapath,
            command=ofproto.OFPFC_DELETE,
            out_port=ofproto.OFPP_ANY,
            out_group=ofproto.OFPG_ANY,
            match=match
        )
        datapath.send_msg(mod)

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        """Installs the table-miss flow entry (priority 0, match all) that sends unknown traffic to the controller."""
        datapath = ev.msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        match = parser.OFPMatch()
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER, ofproto.OFPCML_NO_BUFFER)]

        self.add_flow(datapath, 0, match, actions)

    def add_flow(self, datapath, priority, match, actions, buffer_id=None):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actions)]

        if buffer_id:
            mod = parser.OFPFlowMod(
                datapath=datapath,
                buffer_id=buffer_id,
                priority=priority,
                match=match,
                instructions=inst
            )
        else:
            mod = parser.OFPFlowMod(
                datapath=datapath,
                priority=priority,
                match=match,
                instructions=inst
            )
        datapath.send_msg(mod)

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def _packet_in_handler(self, ev):
        if ev.msg.msg_len < ev.msg.total_len:
            self.logger.info("Packet truncated: only %s of %s bytes received",
                                ev.msg.msg_len, ev.msg.total_len)

        msg = ev.msg
        datapath = msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        in_port = msg.match['in_port']

        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocols(ethernet.ethernet)[0]

        dst = eth.dst
        src = eth.src

        dpid = datapath.id

        if eth.ethertype == ether_types.ETH_TYPE_ARP:
            arp_packet = pkt.get_protocols(arp.arp)[0]

            if arp_packet.src_ip not in self.host_ports:
                self.host_ports[arp_packet.src_ip] = {
                    'mac': arp_packet.src_mac,
                    'dpid': datapath.id,
                    'port': in_port
                }

                with open("host_ports.txt", 'a') as file:
                    file.write(f"IP: {arp_packet.src_ip} collegato a Switch: {datapath.id} su port: {in_port}\n")

                utils.add_switch_port_entry(
                    self.switch_ports, datapath.id, arp_packet.src_ip, arp_packet.src_mac, in_port, arp_packet.opcode
                )
            else:
                if (self.host_ports[arp_packet.src_ip]['mac'] != arp_packet.src_mac or
                    self.host_ports[arp_packet.src_ip]['dpid'] != datapath.id or
                    self.host_ports[arp_packet.src_ip]['port'] != in_port):
                    self.host_ports[arp_packet.src_ip] = {
                        'mac': arp_packet.src_mac,
                        'dpid': datapath.id,
                        'port': in_port
                    }

        self.mac_to_port.setdefault(dpid, {})

        self.logger.info("Packet in %s %s %s %s", dpid, src, dst, in_port)

        self.mac_to_port[dpid][src] = in_port

        if dst in self.mac_to_port[dpid]:
            out_port = self.mac_to_port[dpid][dst]
        else:
            out_port = ofproto.OFPP_FLOOD

        actions = [parser.OFPActionOutput(out_port)]

        if out_port != ofproto.OFPP_FLOOD:
            match = parser.OFPMatch(in_port=in_port, eth_dst=dst, eth_src=src)
            if msg.buffer_id != ofproto.OFP_NO_BUFFER:
                self.add_flow(datapath, 1, match, actions, msg.buffer_id)
                return
            else:
                self.add_flow(datapath, 1, match, actions)

        data = None
        if msg.buffer_id == ofproto.OFP_NO_BUFFER:
            data = msg.data

        out = parser.OFPPacketOut(
            datapath=datapath,
            buffer_id=msg.buffer_id,
            in_port=in_port,
            actions=actions,
            data=data
        )

        datapath.send_msg(out)
