from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib.packet import packet
from ryu.lib.packet import ethernet, arp, ipv4, icmp, tcp


class RyuRedirect(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    CLIENT_IP = "10.0.1.5"
    S1_IP = "10.0.1.2"
    S2_IP = "10.0.1.3"
    S1_MAC = "00:00:00:00:00:01"
    S2_MAC = "00:00:00:00:00:02"

    def __init__(self, *args, **kwargs):
        super(RyuRedirect, self).__init__(*args, **kwargs)
        self.mac_to_port = {}  # dpid -> {mac: port}

    def add_flow(self, datapath, priority, match, actions, idle_timeout=0, hard_timeout=0):
        ofp = datapath.ofproto
        parser = datapath.ofproto_parser
        inst = [parser.OFPInstructionActions(ofp.OFPIT_APPLY_ACTIONS, actions)]
        mod = parser.OFPFlowMod(
            datapath=datapath,
            priority=priority,
            match=match,
            instructions=inst,
            idle_timeout=idle_timeout,
            hard_timeout=hard_timeout,
        )
        datapath.send_msg(mod)

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        datapath = ev.msg.datapath
        ofp = datapath.ofproto
        parser = datapath.ofproto_parser

        # Table-miss
        match = parser.OFPMatch()
        actions = [parser.OFPActionOutput(ofp.OFPP_CONTROLLER, ofp.OFPCML_NO_BUFFER)]
        self.add_flow(datapath, priority=0, match=match, actions=actions)

        self.logger.info("Redirect: switch connected, table-miss installed.")

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def packet_in_handler(self, ev):
        msg = ev.msg
        datapath = ev.msg.datapath
        ofp = datapath.ofproto
        parser = datapath.ofproto_parser
        dpid = datapath.id
        in_port = msg.match["in_port"]

        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocol(ethernet.ethernet)
        if eth is None:
            return

        # Ignore LLDP
        if eth.ethertype == 0x88cc:
            return

        dst = eth.dst
        src = eth.src

        # MAC learning
        self.mac_to_port.setdefault(dpid, {})
        self.mac_to_port[dpid][src] = in_port

        # ARP: flood (ensures hosts can resolve MAC)
        if pkt.get_protocol(arp.arp):
            actions = [parser.OFPActionOutput(ofp.OFPP_FLOOD)]
            out = parser.OFPPacketOut(
                datapath=datapath,
                buffer_id=ofp.OFP_NO_BUFFER,
                in_port=in_port,
                actions=actions,
                data=msg.data,
            )
            datapath.send_msg(out)
            return

        # Default L2 forwarding port selection
        if dst in self.mac_to_port[dpid]:
            base_out_port = self.mac_to_port[dpid][dst]
        else:
            base_out_port = ofp.OFPP_FLOOD

        ip_pkt = pkt.get_protocol(ipv4.ipv4)
        icmp_pkt = pkt.get_protocol(icmp.icmp)
        tcp_pkt = pkt.get_protocol(tcp.tcp)

        # If not IPv4, just L2 flood/unicast
        if not ip_pkt:
            actions = [parser.OFPActionOutput(base_out_port)]
            out = parser.OFPPacketOut(
                datapath=datapath,
                buffer_id=ofp.OFP_NO_BUFFER,
                in_port=in_port,
                actions=actions,
                data=msg.data,
            )
            datapath.send_msg(out)
            return

        # ICMP should NOT be redirected; install ICMP flow with idle_timeout=5
        if icmp_pkt and base_out_port != ofp.OFPP_FLOOD:
            actions = [parser.OFPActionOutput(base_out_port)]
            match = parser.OFPMatch(
                in_port=in_port,
                eth_type=0x0800,
                ip_proto=1,
                ipv4_src=ip_pkt.src,
                ipv4_dst=ip_pkt.dst,
            )
            self.add_flow(datapath, priority=100, match=match, actions=actions, idle_timeout=5)

            out = parser.OFPPacketOut(
                datapath=datapath,
                buffer_id=ofp.OFP_NO_BUFFER,
                in_port=in_port,
                actions=actions,
                data=msg.data,
            )
            datapath.send_msg(out)
            return

        # TCP redirection: traffic aimed at Server1 IP is redirected to Server2
        if tcp_pkt and ip_pkt.dst == self.S1_IP:
            # Choose output port toward Server2 by MAC learning (fallback flood)
            if self.S2_MAC in self.mac_to_port[dpid]:
                out_port = self.mac_to_port[dpid][self.S2_MAC]
            else:
                out_port = ofp.OFPP_FLOOD

            actions = [
                parser.OFPActionSetField(ipv4_dst=self.S2_IP),
                parser.OFPActionSetField(eth_dst=self.S2_MAC),
                parser.OFPActionOutput(out_port),
            ]

            # Forward-direction redirect flow (Client -> Server1 becomes Client -> Server2)
            match_fwd = parser.OFPMatch(
                in_port=in_port,
                eth_type=0x0800,
                ip_proto=6,
                ipv4_src=ip_pkt.src,
                ipv4_dst=self.S1_IP,
                tcp_src=tcp_pkt.src_port,
                tcp_dst=tcp_pkt.dst_port,
            )
            self.add_flow(datapath, priority=200, match=match_fwd, actions=actions, idle_timeout=5)

            # Reverse-direction NAT back (Server2 -> Client appears as Server1 -> Client)
            # Output port back to client is learned from CLIENT MAC if present, else use in_port as fallback.
            client_port = None
            for mac, port in self.mac_to_port[dpid].items():
                # If you know the client's MAC, you can pin it here; otherwise rely on learning.
                pass
            # Best-effort: send replies back to the incoming port (works in 1-switch topology)
            client_port = in_port

            actions_rev = [
                parser.OFPActionSetField(ipv4_src=self.S1_IP),
                parser.OFPActionSetField(eth_src=self.S1_MAC),
                parser.OFPActionOutput(client_port),
            ]
            match_rev = parser.OFPMatch(
                eth_type=0x0800,
                ip_proto=6,
                ipv4_src=self.S2_IP,
                ipv4_dst=ip_pkt.src,
                tcp_src=tcp_pkt.dst_port,
                tcp_dst=tcp_pkt.src_port,
            )
            self.add_flow(datapath, priority=190, match=match_rev, actions=actions_rev, idle_timeout=5)

            # PacketOut for current SYN/data
            out = parser.OFPPacketOut(
                datapath=datapath,
                buffer_id=ofp.OFP_NO_BUFFER,
                in_port=in_port,
                actions=actions,
                data=msg.data,
            )
            datapath.send_msg(out)
            return

        # Other IPv4 (including TCP not targeting S1): normal L2 forwarding
        actions = [parser.OFPActionOutput(base_out_port)]
        if base_out_port != ofp.OFPP_FLOOD:
            match = parser.OFPMatch(
                in_port=in_port,
                eth_type=0x0800,
                ipv4_src=ip_pkt.src,
                ipv4_dst=ip_pkt.dst,
            )
            self.add_flow(datapath, priority=50, match=match, actions=actions, idle_timeout=5)

        out = parser.OFPPacketOut(
            datapath=datapath,
            buffer_id=ofp.OFP_NO_BUFFER,
            in_port=in_port,
            actions=actions,
            data=msg.data,
        )
        datapath.send_msg(out)
