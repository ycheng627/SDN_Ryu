    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def _packet_in_handler(self, ev):
        msg = ev.msg
        datapath = msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        # get Datapath ID to identify OpenFlow switches.
        dpid = datapath.id
        self.mac_to_port.setdefault(dpid, {})

        # analyse the received packets using the packet library.
        pkt = packet.Packet(msg.data)
        eth_pkt = pkt.get_protocol(ethernet.ethernet)
        arp_pkt = pkt.get_protocol(arp.arp)
        ip_pkt = pkt.get_protocol(ipv4.ipv4)
        udp_pkt = pkt.get_protocol(udp.udp)
        tcp_pkt = pkt.get_protocol(tcp.tcp)

        if arp_pkt != None:
            dst_ip = arp_pkt.dst_ip
            src_ip = arp_pkt.src_ip
            
            dst_ip_end = int(dst_ip.split('.')[-1])
            src_ip_end = int(src_ip.split('.')[-1])
            
            if dst_ip_end % 2 != src_ip_end % 2:
                return

        eth_dst = eth_pkt.dst
        eth_src = eth_pkt.src

        # get the received port number from packet_in message.
        in_port = msg.match['in_port']

        self.logger.info("packet in %s %s %s %s", dpid, eth_src, eth_dst, in_port)

        # learn a mac address to avoid FLOOD next time.
        self.mac_to_port[dpid][eth_src] = in_port

        # if the destination mac address is already learned,
        # decide which port to output the packet, otherwise FLOOD.
        if eth_dst in self.mac_to_port[dpid]:
            out_port = self.mac_to_port[dpid][eth_dst]
        else:
            out_port = ofproto.OFPP_FLOOD

        # construct action list.
        actions = [parser.OFPActionOutput(out_port)]

        # install a flow to avoid packet_in next time.
        if out_port != ofproto.OFPP_FLOOD and (ip_pkt != None and (udp_pkt != None or tcp_pkt != None)):
            src_ip = ip_pkt.src
            dst_ip = ip_pkt.dst
            match = None

            if udp_pkt:
                src_port = udp_pkt.src_port
                dst_port = udp_pkt.dst_port
                match = parser.OFPMatch(in_port=in_port, eth_type=ether.ETH_TYPE_IP, ip_proto=inet.IPPROTO_UDP, ipv4_src=src_ip, ipv4_dst=dst_ip, udp_src=src_port, udp_dst=dst_port)
            else:
                src_port = tcp_pkt.src_port
                dst_port = tcp_pkt.dst_port
                match = parser.OFPMatch(in_port=in_port, eth_type=ether.ETH_TYPE_IP, ip_proto=inet.IPPROTO_TCP, ipv4_src=src_ip, ipv4_dst=dst_ip, tcp_src=src_port, tcp_dst=dst_port)
            self.add_flow(datapath, 1, match, actions)

        data = None
        if msg.buffer_id == ofproto.OFP_NO_BUFFER:
            data = msg.data
            
        # construct packet_out message and send it.
        out = parser.OFPPacketOut(datapath=datapath,
                                  buffer_id=ofproto.OFP_NO_BUFFER,
                                  in_port=in_port, actions=actions,
                                  data=msg.data)
        datapath.send_msg(out)
