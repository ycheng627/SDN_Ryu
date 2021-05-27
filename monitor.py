from operator import attrgetter
import controller
from ryu.controller import ofp_event
from ryu.controller.handler import MAIN_DISPATCHER, DEAD_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.lib import hub
from collections import defaultdict
import numpy as np


class SimpleMonitor13(controller.SimpleSwitch13):

    def __init__(self, *args, **kwargs):
        super(SimpleMonitor13, self).__init__(*args, **kwargs)
        self.datapaths = {}
        self.monitor_thread = hub.spawn(self._monitor)
        self.record = {}
        self.threshold = 1e6

    @set_ev_cls(ofp_event.EventOFPStateChange,
                [MAIN_DISPATCHER, DEAD_DISPATCHER])
    def _state_change_handler(self, ev):
        datapath = ev.datapath
        if ev.state == MAIN_DISPATCHER:
            if datapath.id not in self.datapaths:
                self.logger.debug('register datapath: %016x', datapath.id)
                self.datapaths[datapath.id] = datapath
        elif ev.state == DEAD_DISPATCHER:
            if datapath.id in self.datapaths:
                self.logger.debug('unregister datapath: %016x', datapath.id)
                del self.datapaths[datapath.id]

    def _monitor(self):
        while True:
            for dp in self.datapaths.values():
                self._request_stats(dp)
            hub.sleep(10)

    def _request_stats(self, datapath):
        self.logger.debug('send stats request: %016x', datapath.id)
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        req = parser.OFPFlowStatsRequest(datapath)
        datapath.send_msg(req)

        req = parser.OFPPortStatsRequest(datapath, 0, ofproto.OFPP_ANY)
        datapath.send_msg(req)

    def block_flow(self, datapath, priority, flow):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        # match = None

        # in_port = flow.match['in_port']
        # eth_type = flow.match['eth_type']
        # ip_proto = flow.match['ip_proto']
        # ipv4_src = flow.match['ipv4_src']
        # ipv4_dst = flow.match['ipv4_dst']

        # if ip_proto == inet.IPPROTO_UDP:
        #     udp_src = flow.match['udp_src']
        #     udp_dst = flow.match['udp_dst']
        #     match = parser.OFPMatch(in_port=in_port, eth_type=ether.ETH_TYPE_IP, ip_proto=inet.IPPROTO_UDP, ipv4_src=ipv4_src, ipv4_dst=ipv4_dst, udp_src=udp_src, udp_dst=udp_dst)
        # else:
        #     tcp_src = flow.match['tcp_src']
        #     tcp_dst = flow.match['tcp_dst']
        #     match = parser.OFPMatch(in_port=in_port, eth_type=ether.ETH_TYPE_IP, ip_proto=inet.IPPROTO_TCP, ipv4_src=ipv4_src, ipv4_dst=ipv4_dst, tcp_src=tcp_src, tcp_dst=tcp_dst)

        instruction = [parser.OFPInstructionActions(ofproto.OFPIT_CLEAR_ACTIONS, [])]
        # mod = parser.OFPFlowMod(datapath=datapath, priority=priority, match=match, instructions=instruction)

        mod = parser.OFPFlowMod(datapath=datapath, priority=priority, match=flow.match, instructions=instruction)
        datapath.send_msg(mod)


    @set_ev_cls(ofp_event.EventOFPFlowStatsReply, MAIN_DISPATCHER)
    def _flow_stats_reply_handler(self, ev):
        body = ev.msg.body
        dpid = ev.msg.datapath.id

        if dpid not in self.record:
            self.record[dpid] = defaultdict(int)
        
        self.logger.info('datapath '
                'in-port  src_ip        src_port dst_ip        dst_port proto'
                'out-port packets  bytes')
        self.logger.info('-------- '
                '-------- ------------- -------- ------------- -------- ------'
                '-------- -------- --------')

        # self.logger.info('datapath         '
        #                 'in-port  eth-dst           '
        #                 'out-port packets  bytes')
        # self.logger.info('---------------- '
        #                 '-------- ----------------- '
        #                 '-------- -------- --------')
        stats = sorted([flow for flow in body if flow.priority == 1],
                        key=lambda flow: flow.match['in_port'])
        
        local_record = {}
        grow_list = []
        group_dict = defaultdict(list)

        def log_and_block_congestion_flow(order, group, group_grow_list):
            self.logger.info('!!!!! Congestion detected !!!!!')
            self.logger.info('!!!!! Listing congestion flows !!!!!')
            self.logger.info('datapath '
                    'in-port  src_ip        src_port dst_ip        dst_port proto '
                    'out-port grow')
            self.logger.info('--------- '
                    '-------- ------------- -------- ------------- -------- ------'
                    '-------- --------')

            big_flow = 0
            big_flow_stat = None

            for group_idx in order:
                stat = stats[group[group_idx]]
                grow = group_grow_list[group_idx]

                protocol = 'TCP' if stat.match['tcp_src'] is not None else 'UDP'
                if protocol == 'TCP':
                    self.logger.info('%08x %8x %14s %8d %14s %8d %5s %8x %8d',
                            dpid, stat.match['in_port'], 
                            stat.match['ipv4_src'], stat.match['tcp_src'],
                            stat.match['ipv4_dst'], stat.match['tcp_dst'], 'TCP',
                            stat.instructions[0].actions[0].port, grow)
                elif protocol == 'UDP':
                    self.logger.info('%08x %8x %14s %6d %14s %6d %5s %8x %8d',
                            dpid, stat.match['in_port'], 
                            stat.match['ipv4_src'], stat.match['udp_src'],
                            stat.match['ipv4_dst'], stat.match['udp_dst'], 'UDP',
                            stat.instructions[0].actions[0].port, grow)

                if grow > big_flow:
                    big_flow = grow
                    big_flow_stat = stat
                
            # self.block_flow(ev.msg.datapath, 1, big_flow_stat.match['in_port'], big_flow_stat.match['eth_dst'])
            self.block_flow(ev.msg.datapath, 2, big_flow_stat)

        for idx, stat in enumerate(stats):
            if len(stat.instructions[0].actions) == 0: # blocked flow
                grow_list.append(0)
                continue
            
            transmit_amount = stat.byte_count
            in_port = stat.match['in_port']
            out_port = stat.instructions[0].actions[0].port

            protocol = 'TCP' if stat.match['tcp_src'] is not None else 'UDP'

            if protocol == 'TCP':
                key = (in_port, out_port, stat.match['ipv4_src'], stat.match['tcp_src'],
                       stat.match['ipv4_dst'], stat.match['tcp_dst'], 'TCP')
                previous_transmit_amount = self.record[dpid][key]

                self.logger.info('%8x %8x %14s %6d %14s %6d %5s %8x %8d %8d %8d',
                        dpid, stat.match['in_port'], 
                        stat.match['ipv4_src'], stat.match['tcp_src'],
                        stat.match['ipv4_dst'], stat.match['tcp_dst'], 'TCP',
                        out_port, stat.packet_count, transmit_amount, previous_transmit_amount)
            elif protocol == 'UDP':
                key = (in_port, out_port, stat.match['ipv4_src'], stat.match['udp_src'],
                       stat.match['ipv4_dst'], stat.match['udp_dst'], 'TCP')
                previous_transmit_amount = self.record[dpid][key]

                self.logger.info('%8x %8x %14s %8d %14s %8d %5s %8x %8d %8d %8d',
                        dpid, stat.match['in_port'], 
                        stat.match['ipv4_src'], stat.match['udp_src'],
                        stat.match['ipv4_dst'], stat.match['udp_dst'], 'UDP',
                        out_port, stat.packet_count, transmit_amount, previous_transmit_amount)
            
            if in_port == out_port:
                grow_list.append(0)
                continue

            local_record[key] = transmit_amount

            if key in self.record[dpid]:
                prev_transmit_amount = self.record[dpid][key]
                grow_amount = transmit_amount - prev_transmit_amount
            else:
                grow_amount = transmit_amount
            
            grow_list.append(grow_amount)
            group_dict[out_port].append(idx)
        

        for group_key, group in group_dict.items():


            # if len(group) == 1:
            #     continue

            

            group_grow_list = [grow_list[i] for i in group]

            order = np.argsort(group_grow_list)[::-1]
            grow_sum = np.sum(group_grow_list)
            self.logger.info('grow sum: %d', grow_sum)

            if grow_sum < self.threshold:
                continue

            # for group_idx in order:
            #     stat = stats[group[group_idx]]
            #     grow = group_grow_list[group_idx]
            #     in_port = stat.match['in_port']
            #     out_port = stat.instructions[0].actions[0].port
            log_and_block_congestion_flow(order, group, group_grow_list)

            self.logger.info("###\n###\n")

        for key, value in local_record.items():
            self.record[dpid][key] = value

    @set_ev_cls(ofp_event.EventOFPPortStatsReply, MAIN_DISPATCHER)
    def _port_stats_reply_handler(self, ev):
        body = ev.msg.body

        self.logger.info('datapath port     '
                         'rx-pkts  rx-bytes rx-error '
                         'tx-pkts  tx-bytes tx-error')
        self.logger.info('-------- -------- '
                         '-------- -------- -------- '
                         '-------- -------- --------')
        for stat in sorted(body, key=attrgetter('port_no')):
            self.logger.info('%08x %8x %8d %8d %8d %8d %8d %8d',
                             ev.msg.datapath.id, stat.port_no,
                             stat.rx_packets, stat.rx_bytes, stat.rx_errors,
                             stat.tx_packets, stat.tx_bytes, stat.tx_errors)
