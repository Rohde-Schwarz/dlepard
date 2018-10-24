# SPDX-License-Identifier: MIT

import logging
import asyncio
import socket
import struct
import os
import sys
import argparse
import json
import urllib.error
import urllib.request

from helperfunctions import *
from items_specification import *
from dataitems import *
from udpproxy import *
from heartbeat_timer import *

sys.path.append('../modules/radio')

log = logging.getLogger("hdremu")
fh = logging.FileHandler('/var/logs/tmp/trace.txt')
formatter = logging.Formatter('%(asctime)s %(message)s')
fh.setFormatter(formatter)
# log.addHandler(fh)
# log.addHandler(logging.StreamHandler(sys.stdout))
#log.setLevel(logging.DEBUG)

PROG_NAME = "DLEP_ROUTER"


def extract_itemtype_and_length(msgbuf):
    dataItemType = DataItemType(int.from_bytes(msgbuf[0:2], 'big'))
    length = int.from_bytes(msgbuf[2:4], 'big')

    return dataItemType, length


################################################################################
## Protocol behavior
#
class DlepSessionState(IntEnum):
    PEER_DISCOVERY_STATE = 0,
    SESSION_INITIALISATION_STATE = 1,
    IN_SESSION_STATE = 2,
    SESSION_TERMINATION_STATE = 3,
    SESSION_RESET_STATE = 4


class DestinationInformationBase:
    def __init__(self):
        self.macAddress = None
        self.ipv4Address = None
        self.maxDatarateRx = 0
        self.maxDatarateTx = 0
        self.currDatarateRx = 0
        self.currDatarateTx = 0
        self.latency = 0


class DLEPSession:
    def __init__(self, conf, interface, loop=None, update_callback = None):
        self.dlep_mcast_ipv4addr = conf["dlep"]["mcast-ip4addr"]
        self.dlep_udp_port = conf["dlep"]["udp-port"]

        self.conf = conf

        self.loop = loop
        self.state = DlepSessionState.PEER_DISCOVERY_STATE
        self.interface = interface
        self.udpProxy = UDPProxy(self.dlep_mcast_ipv4addr, self.dlep_udp_port, interface,
                                 self.on_udp_receive, loop, multicast=True)
        self.tcpProxy = None

        self.running = False
        self.heartbeatTimer = None
        self.heartbeatWatchdog = None
        self.missedHeartbeats = 0
        self.ownHeartbeatInterval = 5000

        self.peerTcpPort = None
        self.peerType = ""
        self.peerHeartbeat = 0
        self.peerInformationBase = DestinationInformationBase()

        self.destinationInformationBase = []

        self.update_callback = update_callback

    def on_udp_receive(self, message, addr):
        log.debug("received something with len {} from {}".format(len(message), addr))
        total_len = len(message)
        pdu = SignalPdu()
        pdu.from_buffer(message[:SIGNAL_HEADER_SIZE])
        log.debug("EXTRACTED signal PDU type {} len {}".format(pdu.type, pdu.len))

        pdu.data_items = extract_all_dataitems(message[SIGNAL_HEADER_SIZE:])

        if self.state == DlepSessionState.PEER_DISCOVERY_STATE:
            if pdu.type == SignalType.PEER_OFFER_SIGNAL:
                self.process_data_items(pdu.data_items, self.peerInformationBase)

                asyncio.ensure_future(self.enter_session_initialisation_state())

    def on_tcp_receive(self, message, addr):
        self.reset_heartbeat_watchdog()

        log.debug("received something with len {} from {}".format(len(message), addr))
        total_len = len(message)
        pdu = MessagePdu()
        pdu.from_buffer(message[:MESSAGE_HEADER_LENGTH])
        log.debug("EXTRACTED message PDU type {} len {}".format(pdu.type, pdu.len))

        pdu.data_items = extract_all_dataitems(message[MESSAGE_HEADER_LENGTH:])

        if self.state == DlepSessionState.SESSION_INITIALISATION_STATE:
            if pdu.type == MessageType.SESSION_INITIALISATION_RESPONSE_MESSAGE:
                for item in pdu.data_items:
                    if item.type == DataItemType.STATUS:
                        if item.status_code == StatusCode.SUCCESS:
                            self.process_data_items(pdu.data_items, self.peerInformationBase)
                            self.print_destination_information_base(peer=True)
                            self.enter_in_session_state()

        elif self.state == DlepSessionState.IN_SESSION_STATE:
            if pdu.type == MessageType.DESTINATION_UP_MESSAGE:
                log.debug("--> got destination up message")
                new_dib = DestinationInformationBase()
                self.process_data_items(pdu.data_items, new_dib)
                self.destinationInformationBase.append(new_dib)

                response_msg = MessagePdu(MessageType.DESTINATION_UP_RESPONSE_MESSAGE)
                response_msg.data_items.append(MacAddress(new_dib.macAddress))
                response_msg.data_items.append(Status(StatusCode.SUCCESS, "RX-OK"))
                self.tcpProxy.send_msg(response_msg.to_buffer())

                self.print_destination_information_base(peer=True)

            elif pdu.type == MessageType.DESTINATION_DOWN_MESSAGE:
                log.debug("--> got destination down message")
                dib_to_remove = DestinationInformationBase()
                self.process_data_items(pdu.data_items, dib_to_remove)
                entries_to_remove = list(filter(lambda x: dib_to_remove.macAddress.lower() == x.macAddress.lower(),
                                         self.destinationInformationBase))
                for x in entries_to_remove:
                    self.destinationInformationBase.remove(x)

                response_msg = MessagePdu(MessageType.DESTINATION_DOWN_RESPONSE_MESSAGE)
                response_msg.data_items.append(MacAddress(dib_to_remove.macAddress))
                response_msg.data_items.append(Status(StatusCode.SUCCESS, "RX-OK"))
                self.tcpProxy.send_msg(response_msg.to_buffer())

                self.print_destination_information_base(peer=True)

            elif pdu.type == MessageType.DESTINATION_UPDATE_MESSAGE:
                log.debug("--> got destination update message")
                new_dib = DestinationInformationBase()
                self.process_data_items(pdu.data_items, new_dib)

                for i, entry in enumerate(self.destinationInformationBase):
                    if entry.macAddress.lower() == new_dib.macAddress.lower():
                        self.destinationInformationBase[i] = new_dib

                self.print_destination_information_base(peer=True)
            elif pdu.type == MessageType.HEARTBEAT_MESSAGE:
                log.debug("-> received Heartbeat Message")

    def start_heartbeat_timer(self):
            # TODO: this should be peerHeartbeat!!
            self.heartbeatTimer = HeartbeatTimer(self.ownHeartbeatInterval/1000, self.heartbeat_callback)
            self.heartbeatTimer.start()

    def restart_heartbeat_timer(self):
        if self.heartbeatTimer is not None:
            self.heartbeatTimer.cancel()
            self.start_heartbeat_timer()

    def heartbeat_callback(self):
        log.debug("sending Heartbeat")
        heartbeat_pdu = MessagePdu(MessageType.HEARTBEAT_MESSAGE)
        heartbeat_pdu.len = 0
        self.tcpProxy.send_msg(heartbeat_pdu.to_buffer())

    def start_watchdog_timer(self):
        self.heartbeatWatchdog = HeartbeatTimer(self.ownHeartbeatInterval/1000, self.watchdog_callback)
        self.heartbeatWatchdog.start()

    def reset_heartbeat_watchdog(self):
        if self.heartbeatWatchdog is not None:
            self.missedHeartbeats = 0
            self.heartbeatWatchdog.reset()

    def watchdog_callback(self):
        self.missedHeartbeats += 1
        log.warning("!!! missed a heartbeat nr {} from peer !!!".format(self.missedHeartbeats))

    def process_data_items(self, item_array, information_base: DestinationInformationBase):
        for item in item_array:
            if item.type == DataItemType.IPV4_CONNECTION_POINT:
                information_base.ipv4Address = item.ipaddr
                self.peerTcpPort = item.tcp_port
            elif item.type == DataItemType.PEER_TYPE:
                self.peerType = item.description
            elif item.type == DataItemType.HEARTBEAT_INTERVAL:
                self.peerHeartbeat = item.heartbeatInterval
            elif item.type == DataItemType.MAXIMUM_DATA_RATE_RX:
                information_base.maxDatarateRx = item.datarate
            elif item.type == DataItemType.MAXIMUM_DATA_RATE_TX:
                information_base.maxDatarateTx = item.datarate
            elif item.type == DataItemType.CURRENT_DATA_RATE_RX:
                information_base.currDatarateRx = item.datarate
            elif item.type == DataItemType.CURRENT_DATA_RATE_TX:
                information_base.currDatarateTx = item.datarate
            elif item.type == DataItemType.LATENCY:
                information_base.latency = item.latency
            elif item.type == DataItemType.MAC_ADDRESS:
                information_base.macAddress = item.adr
            elif item.type == DataItemType.IPV4_ADDRESS:
                information_base.ipv4Address = item.ipaddr

    async def enter_session_initialisation_state(self):
        log.debug("entering SESSION_INITIALISATION_STATE...")
        self.state = DlepSessionState.SESSION_INITIALISATION_STATE

        # TODO this should NOT be UDP!!!
        # TODO dont use the multicast address! -- used because arp not implemented yet
        self.tcpProxy = UDPProxy(self.dlep_mcast_ipv4addr, self.peerTcpPort, self.interface,
                                 self.on_tcp_receive, self.loop, multicast=True)

        await self.tcpProxy.start()
        log.debug("started tcp Proxy")

        sessionInitMessage = MessagePdu(MessageType.SESSION_INITIALISATION_MESSAGE)
        sessionInitMessage.data_items.append(HeartbeatInterval(self.ownHeartbeatInterval))
        sessionInitMessage.data_items.append(PeerType("servus"))

        log.debug("sending session initialisation message")
        self.tcpProxy.send_msg(sessionInitMessage.to_buffer())

    def enter_in_session_state(self):
        self.state = DlepSessionState.IN_SESSION_STATE
        log.debug("entering IN_SESSION_STATE")
        self.start_heartbeat_timer()
        self.start_watchdog_timer()

    def print_destination_information_base(self, peer=False):
        if peer:
            log.info("=====================================================================")
            log.info("====================== Peer Information =============================")
            log.info("=====================================================================")
            log.info("IPv4 Address     - {}".format(self.peerInformationBase.ipv4Address))
            log.info("Port             - {}".format(self.peerTcpPort))
            log.info("Interface        - {}".format(self.interface))
            log.info("Heartbeat        - {}".format(self.peerHeartbeat))
            log.info("Max. Datarate RX - {}".format(self.peerInformationBase.maxDatarateRx))
            log.info("Max. Datarate TX - {}".format(self.peerInformationBase.maxDatarateTx))
            log.info("Cur. Datarate RX - {}".format(self.peerInformationBase.currDatarateRx))
            log.info("Cur. Datarate TX - {}".format(self.peerInformationBase.currDatarateTx))
            log.info("Latency          - {}".format(self.peerInformationBase.latency))

        log.info("=====================================================================")
        log.info("=============== Current Destination Information Base ================")
        log.info("=====================================================================")
        for dest in self.destinationInformationBase:
            log.info("---------------------------------------------------------------------")
            log.info("MAC Address      - {}".format(dest.macAddress))
            log.info("IPv4 Address     - {}".format(dest.ipv4Address))
            log.info("Max. Datarate RX - {}".format(dest.maxDatarateRx))
            log.info("Max. Datarate TX - {}".format(dest.maxDatarateTx))
            log.info("Cur. Datarate RX - {}".format(dest.currDatarateRx))
            log.info("Cur. Datarate TX - {}".format(dest.currDatarateTx))
            log.info("Latency          - {}".format(dest.latency))

        # TODO: maybe this is not the best place to call it
        if self.update_callback is not None:
            self.update_callback(self)

    def get_information_json_string(self):
        json_data = dict()
        json_data['destinations'] = []
        json_data['peer'] = {
            'tcp_port': self.peerTcpPort,
            'interface': self.interface,
            'heartbeat_interval': self.peerHeartbeat,
            'peer_type': self.peerTcpPort,
            'ipv4-address': self.peerInformationBase.ipv4Address,
            'max_datarate_rx': self.peerInformationBase.maxDatarateRx,
            'max_datarate_tx': self.peerInformationBase.maxDatarateTx,
            'cur_datarate_rx': self.peerInformationBase.currDatarateRx,
            'cur_datarate_tx': self.peerInformationBase.currDatarateTx,
            'latency': self.peerInformationBase.latency
        }
        for dest in self.destinationInformationBase:
            destination_data = {
                'mac-address': dest.macAddress,
                'ipv4-address': dest.ipv4Address,
                'max_datarate_rx': dest.maxDatarateRx,
                'max_datarate_tx': dest.maxDatarateTx,
                'cur_datarate_rx': dest.currDatarateRx,
                'cur_datarate_tx': dest.currDatarateTx,
                'latency': dest.latency
            }
            json_data['destinations'].append(destination_data)

        json_str = json.dumps(json_data)
        return json_str

    async def start(self):
        await self.udpProxy.start()
        self.running = True
        log.debug("dlep-router is running")
        asyncio.ensure_future(self.execute())

    async def execute(self):
        while self.running:
            if self.state == DlepSessionState.PEER_DISCOVERY_STATE:
                discovery_pdu = SignalPdu(SignalType.PEER_DISCOVERY_SIGNAL)
                pdu = discovery_pdu.to_buffer()

                log.debug("sending discovery signal of len {}".format(len(pdu)))
                self.udpProxy.send_msg(pdu)

            # Wait 60 seconds to send next Peer Discovery signal
            await asyncio.sleep(10)


def extract_all_dataitems(message):
    total_len = len(message)
    analyzed_len = 0
    all_data_items = []

    while analyzed_len < total_len:
        item_type_current, length_current_item = extract_itemtype_and_length(
            message[analyzed_len:analyzed_len+16])

        log.debug("extracting dataitem type {} and len {}".format(item_type_current, length_current_item))

        length_current_item += 4  # we need the type and length fields too

        if (analyzed_len + length_current_item) > total_len:
            log.error("RX: length of Data Item exceeded total buffer length")
            return all_data_items

        item = None

        if item_type_current == DataItemType.IPV4_CONNECTION_POINT:
            item = DataItemIp4ConnPt()
        elif item_type_current == DataItemType.PEER_TYPE:
            item = PeerType()
        elif item_type_current == DataItemType.HEARTBEAT_INTERVAL:
            item = HeartbeatInterval()
        elif item_type_current == DataItemType.STATUS:
            item = Status()
        elif item_type_current == DataItemType.MAXIMUM_DATA_RATE_RX:
            item = MaximumDatarateReceive()
        elif item_type_current == DataItemType.MAXIMUM_DATA_RATE_TX:
            item = MaximumDatarateTransmit()
        elif item_type_current == DataItemType.CURRENT_DATA_RATE_RX:
            item = CurrentDatarateReceive()
        elif item_type_current == DataItemType.CURRENT_DATA_RATE_TX:
            item = CurrentDatarateTransmit()
        elif item_type_current == DataItemType.LATENCY:
            item = Latency()
        elif item_type_current == DataItemType.MAC_ADDRESS:
            item = MacAddress()
        elif item_type_current == DataItemType.IPV4_ADDRESS:
            item = IPv4Address()
        else:
            log.warning("unknown dataitem type")

        if item is not None:
            item.from_buffer(message[analyzed_len: (analyzed_len + length_current_item)])
            all_data_items.append(item)
            log.debug("found new Dataitem type {}".format(item.type))

        analyzed_len += length_current_item

    return all_data_items

####################### MAIN ######################################


def dlep_router_init(ctx, loop, interfaces):
    ctx['loop'] = loop
    sessions = []
    for intf in interfaces:
        session = DLEPSession(ctx['conf'], intf, loop=loop, update_callback=update_webview)
        log.debug("run dlep-router for if {}".format(intf))
        loop.run_until_complete(session.start())
        sessions.append(session)

    return sessions


def main(ctx):
    loop = asyncio.get_event_loop()
    loop.set_debug(True)
    interfaces = ctx['args'].interface
    sessions = dlep_router_init(ctx, loop, interfaces)
    asyncio.ensure_future(init_logging(sessions))
    try:
        loop.run_forever()
    except KeyboardInterrupt:
        for task in asyncio.Task.all_tasks():
            task.cancel()
        loop.close()


def parse_args():
    parser = argparse.ArgumentParser()
    parser.add_argument("-f", "--configuration", help="configuration", type=str, default=None)
    parser.add_argument("-v", "--verbose", help="verbose", action='store_true', default=False)
    parser.add_argument("-i", "--interface", type=str, nargs='+', required=True)
    args = parser.parse_args()
    if not args.configuration:
        emsg = "Configuration required, please specify a valid file path, exiting now\n"
        sys.stderr.write(emsg)
    return args


def load_configuration_file(args):
    file = open(args.configuration)
    configur = json.loads(file.read())
    return configur


def update_webview(session: DLEPSession):
    info = session.get_information_json_string().encode('utf-8')
    if "rest-if" in session.conf:
        for url in session.conf["rest-if"]["broadcast-url"]:
            send_api_call(url, info)


def send_api_call(url: str, info):
    proxy_support = urllib.request.ProxyHandler({})
    opener = urllib.request.build_opener(proxy_support)
    urllib.request.install_opener(opener)
    req = urllib.request.Request(url)
    req.add_header('Content-Type', 'application/json')
    req.add_header('Accept', 'application/json')
    req.add_header('User-Agent', 'Mozilla/5.0 (compatible; Chrome/22.0.1229.94; Windows NT)')
    req.add_header('Content-Length', len(info))
    try:
        urllib.request.urlopen(req, info, timeout=3)
    except urllib.error.URLError as e:
        print("Webview update failed with {}".format(e.reason))


async def init_logging(session_list: list):
    log2 = logging.getLogger("dlepJsonLogger")
    fh = logging.FileHandler('./log.txt')
    formatter = logging.Formatter('%(asctime)s %(message)s')
    fh.setFormatter(formatter)
    log2.addHandler(fh)
    log2.setLevel(logging.INFO)

    while True:
        for session in session_list:
            info = session.get_information_json_string()
            log2.info(info)
            await asyncio.sleep(10)


def conf_init():
    args = parse_args()
    conf = load_configuration_file(args)
    return conf, args


def ctx_init():
    return dict()


if __name__ == '__main__':
    sys.stderr.write("{}\n".format(PROG_NAME))
    conf, args = conf_init()
    ctx = ctx_init()
    ctx['conf'] = conf
    ctx['args'] = args
    main(ctx)
