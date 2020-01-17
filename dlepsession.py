import asyncio
import json
from udpproxy import UDPProxy
from tcpproxy import TCPProxy
from dataitems import *
from heartbeattimer import HeartbeatTimer


class DlepSessionState(IntEnum):
    """
    class DlepSessionState represents all the states of the DLEP Session as
    defined in RFC8175
    """
    PEER_DISCOVERY_STATE = 0
    SESSION_INITIALISATION_STATE = 1
    IN_SESSION_STATE = 2
    SESSION_TERMINATION_STATE = 3
    SESSION_RESET_STATE = 4


class DestinationInformationBase:
    """
    Encapsulates all information related to the destinations
    """
    def __init__(self):
        self.mac_address = None
        self.ipv4_address = None
        self.max_datarate_rx = 0
        self.max_datarate_tx = 0
        self.curr_datarate_rx = 0
        self.curr_datarate_tx = 0
        self.latency = 0
        self.loss = 0


class RecentEvent:
    """
    Encapsulates all information about recently occured events like
    destination-up destination-down messages. This information has to be
    forwarded by the rest-api.
    """
    TYPE_DEST_DOWN = "dest-down"
    TYPE_DEST_UP = "dest-up"

    def __init__(self, ev_type, mac, ipv4):
        self.type = ev_type
        self.ipv4_addr = ipv4
        self.node_mac_addr = mac


class DLEPSession:
    def __init__(self, conf, interface, loop=None, update_callback=None):
        """
        Create a new instance of a DLEP session for a single interface
        Args:
            conf: configuration to be registered
            interface: Name of the OS interface (e.g. enp1s0)
            loop: asyncio main loop
            update_callback: this method is called for signalling major updates
                             of the internal database
        """
        self.dlep_mcast_ipv4addr = conf["dlep"]["mcast-ip4addr"]
        self.dlep_udp_port = conf["dlep"]["udp-port"]

        self.conf = conf

        self.loop = loop
        self.state = DlepSessionState.PEER_DISCOVERY_STATE
        self.interface = interface
        self.udp_proxy = UDPProxy(self.dlep_mcast_ipv4addr,
                                  self.dlep_udp_port,
                                  interface,
                                  self.on_udp_receive,
                                  loop,
                                  multicast=True)
        self.tcp_proxy = None

        self.running = False
        self.heartbeat_timer = None
        self.heartbeat_watchdog = None
        self.missed_heartbeats = 0
        if "heartbeat-interval-ms" in conf["dlep"]:
            self.own_heartbeat_interval = conf["dlep"]["heartbeat-interval-ms"]
        else:
            self.own_heartbeat_interval = 60000  # See RFC 8175

        self.peer_tcp_port = None
        self.peer_type = ""
        self.peer_heartbeat = 0
        self.peer_information_base = DestinationInformationBase()

        self.destination_information_base = []
        self.recent_events = []

        self.update_callback = update_callback

    def __process_session_init_tcp_message(self, pdu):
        """
        Handles all the TCP messages in the SESSION_INITIALISATION_STATE
        Args:
            pdu: message pdu extracted from tcp message including all dataitems

        """
        if pdu.type == MessageType.SESSION_INITIALISATION_RESPONSE_MESSAGE:
            for item in pdu.data_items:
                if item.type == DataItemType.STATUS:
                    if item.status_code == StatusCode.SUCCESS:
                        self.process_data_items(pdu.data_items,
                                                self.peer_information_base)
                        self.print_destination_information_base(peer=True)
                        self.enter_in_session_state()

    def __process_in_session_tcp_message(self, pdu):
        """
        Handles all the TCP messages in the IN_SESSION_STATE
        - updates destination information base
        - performs state transitions if required
        - sends response messages
        Args:
            pdu: message pdu extracted from tcp message including all dataitems

        """
        if pdu.type == MessageType.DESTINATION_UP_MESSAGE:
            log.debug("--> got destination up message")
            new_dib = DestinationInformationBase()
            self.process_data_items(pdu.data_items, new_dib)
            self.destination_information_base.append(new_dib)
            self.recent_events.append(RecentEvent(RecentEvent.TYPE_DEST_UP,
                                                  new_dib.mac_address,
                                                  new_dib.ipv4_address))

            response_msg = MessagePdu(MessageType.DESTINATION_UP_RESPONSE_MESSAGE)
            response_msg.data_items.append(MacAddress(new_dib.mac_address))
            response_msg.data_items.append(Status(StatusCode.SUCCESS, "RX-OK"))
            self.tcp_proxy.send_msg(response_msg.to_buffer())

            self.print_destination_information_base(peer=True)

        elif pdu.type == MessageType.DESTINATION_DOWN_MESSAGE:
            log.debug("--> got destination down message")
            dib_to_remove = DestinationInformationBase()
            self.process_data_items(pdu.data_items, dib_to_remove)
            self.recent_events.append(RecentEvent(RecentEvent.TYPE_DEST_DOWN,
                                                  dib_to_remove.mac_address,
                                                  dib_to_remove.ipv4_address))

            list_filter = filter(
                lambda x: dib_to_remove.mac_address.lower() == x.mac_address.lower(),
                self.destination_information_base
            )
            entries_to_remove = list(list_filter)
            for x in entries_to_remove:
                self.destination_information_base.remove(x)

            response_msg = MessagePdu(MessageType.DESTINATION_DOWN_RESPONSE_MESSAGE)
            response_msg.data_items.append(MacAddress(dib_to_remove.mac_address))
            response_msg.data_items.append(Status(StatusCode.SUCCESS, "RX-OK"))
            self.tcp_proxy.send_msg(response_msg.to_buffer())

            self.print_destination_information_base(peer=True)

        elif pdu.type == MessageType.DESTINATION_UPDATE_MESSAGE:
            log.debug("--> got destination update message")
            new_dib = DestinationInformationBase()
            self.process_data_items(pdu.data_items, new_dib)

            for i, entry in enumerate(self.destination_information_base):
                if entry.mac_address.lower() == new_dib.mac_address.lower():
                    self.destination_information_base[i] = new_dib

            self.print_destination_information_base(peer=True)

        elif pdu.type == MessageType.HEARTBEAT_MESSAGE:
            log.debug("-> received Heartbeat Message")

        elif pdu.type == MessageType.SESSION_TERMINATION_MESSAGE:
            log.debug("--> got session termination message")
            response_msg = MessagePdu(MessageType.SESSION_TERMINATION_RESPONSE_MESSAGE)
            self.tcp_proxy.send_msg(response_msg.to_buffer())
            self.session_reset()

    def __process_session_termination_tcp_message(self, pdu):
        """
        Handles all the TCP messages in the SESSION_TERMINATION_STATE
        Args:
            pdu: message pdu extracted from tcp message including all dataitems

        """
        if pdu.type == MessageType.SESSION_TERMINATION_RESPONSE_MESSAGE:
            log.debug("--> got session termination response message")
            self.session_reset()

    def on_udp_receive(self, message, addr):
        """
        Callback function for asyncio udp receiver.
        Handles the incoming messages according to the DLEP state machine
        Args:
            message: The message received over UDP
            addr: Address from the transmitter
        """
        log.debug("received something with len {} from {}".format(len(message), addr))
        pdu = SignalPdu()
        pdu.from_buffer(message[:SIGNAL_HEADER_SIZE])
        log.debug("EXTRACTED signal PDU type {} len {}".format(pdu.type,
                                                               pdu.len))

        pdu.data_items = self.extract_all_dataitems(message[SIGNAL_HEADER_SIZE:])

        if self.state == DlepSessionState.PEER_DISCOVERY_STATE:
            if pdu.type == SignalType.PEER_OFFER_SIGNAL:
                self.process_data_items(pdu.data_items, self.peer_information_base)

                asyncio.ensure_future(self.enter_session_initialisation_state())

    def on_tcp_receive(self, message):
        """
        Callback function for asyncio tcp receiver.
        Handles the incoming messages according to the DLEP state machine
        Args:
            message: The message received over TCP
            addr: Address from the transmitter
        """
        self.reset_heartbeat_watchdog()

        log.debug("received something with len {}".format(len(message)))
        pdu = MessagePdu()
        pdu.from_buffer(message[:MESSAGE_HEADER_LENGTH])
        log.debug("EXTRACTED message PDU type {} len {}".format(pdu.type,
                                                                pdu.len))

        pdu.data_items = self.extract_all_dataitems(message[MESSAGE_HEADER_LENGTH:])

        if self.state == DlepSessionState.SESSION_INITIALISATION_STATE:
            self.__process_session_init_tcp_message(pdu)

        elif self.state == DlepSessionState.IN_SESSION_STATE:
            self.__process_in_session_tcp_message(pdu)

        elif self.state == DlepSessionState.SESSION_TERMINATION_STATE:
            self.__process_session_termination_tcp_message(pdu)

    def start_heartbeat_timer(self):
        # TODO: This should be peer_heartbeat
        timeout = (self.own_heartbeat_interval / 1000) + 2
        self.heartbeat_timer = HeartbeatTimer(timeout,
                                              self.heartbeat_callback)
        self.heartbeat_timer.start()

    def restart_heartbeat_timer(self):
        if self.heartbeat_timer is not None:
            self.heartbeat_timer.cancel()
            self.start_heartbeat_timer()

    def heartbeat_callback(self):
        """
        Callback function for signaling when the timer is expired.
        Leads to a new transmission of the heartbeat message
        """
        log.debug("sending Heartbeat")
        heartbeat_pdu = MessagePdu(MessageType.HEARTBEAT_MESSAGE)
        heartbeat_pdu.len = 0
        self.tcp_proxy.send_msg(heartbeat_pdu.to_buffer())

    def start_watchdog_timer(self):
        timeout = (self.own_heartbeat_interval / 1000) + 2
        self.heartbeat_watchdog = HeartbeatTimer(timeout,
                                                 self.watchdog_callback)
        self.heartbeat_watchdog.start()

    def reset_heartbeat_watchdog(self):
        if self.heartbeat_watchdog is not None:
            self.missed_heartbeats = 0
            self.heartbeat_watchdog.reset()

    def watchdog_callback(self):
        """
        Callback function for signalling when the watchdog is expired
        Indicates that a heartbeat from the peer has been missed
        """
        self.missed_heartbeats += 1
        log.critical("!!! missed a heartbeat "
                     "nr {} from peer !!!".format(self.missed_heartbeats))

        if (self.state == DlepSessionState.IN_SESSION_STATE) \
                and (self.missed_heartbeats > 3):
            self.enter_session_termination_state()
        if (self.state == DlepSessionState.SESSION_TERMINATION_STATE) \
                and (self.missed_heartbeats > 4):
            self.session_reset()

    def process_data_items(self,
                           item_array,
                           information_base: DestinationInformationBase):
        """
        Applies the received Data Items to the according fields of the
        destination information base
        Args:
            item_array: list where all the new Data Items are stored
            information_base: Destination information base where the new
                              items are applied to
        """
        for item in item_array:
            if item.type == DataItemType.IPV4_CONNECTION_POINT:
                information_base.ipv4_address = item.ipaddr
                self.peer_tcp_port = item.tcp_port
            elif item.type == DataItemType.PEER_TYPE:
                self.peer_type = item.description
            elif item.type == DataItemType.HEARTBEAT_INTERVAL:
                self.peer_heartbeat = item.heartbeatInterval
            elif item.type == DataItemType.MAXIMUM_DATA_RATE_RX:
                information_base.max_datarate_rx = item.datarate
            elif item.type == DataItemType.MAXIMUM_DATA_RATE_TX:
                information_base.max_datarate_tx = item.datarate
            elif item.type == DataItemType.CURRENT_DATA_RATE_RX:
                information_base.curr_datarate_rx = item.datarate
            elif item.type == DataItemType.CURRENT_DATA_RATE_TX:
                information_base.curr_datarate_tx = item.datarate
            elif item.type == DataItemType.LATENCY:
                information_base.latency = item.latency
            elif item.type == DataItemType.MAC_ADDRESS:
                information_base.mac_address = item.adr
            elif item.type == DataItemType.IPV4_ADDRESS:
                information_base.ipv4_address = item.ipaddr
            elif item.type == DataItemType.LOSS_RATE:
                information_base.loss = item.loss

    async def enter_session_initialisation_state(self):
        log.debug("entering SESSION_INITIALISATION_STATE...")
        self.state = DlepSessionState.SESSION_INITIALISATION_STATE

        # TODO: This should NOT be UDP
        # TODO: Don't use the multicast address
        # - used because arp not implemented yet
        self.tcp_proxy = TCPProxy(self.peer_information_base.ipv4_address,
                                  self.peer_tcp_port,
                                  self.interface,
                                  self.on_tcp_receive,
                                  self.loop)

        await self.tcp_proxy.start()
        log.debug("started tcp Proxy")

        session_init_message = MessagePdu(MessageType.SESSION_INITIALISATION_MESSAGE)
        session_init_message.data_items.append(HeartbeatInterval(self.own_heartbeat_interval))
        session_init_message.data_items.append(PeerType("servus"))

        log.debug("sending session initialisation message")
        self.tcp_proxy.send_msg(session_init_message.to_buffer())

    def enter_in_session_state(self):
        self.state = DlepSessionState.IN_SESSION_STATE
        log.debug("entering IN_SESSION_STATE")
        self.start_heartbeat_timer()
        self.start_watchdog_timer()

    def enter_session_termination_state(self):
        self.state = DlepSessionState.SESSION_TERMINATION_STATE
        log.debug("entering SESSION_TERMINATION_STATE")
        self.reset_heartbeat_watchdog()

        session_termination_message = MessagePdu(MessageType.SESSION_TERMINATION_MESSAGE)
        session_termination_message.data_items.append(Status(StatusCode.TIMED_OUT,
                                                             "missed Heartbeats!"))

        log.debug("sending Termination Message")
        self.tcp_proxy.send_msg(session_termination_message.to_buffer())

    def session_reset(self):
        self.state = DlepSessionState.SESSION_RESET_STATE
        log.debug("Session Reset")
        self.reset_heartbeat_watchdog()
        self.destination_information_base.clear()
        self.recent_events.clear()
        self.heartbeat_timer.stop()
        self.heartbeat_watchdog.stop()
        self.heartbeat_timer = None
        self.heartbeat_watchdog = None
        # TODO: Terminate tcp connection, del tcp proxy
        self.state = DlepSessionState.PEER_DISCOVERY_STATE
        log.debug("entering PEER_DISCOVERY_STATE")

    def print_destination_information_base(self, peer=False):
        if peer:
            log.info("=======================================================")
            log.info("=============== Peer Information ======================")
            log.info("=======================================================")
            log.info("IPv4 Address     - {}".format(self.peer_information_base.ipv4_address))
            log.info("Port             - {}".format(self.peer_tcp_port))
            log.info("Interface        - {}".format(self.interface))
            log.info("Heartbeat        - {}".format(self.peer_heartbeat))
            log.info("Max. data rate RX - {}".format(self.peer_information_base.max_datarate_rx))
            log.info("Max. data rate TX - {}".format(self.peer_information_base.max_datarate_tx))
            log.info("Cur. data rate RX - {}".format(self.peer_information_base.curr_datarate_rx))
            log.info("Cur. data rate TX - {}".format(self.peer_information_base.curr_datarate_tx))
            log.info("Latency          - {}".format(self.peer_information_base.latency))

        log.info("===========================================================")
        log.info("========== Current Destination Information Base ===========")
        log.info("===========================================================")
        for dest in self.destination_information_base:
            log.info("--------------------------------------------------------")
            log.info("MAC Address      - {}".format(dest.mac_address))
            log.info("IPv4 Address     - {}".format(dest.ipv4_address))
            log.info("Max. data rate RX - {}".format(dest.max_datarate_rx))
            log.info("Max. data rate TX - {}".format(dest.max_datarate_tx))
            log.info("Cur. data rate RX - {}".format(dest.curr_datarate_rx))
            log.info("Cur. data rate TX - {}".format(dest.curr_datarate_tx))
            log.info("Loss Rate        - {}".format(dest.loss))

        # TODO: Move to TCP callback
        if self.update_callback is not None:
            self.update_callback(self)

    def get_information_json_string(self):
        json_data = dict()
        json_data['events'] = []
        json_data['destinations'] = []
        json_data['peer'] = {
            'tcp_port': self.peer_tcp_port,
            'interface': self.interface,
            'heartbeat_interval': self.peer_heartbeat,
            'peer_type': self.peer_tcp_port,
            'ipv4-address': self.peer_information_base.ipv4_address,
            'max_datarate_rx': self.peer_information_base.max_datarate_rx,
            'max_datarate_tx': self.peer_information_base.max_datarate_tx,
            'cur_datarate_rx': self.peer_information_base.curr_datarate_rx,
            'cur_datarate_tx': self.peer_information_base.curr_datarate_tx,
            'latency': self.peer_information_base.latency
        }
        for dest in self.destination_information_base:
            destination_data = {
                'mac-address': dest.mac_address,
                'ipv4-address': dest.ipv4_address,
                'max_datarate_rx': dest.max_datarate_rx,
                'max_datarate_tx': dest.max_datarate_tx,
                'cur_datarate_rx': dest.curr_datarate_rx,
                'cur_datarate_tx': dest.curr_datarate_tx,
                'loss': dest.loss
            }
            json_data['destinations'].append(destination_data)

        for event in self.recent_events:
            ev_data = {
                'event-type': event.type,
                'ipv4-addr': event.ipv4_addr,
                'mac-addr': event.node_mac_addr
            }
            json_data['events'].append(ev_data)

        self.recent_events.clear()
        json_str = json.dumps(json_data)
        return json_str

    async def start(self):
        await self.udp_proxy.start()
        self.running = True
        log.debug("dlep-router is running")
        asyncio.ensure_future(self.execute())

    async def execute(self):
        while self.running:
            if self.state == DlepSessionState.PEER_DISCOVERY_STATE:
                # sending the peer discovery messages
                discovery_pdu = SignalPdu(SignalType.PEER_DISCOVERY_SIGNAL)
                pdu = discovery_pdu.to_buffer()

                log.info("sending discovery signal of len {}".format(len(pdu)))
                self.udp_proxy.send_msg(pdu)

            # Wait 60 seconds to send next Peer Discovery signal
            await asyncio.sleep(10)

    @staticmethod
    def extract_itemtype_and_length(msgbuf):
        dataitem_type = DataItemType(int.from_bytes(msgbuf[0:2], 'big'))
        length = int.from_bytes(msgbuf[2:4], 'big')

        return dataitem_type, length

    def extract_all_dataitems(self, message):
        """
        Extracts all the Data Items from the received tcp message
        Args:
            message: message buffer received over tcp

        Returns: list with all data items extracted from the given buffer
        """
        total_len = len(message)
        analyzed_len = 0
        all_data_items = []

        while analyzed_len < total_len:
            item_type_current, length_current_item = self.extract_itemtype_and_length(
                message[analyzed_len:analyzed_len+16])

            log.debug("extracting data item "
                      "type {} and len {}".format(item_type_current,
                                                  length_current_item))

            length_current_item += 4  # we need the type and length fields too

            if (analyzed_len + length_current_item) > total_len:
                log.warning("RX: length of Data Item exceeded total buffer length")
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
            elif item_type_current == DataItemType.LOSS_RATE:
                item = LossRate()
            else:
                log.warning("unknown data item type")

            if item is not None:
                length = analyzed_len + length_current_item
                item.from_buffer(message[analyzed_len: length])
                all_data_items.append(item)
                log.debug("found new data item type {}".format(item.type))

            analyzed_len += length_current_item

        return all_data_items
