import asyncio
from dataclasses import dataclass
from enum import IntEnum
import ipaddress
import json
import logging
from typing import Optional, List

from rsb_dlep.data_items import DataItemType, StatusCode, ExtensionType
import rsb_dlep.data_items.core as di
import rsb_dlep.data_items.link_identifier as lid
from rsb_dlep.message import MessageType, MessagePdu, MessageHeader
from rsb_dlep.signal import SignalType, SignalPdu

from .heartbeattimer import HeartbeatTimer
from .tcpproxy import TCPProxy
from .udpproxy import UDPProxy

log = logging.getLogger("DLEPard")


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
        self.link_identifier: bytes = b""
        self.ipv4_address: Optional[ipaddress.IPv4Address] = None
        self.ipv4_attached_subnets: List[ipaddress.IPv4Network] = []
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

    def __init__(
        self,
        ev_type,
        mac,
        ipv4: ipaddress.IPv4Address,
    ):
        self.type = ev_type
        self.node_mac_addr = mac
        self.ipv4_addr = ipv4


@dataclass
class DLEPConfiguration:
    local_ipv4addr: list
    """All addresses to bind to."""
    discovery: Optional[dict] = None
    """UDP configuration."""
    tcp: Optional[dict] = None
    """TCP configuration."""
    rest_if: Optional[dict] = None
    """REST interface configuraion."""
    heartbeat_interval_ms: int = 60000
    enable_lid_ext: bool = False


class DLEPSession:

    DISCOVERY_PORT = 854
    """Default discovery port."""
    HEARTBEAT_IVAL = 60000
    """Default heartbeat interval."""

    def __init__(self, conf: dict, addr: str, loop=None, update_callback=None):
        """
        Create a new instance of a DLEP session for a single interface
        Args:
            conf: configuration to be registered
            addr: local IP address to bind to
            loop: asyncio main loop
            update_callback: this method is called for signalling major updates
                             of the internal database
        """
        self.conf = DLEPConfiguration(**conf)

        if self.conf.discovery is None:
            self.dlep_mcast_ipv4addr = ""
            self.dlep_udp_port = self.DISCOVERY_PORT
        else:
            self.dlep_mcast_ipv4addr = self.conf.discovery.get("ipv4addr", "")
            self.dlep_udp_port = self.conf.discovery.get("port", self.DISCOVERY_PORT)

        self.loop = loop
        self.state = DlepSessionState.PEER_DISCOVERY_STATE
        self.addr = addr

        self.running = False
        self.heartbeat_timer = None
        self.heartbeat_watchdog = None
        self.missed_heartbeats = 0
        self.own_heartbeat_interval = self.conf.heartbeat_interval_ms
        self.enabled_extensions = set()
        self._msg_buffer = bytearray()

        self.peer_tcp_port = None
        self.peer_type = ""
        self.peer_heartbeat = 0
        self.peer_information_base = DestinationInformationBase()

        self.destination_information_base: List[DestinationInformationBase] = []
        self.recent_events: List[RecentEvent] = []

        self.update_callback = update_callback

        self.udp_proxy = self.__init_udp()
        if self.udp_proxy is None:
            log.info("Discovery disabled")
        self.tcp_proxy = self.__init_tcp()

    def __init_udp(self) -> Optional[UDPProxy]:
        if not self.dlep_mcast_ipv4addr:
            return None
        if self.conf.discovery.get("disabled", False):
            return None
        return UDPProxy(
            self.dlep_mcast_ipv4addr,
            self.dlep_udp_port,
            self.addr,
            self.on_udp_receive,
            self.loop,
            multicast=True,
        )

    def __init_tcp(self) -> Optional[TCPProxy]:
        if self.conf.tcp is None or self.addr not in self.conf.tcp:
            return None
        if self.udp_proxy is not None:
            return None
        tcp_conf = self.conf.tcp[self.addr]
        self.peer_information_base.ipv4_address = tcp_conf["ipv4addr"]
        self.peer_tcp_port = tcp_conf["port"]
        return TCPProxy(
            str(self.peer_information_base.ipv4_address),
            self.peer_tcp_port,
            self.addr,
            self.on_tcp_receive,
            self.loop,
        )

    def __process_session_init_tcp_message(self, pdu):
        """
        Handles all the TCP messages in the SESSION_INITIALISATION_STATE
        Args:
            pdu: message pdu extracted from tcp message including all dataitems

        """
        if pdu.type != MessageType.SESSION_INITIALISATION_RESPONSE_MESSAGE:
            return
        result = self.process_data_items_init(pdu.data_items)
        if result is None or result != StatusCode.SUCCESS:
            return
        self.process_data_items(pdu.data_items, self.peer_information_base)
        self.print_destination_information_base(peer=True)
        self.enter_in_session_state()

    def _send_destination_response(
        self, msg_type: MessageType, dib: DestinationInformationBase
    ):
        response_msg = MessagePdu(msg_type)
        if dib.link_identifier:
            response_msg.append_data_item(lid.LinkIdentifier(dib.link_identifier))
        else:
            response_msg.append_data_item(di.MacAddress(dib.mac_address))
        response_msg.append_data_item(di.Status(StatusCode.SUCCESS, "RX-OK"))
        self.tcp_proxy.send_msg(response_msg.to_buffer())

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
            self.recent_events.append(
                RecentEvent(
                    RecentEvent.TYPE_DEST_UP,
                    new_dib.mac_address,
                    new_dib.ipv4_address,
                )
            )
            self._send_destination_response(
                MessageType.DESTINATION_UP_RESPONSE_MESSAGE, new_dib
            )
            self.print_destination_information_base(peer=True)

        elif pdu.type == MessageType.DESTINATION_DOWN_MESSAGE:
            log.debug("--> got destination down message")
            dib_to_remove = DestinationInformationBase()
            self.process_data_items(pdu.data_items, dib_to_remove)
            self.recent_events.append(
                RecentEvent(
                    RecentEvent.TYPE_DEST_DOWN,
                    dib_to_remove.mac_address,
                    dib_to_remove.ipv4_address,
                )
            )

            list_filter = filter(
                lambda x: dib_to_remove.mac_address.lower() == x.mac_address.lower(),
                self.destination_information_base,
            )
            entries_to_remove = list(list_filter)
            for x in entries_to_remove:
                self.destination_information_base.remove(x)

            self._send_destination_response(
                MessageType.DESTINATION_DOWN_RESPONSE_MESSAGE, dib_to_remove
            )
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
        pdu = SignalPdu.from_buffer(message)
        log.debug("EXTRACTED signal PDU type {} len {}".format(pdu.type, pdu.len))

        if self.state == DlepSessionState.PEER_DISCOVERY_STATE:
            if pdu.type == SignalType.PEER_OFFER_SIGNAL:
                self.process_data_items(pdu.data_items, self.peer_information_base)
                asyncio.ensure_future(self.enter_session_initialisation_state())

    def _assemble_dlep_message(self, buffer: bytes) -> Optional[MessagePdu]:
        self._msg_buffer += buffer
        if len(self._msg_buffer) < MessageHeader.SIZE:
            return None
        header = MessageHeader.from_buffer(self._msg_buffer[:MessageHeader.SIZE])
        msg_size = MessageHeader.SIZE + header.len
        if len(self._msg_buffer) < msg_size:
            return None
        msg = MessagePdu.from_buffer(self._msg_buffer[:msg_size])
        self._msg_buffer = self._msg_buffer[msg_size:]
        return msg

    def on_tcp_receive(self, message):
        """
        Callback function for asyncio tcp receiver.
        Handles the incoming messages according to the DLEP state machine
        Args:
            message: The message received over TCP
        """
        self.reset_heartbeat_watchdog()
        log.debug("received something with len {}".format(len(message)))

        pdus = []
        pdu = self._assemble_dlep_message(message)
        while pdu is not None:
            log.debug("EXTRACTED message PDU type {} len {}".format(pdu.type, pdu.len))
            pdus.append(pdu)
            pdu = self._assemble_dlep_message(b"")

        for pdu in pdus:
            if self.state == DlepSessionState.SESSION_INITIALISATION_STATE:
                self.__process_session_init_tcp_message(pdu)

            elif self.state == DlepSessionState.IN_SESSION_STATE:
                self.__process_in_session_tcp_message(pdu)

            elif self.state == DlepSessionState.SESSION_TERMINATION_STATE:
                self.__process_session_termination_tcp_message(pdu)

    def start_heartbeat_timer(self):
        # TODO: This should be peer_heartbeat
        timeout = (self.own_heartbeat_interval / 1000) + 2
        self.heartbeat_timer = HeartbeatTimer(timeout, self.heartbeat_callback)
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
        self.tcp_proxy.send_msg(heartbeat_pdu.to_buffer())

    def start_watchdog_timer(self):
        timeout = (self.own_heartbeat_interval / 1000) + 2
        self.heartbeat_watchdog = HeartbeatTimer(timeout, self.watchdog_callback)
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
        log.critical(
            "!!! missed a heartbeat "
            "nr {} from peer !!!".format(self.missed_heartbeats)
        )

        if (self.state == DlepSessionState.IN_SESSION_STATE) and (
            self.missed_heartbeats > 3
        ):
            self.enter_session_termination_state()
        if (self.state == DlepSessionState.SESSION_TERMINATION_STATE) and (
            self.missed_heartbeats > 4
        ):
            self.session_reset()

    def process_data_items(
        self, item_array, information_base: DestinationInformationBase
    ):
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
                information_base.mac_address = item.addr
            elif item.type == DataItemType.IPV4_ADDRESS:
                information_base.ipv4_address = item.ipaddr
            elif isinstance(item, di.IPv4AttachedSubnet):
                information_base.ipv4_attached_subnets.append(item.subnet)
            elif item.type == DataItemType.LOSS_RATE:
                information_base.loss = item.loss
            elif isinstance(item, lid.LinkIdentifier):
                information_base.link_identifier = item.lid

    def process_data_items_init(self, item_array) -> Optional[StatusCode]:
        items = {item.type: item for item in item_array}
        try:
            item = items[DataItemType.HEARTBEAT_INTERVAL]  # type: di.HeartbeatInterval
            self.peer_heartbeat = item.heartbeatInterval
            item = items[DataItemType.STATUS]  # type: di.Status
            status = item.status_code
        except KeyError:
            return None
        if DataItemType.EXTENSIONS_SUPPORTED in items:
            item = items[
                DataItemType.EXTENSIONS_SUPPORTED
            ]  # type: di.ExtensionsSupported
            if ExtensionType.LINK_IDENTIFIER in item.ext_list:
                self.enabled_extensions.add(ExtensionType.LINK_IDENTIFIER)
        return status

    async def enter_session_initialisation_state(self):
        log.debug("entering SESSION_INITIALISATION_STATE...")
        self.state = DlepSessionState.SESSION_INITIALISATION_STATE

        if self.tcp_proxy is None:
            self.tcp_proxy = TCPProxy(
                str(self.peer_information_base.ipv4_address),
                self.peer_tcp_port,
                self.addr,
                self.on_tcp_receive,
                self.loop,
            )
            await self.tcp_proxy.start()

        session_init_message = MessagePdu(MessageType.SESSION_INITIALISATION_MESSAGE)
        session_init_message.append_data_item(
            di.HeartbeatInterval(self.own_heartbeat_interval)
        )
        session_init_message.append_data_item(di.PeerType("servus"))
        if self.conf.enable_lid_ext:
            item = di.ExtensionsSupported([ExtensionType.LINK_IDENTIFIER])
            session_init_message.append_data_item(item)

        tcp_conf = self.conf.tcp[self.addr]
        if "ipv4subnets" in tcp_conf:
            for entry in tcp_conf["ipv4subnets"]:
                session_init_message.append_data_item(
                    di.IPv4AttachedSubnet(ipaddress.IPv4Network(entry))
                )

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

        session_termination_message = MessagePdu(
            MessageType.SESSION_TERMINATION_MESSAGE
        )
        session_termination_message.append_data_item(
            di.Status(StatusCode.TIMED_OUT, "missed Heartbeats!")
        )

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
            log.info("Local Address     - {}".format(self.addr))
            log.info(
                "Remote Address    - {}".format(self.peer_information_base.ipv4_address)
            )
            log.info("Port              - {}".format(self.peer_tcp_port))
            log.info("Heartbeat         - {}".format(self.peer_heartbeat))
            log.info(
                "Max. data rate RX - {}".format(
                    self.peer_information_base.max_datarate_rx
                )
            )
            log.info(
                "Max. data rate TX - {}".format(
                    self.peer_information_base.max_datarate_tx
                )
            )
            log.info(
                "Cur. data rate RX - {}".format(
                    self.peer_information_base.curr_datarate_rx
                )
            )
            log.info(
                "Cur. data rate TX - {}".format(
                    self.peer_information_base.curr_datarate_tx
                )
            )
            log.info("Latency          - {}".format(self.peer_information_base.latency))

        log.info("===========================================================")
        log.info("========== Current Destination Information Base ===========")
        log.info("===========================================================")
        for dest in self.destination_information_base:
            log.info("--------------------------------------------------------")
            if dest.link_identifier:
                log.info("Link Identifier   - {}".format(dest.link_identifier.hex()))
            else:
                log.info("MAC Address       - {}".format(dest.mac_address))
            log.info("IPv4 Address      - {}".format(dest.ipv4_address))
            log.info(
                "IPv4 Subnets      - {}".format(
                    [str(x) for x in dest.ipv4_attached_subnets]
                )
            )
            log.info("Max. data rate RX - {}".format(dest.max_datarate_rx))
            log.info("Max. data rate TX - {}".format(dest.max_datarate_tx))
            log.info("Cur. data rate RX - {}".format(dest.curr_datarate_rx))
            log.info("Cur. data rate TX - {}".format(dest.curr_datarate_tx))
            log.info("Loss Rate         - {}".format(dest.loss))

        # TODO: Move to TCP callback
        if self.update_callback is not None:
            self.update_callback(self)

    def get_information_json_string(self):
        json_data = dict()
        json_data["events"] = []
        json_data["destinations"] = []
        json_data["peer"] = {
            "tcp_port": self.peer_tcp_port,
            "heartbeat_interval": self.peer_heartbeat,
            "peer_type": self.peer_tcp_port,
            "ipv4-address": str(self.peer_information_base.ipv4_address),
            "ipv4-attached-subnets": [
                str(x) for x in self.peer_information_base.ipv4_attached_subnets
            ],
            "max_datarate_rx": self.peer_information_base.max_datarate_rx,
            "max_datarate_tx": self.peer_information_base.max_datarate_tx,
            "cur_datarate_rx": self.peer_information_base.curr_datarate_rx,
            "cur_datarate_tx": self.peer_information_base.curr_datarate_tx,
            "latency": self.peer_information_base.latency,
        }
        for dest in self.destination_information_base:
            destination_data = {
                "mac-address": dest.mac_address,
                "link-identifier": dest.link_identifier.hex(),
                "ipv4-address": str(dest.ipv4_address),
                "ipv4-attached-subnet": [str(x) for x in dest.ipv4_attached_subnets],
                "max_datarate_rx": dest.max_datarate_rx,
                "max_datarate_tx": dest.max_datarate_tx,
                "cur_datarate_rx": dest.curr_datarate_rx,
                "cur_datarate_tx": dest.curr_datarate_tx,
                "loss": dest.loss,
            }
            json_data["destinations"].append(destination_data)

        for event in self.recent_events:
            ev_data = {
                "event-type": event.type,
                "mac-addr": event.node_mac_addr,
                "ipv4-addr": str(event.ipv4_addr),
            }
            json_data["events"].append(ev_data)

        self.recent_events.clear()
        json_str = json.dumps(json_data)
        return json_str

    async def start(self):
        if self.udp_proxy is not None:
            await self.udp_proxy.start()
        elif self.tcp_proxy is not None:
            await self.tcp_proxy.start()
        self.running = True
        log.debug("dlep-router is running")
        if self.udp_proxy is not None:
            asyncio.ensure_future(self.discovery())
        elif self.tcp_proxy is not None:
            asyncio.ensure_future(self.enter_session_initialisation_state())

    async def discovery(self):
        while self.running and self.state == DlepSessionState.PEER_DISCOVERY_STATE:
            # sending the peer discovery messages
            discovery_pdu = SignalPdu(SignalType.PEER_DISCOVERY_SIGNAL)
            pdu = discovery_pdu.to_buffer()

            log.info("sending discovery signal of len {}".format(len(pdu)))
            self.udp_proxy.send_msg(pdu)

            # Wait 60 seconds to send next Peer Discovery signal
            await asyncio.sleep(10)
