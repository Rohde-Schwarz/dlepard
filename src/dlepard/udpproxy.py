# SPDX-License-Identifier: MIT

import asyncio
import logging
import os
import socket
import struct

log = logging.getLogger("DLEPard")


class UDPProxy(asyncio.DatagramProtocol):  # cli.Observer):
    """
    Handles the UDP connection using asyncio DatagramProtocol and provides
    a simple interface to send and receive data.

    UDPProxy can handle multicast as well as unicast sockets
    """

    def __init__(
        self, ipv4adr, port, addr, receive_handler, loop=None, multicast=False
    ):
        """
        Create a new instance of UDPProxy
        Args:
            ipv4adr: the IPv4 address you want to communicate with
            port: the UDP port for the socket
            interface: name of the OS interface name (e.g. enp1s0)
            receive_handler: this function will be called when a new message
                             is received
            loop: asyncio main loop
            multicast: True if multicast socket, False if unicast socket
        """
        # The event loop
        if loop is None:
            self.loop = asyncio.get_event_loop()
        else:
            self.loop = loop
        self.running = False
        self.mcast_ipaddr = ipv4adr
        self.port = port
        self.addr = addr
        self.dir = os.path.dirname(os.path.abspath(__file__))

        self.transport = None

        self.receive_handler = receive_handler

        if multicast:
            # Create multicast socket
            self.sock = socket.socket(
                socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP
            )
            if hasattr(socket, "SO_REUSEADDR"):
                self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            if hasattr(socket, "SO_REUSEPORT"):
                self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT, 1)

            self.sock.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_LOOP, 0)
            print("socket listens at {}".format(self.addr))

            self.sock.bind((self.addr, 0))
            # no idea why its 25
            # value = self.interface.encode('utf-8')
            # self.sock.setsockopt(socket.SOL_SOCKET, 25, value)

            mreq = socket.inet_aton(ipv4adr)
            mreq += socket.inet_aton(self.addr)
            # mreq += struct.pack("@i", socket.if_nametoindex(self.addr))
            self.sock.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_LOOP, 0)
            self.sock.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, 1)
            self.sock.setsockopt(socket.IPPROTO_IP, socket.IP_ADD_MEMBERSHIP, mreq)

            value = socket.inet_aton(self.addr)
            self.sock.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_IF, value)
        else:
            # create unicast socket
            self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

    async def start(self):
        coro = self.loop.create_datagram_endpoint(lambda: self, sock=self.sock)
        await asyncio.wait_for(coro, 5)
        log.debug("Started UDP proxy")

    def send_msg(self, message):
        self.transport.sendto(message, (self.mcast_ipaddr, self.port))

    def connection_made(self, transport):
        self.transport = transport

    def datagram_received(self, data, addr):
        self.receive_handler(data, addr)

    def error_received(self, exc):
        print("Error received:", exc)

    def connection_lost(self, exc):
        print("Socket closed, stop the event loop")
        loop = asyncio.get_event_loop()
        loop.stop()
