# SPDX-License-Identifier: MIT

import asyncio
import os
import socket
import struct


class UDPProxy(asyncio.DatagramProtocol):  # cli.Observer):
    def __init__(self, ipv4adr, port, interface, receive_handler, loop=None, multicast=False):
        # The event loop
        if loop is None:
            self.loop = asyncio.get_event_loop()
        else:
            self.loop = loop
        self.running = False
        self.mcast_ipaddr = ipv4adr
        self.port = port
        self.interface = interface
        self.dir = os.path.dirname(os.path.abspath(__file__))

        self.transport = None

        self.receive_handler = receive_handler

        if multicast:
            # Create multicast socket
            self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
            if hasattr(socket, 'SO_REUSEADDR'):
                self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            # no idea why its 25
            self.sock.setsockopt(socket.SOL_SOCKET, 25, self.interface.encode('utf-8'))
            self.sock.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_LOOP, 0)
            print('socket listens to port {}'.format(self.port))
            self.sock.bind(('', self.port))
            mreq = struct.pack("=4sl", socket.inet_aton(self.mcast_ipaddr), socket.INADDR_ANY)
            self.sock.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, 1)
            self.sock.setsockopt(socket.IPPROTO_IP, socket.IP_ADD_MEMBERSHIP, mreq)
        else:
            self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

    async def start(self):
        coro = self.loop.create_datagram_endpoint(lambda: self, sock=self.sock)
        await asyncio.wait_for(coro, 5)

    def send_msg(self, message):
        self.transport.sendto(message, (self.mcast_ipaddr, self.port))

    def connection_made(self, transport):
        self.transport = transport
        # print('Connection is made:'

    def datagram_received(self, message, addr):
        self.receive_handler(message, addr)

    def error_received(self, exc):
        print('Error received:', exc)

    def connection_lost(self, exc):
        print("Socket closed, stop the event loop")
        loop = asyncio.get_event_loop()
        loop.stop()
