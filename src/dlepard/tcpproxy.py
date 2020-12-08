import asyncio
import logging

log = logging.getLogger("DLEPard")


class TCPProxy(asyncio.Protocol):
    def __init__(self, ipv4adr, port, addr, receive_handler, loop=None):
        if loop is None:
            self.loop = asyncio.get_event_loop()
        else:
            self.loop = loop

        self.running = False
        self.ip_addr = ipv4adr
        self.port = port
        self.addr = addr
        self.transport = None  # type: asyncio.Transport
        self.receive_handler = receive_handler

    def connection_made(self, transport):
        self.transport = transport

    def data_received(self, data: bytes):
        self.receive_handler(data)

    def send_msg(self, message):
        self.transport.write(message)

    async def start(self):
        coro = self.loop.create_connection(
            lambda: self, host=self.ip_addr, port=self.port, local_addr=(self.addr, 0)
        )
        await asyncio.wait_for(coro, 5)
        log.debug("Started TCP proxy")
