import asyncio


class TCPProxy(asyncio.Protocol):
    def __init__(self, ipv4adr, port, interface, receive_handler, loop=None):
        if loop is None:
            self.loop = asyncio.get_event_loop()
        else:
            self.loop = loop

        self.running = False
        self.ip_addr = ipv4adr
        self.port = port
        self.interface = interface
        self.transport = None
        self.receive_handler = receive_handler

    def connection_made(self, transport):
        self.transport = transport

    def data_received(self, data: bytes):
        self.receive_handler(data)

    async def start(self):
        coro = self.loop.create_connection(self, self.ip_addr, self.port)
        await asyncio.wait_for(coro, 5)
