# SPDX-License-Identifier: MIT

import aiohttp
import argparse
import asyncio
import os
from aiohttp import web

path = os.path.dirname(os.path.realpath(__file__))


class UpdateHandler(object):
    def __init__(self):
        self.ws = []
        self.jsonData = None
        self.dataUpdateFlag = asyncio.Condition()

    async def start_update(self):
        """
        Main routine for dynamic update of the webview
        Waiting until new data is available from REST-api and
        pushing to website via websocket, if websocket is available
        """
        print('starting the update')

        while not self.ws.closed:
            await self.dataUpdateFlag.acquire()
            await self.dataUpdateFlag.wait()
            self.dataUpdateFlag.release()
            if self.jsonData is not None:
                try:
                    print('sending update')
                    ret = self.ws.send_json(self.jsonData)
                    if ret:
                        await ret
                except RuntimeError:
                    return
        print('obviously the websocket is closed')

    async def handle_api(self, request):
        """
        Method for handling the REST-API.
        Saves json data in member variable, then
        notifies the webview-updater
        :param request: contains the json data
        :return: response object
        """
        print('got sth from api')
        self.jsonData = await request.json()
        await self.dataUpdateFlag.acquire()
        self.dataUpdateFlag.notify_all()
        self.dataUpdateFlag.release()
        print('jsonData: {}'.format(self.jsonData))
        return aiohttp.web.Response()

    async def handle_websocket(self, request):
        """
        Method for handling the websocket.
        Extracts websocket information from response and
        saves it into member.
        If Websocket sends the 'ready-for-update' string,
        the method starts the update routine (start_update())
        :param request: contains the message from websocket
        :return: websocket Response
        """
        print('got sth from websocket')
        self.ws = web.WebSocketResponse()
        await self.ws.prepare(request)

        async for msg in self.ws:
            if msg.type == aiohttp.WSMsgType.TEXT:
                if msg.data == 'close':
                    await self.ws.close()
                elif msg.data == 'ready-for-update':
                    asyncio.ensure_future(self.start_update())
            elif msg.type == aiohttp.WSMsgType.ERROR or\
                    msg.type == aiohttp.WSMsgType.CLOSING or\
                    msg.type == aiohttp.WSMsgType.CLOSE or\
                    msg.type == aiohttp.WSMsgType.closed:
                await self.ws.close()
                print("websocket closed")

        return self.ws


async def handle_website(request):
    """
    Method for handling the http request.
    Displays the website (html)
    :param request: ignored
    :return: html response (the Website)
    """
    print('new http request')
    with open('{}/dlep_information_view.html'.format(path), 'r') as content_file:
        content = str.encode(content_file.read())
        return web.Response(body=content, content_type='text/html')


def parse_args():
    parser = argparse.ArgumentParser("dlep_infoview")
    parser.add_argument('-p', "--port", help="Port", type=str, default='8080')
    args = parser.parse_args()
    return args


def main():
    args = parse_args()
    handler = UpdateHandler()
    app = web.Application()
    app.add_routes([web.get('/', handle_website)])
    app.add_routes([web.get('/ws', handler.handle_websocket),
                    web.post('/ws', handler.handle_websocket)]),
    app.add_routes([web.get('/api/v1/dlep-update', handler.handle_api),
                    web.post('/api/v1/dlep-update', handler.handle_api)])
    app.router.add_static('/assets', '{}/assets'.format(path), show_index=False)

    web.run_app(app, host='localhost', port=args.port)


if __name__ == '__main__':
    main()
