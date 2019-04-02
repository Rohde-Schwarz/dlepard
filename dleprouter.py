# SPDX-License-Identifier: MIT

import asyncio
import json
import sys
import argparse
import urllib.error
import urllib.request
import logging

from dlepsession import DLEPSession

log = logging.getLogger("myLog")
log.addHandler(logging.StreamHandler(sys.stdout))
log.setLevel(logging.DEBUG)

PROG_NAME = "DLEP_ROUTER"


def dlep_router_init(ctx, loop, interfaces):
    ctx['loop'] = loop
    sessions = []
    for intf in interfaces:
        session = DLEPSession(ctx['conf'],
                              intf,
                              loop=loop,
                              update_callback=update_webview)
        log.debug("run dlep-router for if {}".format(intf))
        loop.run_until_complete(session.start())
        sessions.append(session)

    return sessions


def main(ctx):
    loop = asyncio.get_event_loop()
    loop.set_debug(True)
    interfaces = ctx['conf']['router']['interfaces']
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
    parser.add_argument("-f", "--configuration", help="configuration",
                        type=str, default=None)
    parser.add_argument("-v", "--verbose", help="verbose", action='store_true',
                        default=False)
    args = parser.parse_args()
    if not args.configuration:
        emsg = "Configuration required, please specify a valid file path, " \
               "exiting now\n"
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
    req.add_header('User-Agent', 'Mozilla/5.0 (compatible; Chrome/22.0.1229.94;'
                                 ' Windows NT)')
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
