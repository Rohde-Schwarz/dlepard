# DLEP-Router

This repository contains the implementation for the DLEP protocol according to
[RFC 8175](https://datatracker.ietf.org/doc/rfc8175/).

## Usage and Configuration

The application can be started with the following command:

```
sudo python3 ./dleprouter.py -f conf-enp3s0.json
```

The required command line arguments are:

- `-f`: path to the configuration file

The configuration file (e.g. `dlep-router-conf.json`) contains the following
information:

- `dlep`
  - `mcast-ip4addr`: The service's multicast IPv4 address.
    According to *RFC 8175* e.g.: `224.0.0.117`
  - `udp-port`: The service's port number. According to *RFC 8175* e.g.: `854`
- `router`
  - `interfaces`: A list of interfaces that should be handled as DLEP interfaces.
    This is a subset of all interfaces available at the router.
- `rest-if`
  - `broadcast-url`: The URLs to all REST APIs that require the DLEP information
    (e.g. the routing protocol or the *DLEP Info View*).

## TCP-Proxy

`TCPProxy` is a wrapper class that abstracts the TCP network access. It uses
asyncio's TCP sockets.

## UDP-Proxy

`UDPProxy` is a wrapper class that abstract the UDP network access. It uses
asyncio's Datagram sockets. `UDPProxy` is able to handle multicast communication
as well as unicast communication.

## REST API

This implementation provides a RESTful service. It uses a REST API to forward
the information that is gathered via the DLEP interface. Any application that
requires the link information provided by DLEP can use this interface.

The payload is formatted in JSON and structured as follows:

```json
{
    "peer": {
        "tcp_port": 32222,
        "interface": "eth0",
        "heartbeat_interval": 10000,
        "peer_type": 32222,
        "ipv4-address": "192.1.1.102",
        "max_datarate_rx": 40000,
        "max_datarate_tx": 40000,
        "cur_datarate_rx": 0,
        "cur_datarate_tx": 0,
        "latency": 1000000
    },
    "events": [
        {
            "event-type": "dest-up",
            "ipv4-addr": "192.1.1.104",
            "mac-addr": "00:00:00:00:00:04"
        },
        {
            "event-type": "dest-down",
            "ipv4-addr": "192.1.1.103",
            "mac-addr": "00:00:00:00:00:03"
        }
    ],
    "destinations": [
        {
            "mac-address": "00:00:00:00:00:04",
            "ipv4-address": "192.1.1.104",
            "max_datarate_rx": 40000,
            "max_datarate_tx": 40000,
            "cur_datarate_rx": 0,
            "cur_datarate_tx": 375,
            "loss": 5
        }
    ]
}
```

## DLEP Information Viewer

The *DLEP Information Viewer* is a webserver that provides a simple web GUI to
view the current database from DLEP-Router. The Webserver provides a REST API
that the DLEP plugin can use to publish its information.

The web GUI can be and accessed via <http://localhost:8080/> and should work
with any web browser.

## Contribution

- Please follow the [PEP8](https://www.python.org/dev/peps/pep-0008/) Coding
  Guidelines.
- All contributors are obliged to follow our
  [Code of Conduct](https://github.com/Rohde-Schwarz/rohde-schwarz/blob/master/code-of-conduct.md).

## License

Copyright (c) Rohde & Schwarz GmbH. & Co. KG. All rights reserved.

The software is licensed under MIT [License](./LICENSE).
