# DLEP-Router

This repository contains the implementation for the DLEP protocol according to
[RFC 8175](https://datatracker.ietf.org/doc/rfc8175/).

## Usage and Configuration

The application can be started with the following command:

```
python3 -m dlepard dlep-router-conf.json
```

The configuration file (e.g. `dlep-router-conf.json`) contains the following
information:

- `local_ipv4addr`: List of IP addresses to bind to.  Each address represents a
  router instance.
- `discovery`
  - `ipv4addr`: The service's multicast IPv4 address.
    According to *RFC 8175*, this should be `224.0.0.117`.
  - `port` (optional): The service's port number.  
    Default is `854` (see *RFC 8175*).
  - `disabled` (optional): Whether to deactivate the discovery mechanism and
    start with the session initialization.  
    Default is `false`.
- `tcp` (optional): A dictionary containing TCP connection configurations.
  This is only necessary if discovery is disabled.
  - *Key*: One of the addresses from `local_ipv4addr`.
    - `ipv4addr`: The modem's IP address.
    - `port`: The service's TCP port number.
- `enable_lid_ext`: Wheteher to enable the Link Identifier extension.
- `rest_if`
  - `broadcast_url`: The URLs to all REST APIs that require the DLEP information
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
        "heartbeat_interval": 10000,
        "peer_type": 32222,
        "ipv4-address": "192.1.1.102",
        "ipv4-attached-subnets": "192.1.1.0/24",
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
            "ipv4-attached-subnets": "192.1.1.0/24",
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

The *DLEP Information Viewer* is a web server that provides a simple web GUI to
view the current database from DLEP-Router. The web server provides a REST API
that the DLEP plugin can use to publish its information.

The web GUI can be and accessed via <http://localhost:8080/> and should work
with any web browser.

The application can be started with the following command:

```
python3 -m dlep_infoview -p 8080
```

## Changelog

### Unreleased

### 1.1.0 (2020-12-08)

- Use explicit IP addresses instead of network interface names
  + *UDPProxy* works on Windows 10
- Discovery mechanism can be disabled
- Let the operating system choose the source port for signals and messages
  + No need for *sudo* any more
- The session module can reassemble packets from the TCP buffer

### 1.0.0 (2020-11-12)

- Initial stable version
- Supports UDP discovery and TCP session messages
- Supports the following Data Items from RFC 8175:
  + Status
  + IPv4 Connection Point
  + Heartbeat Interval
  + MAC Address
  + IPv4 Address
  + Maximum Data Rate (Receive)
  + Maximum Data Rate (Transmit)
  + Current Data Rate (Receive)
  + Current Data Rate (Transmit)
  + Latency

## Contribution

- Please follow the [PEP8](https://www.python.org/dev/peps/pep-0008/) Coding
  Guidelines.
- All contributors are obliged to follow our
  [Code of Conduct](https://github.com/Rohde-Schwarz/rohde-schwarz/blob/master/code-of-conduct.md).

## License

Copyright (c) Rohde & Schwarz GmbH. & Co. KG. All rights reserved.

The software is licensed under MIT [License](./LICENSE).

