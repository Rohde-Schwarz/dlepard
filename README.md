# DLEP-Router

This repository contains the implementation for DLEP according to 
[RFC 8175](https://datatracker.ietf.org/doc/rfc8175/)

The application is started by the following command:
```
sudo python3 ./dleprouter.py -f dlep-router-conf.json
```
Required command line arguments:
- -f: path to the config.json file

### Config
dlep-router-conf.json is the configuration file that has to be specified at the 
startup. 
It contains following information:
- dlep
   - multicast ipv4 address (according to rfc8175: **_224.0.0.117_**)
   - udp-port (according to rfc8175: **_854_**)
- router
   - interfaces: list of the router's interfaces that should be handled as 
     DLEP interfaces.
- rest-if
   - broadcast-url: all URLs to the rest APIs that require the DLEP information
     (e.g. the Routing Protocol or the DLEPInfoView)

### TCP-Proxy
TCPProxy is a wrapper class to abstract the TCP network access. It uses the 
asyncio TCP-Socket.

### UDP-Proxy
UDPProxy is a wrapper class to abstract the UDP network access. It uses the 
asyncio Datagram-Socket. UDPProxy is able to handle multicast communication as well as
unicast communication.

### REST API
For forwarding the information that is gathered via the DLEP interface, this implementation
uses a REST API. This API can implemented by any application that requires the link information
provided by DLEP.
```
{
    'peer': {
        'tcp_port': 32222, 
        'interface': 'eth0', 
        'heartbeat_interval': 10000, 
        'peer_type': 32222, 
        'ipv4-address': '192.1.1.102', 
        'max_datarate_rx': 40000, 
        'max_datarate_tx': 40000, 
        'cur_datarate_rx': 0, 
        'cur_datarate_tx': 0, 
        'latency': 1000000
    },
    'events': [
        {
            'event-type': 'dest-up', 
            'ipv4-addr': '192.1.1.104', 
            'mac-addr': '00:00:00:00:00:04'
        },
        {
            'event-type': 'dest-down', 
            'ipv4-addr': '192.1.1.103', 
            'mac-addr': '00:00:00:00:00:03'
        }
    ], 
    'destinations': [
        {
            'mac-address': '00:00:00:00:00:04', 
            'ipv4-address': '192.1.1.104', 
            'max_datarate_rx': 40000, 
            'max_datarate_tx': 40000, 
            'cur_datarate_rx': 0, 
            'cur_datarate_tx': 375, 
            'loss': 5
        }
    ]
}
```

# DLEP Information Viewer
DLEP Information Viewer is a webserver that provides a simple WEB-GUI to view the 
current Database from DLEP Router.
The Webserver provides a REST-API where the DLEP plugin can push its information to.
The web GUI can be accessed by any webbrowser on http://localhost:8080/

# Contribution
- Please follow [PEP8](https://www.python.org/dev/peps/pep-0008/) Coding Guidlines.
- The [Code of Conduct](https://github.com/Rohde-Schwarz/rohde-schwarz/blob/master/code-of-conduct.md) 
has to be respected.

# License
Copyright (c) Rohde & Schwarz GmbH. & Co. KG. All rights reserved.

The software is licensed under MIT [License](./LICENSE)
