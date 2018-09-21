import json
import urllib.error
import urllib.request


json_data = dict()
json_data['destinations'] = [
    {
        'mac-address': 'MYMAC',
        'ipv4-address': 'IPV4',
        'max_datarate_rx': 'MAX_DATA_RX',
        'max_datarate_tx': 'MAX_DATA_TX',
        'cur_datarate_rx': 'CUR_DATA+RX',
        'cur_datarate_tx': 'cur_data_tx',
        'latency': 'anylatency'
    }
]
json_data['peer'] = {
    'tcp_port': 'self.peerTcpPort',
    'heartbeat_interval': 'self.peerHeartbeat',
    'interface': 'eth1',
    'peer_type': 'self.peerTcpPort',
    'ipv4-address': 'self.peerInformationBase.ipv4Address',
    'max_datarate_rx': 'self.peerInformationBase.maxDatarateRx',
    'max_datarate_tx': 'self.peerInformationBase.maxDatarateTx',
    'cur_datarate_rx': 'self.peerInformationBase.currDatarateRx',
    'cur_datarate_tx': 'self.peerInformationBase.currDatarateTx',
    'latency': 'self.peerInformationBase.latency'
}

proxy_support = urllib.request.ProxyHandler({})
opener = urllib.request.build_opener(proxy_support)
urllib.request.install_opener(opener)
url = "http://localhost:8080/api/v1/dlep-update"
req = urllib.request.Request(url)
req.add_header('Content-Type', 'application/json')
req.add_header('Accept', 'application/json')
req.add_header('User-Agent',
               'Mozilla/5.0 (compatible; Chrome/22.0.1229.94; Windows NT)')
jsonstring = json.dumps(json_data)
jsonstring_bytes = jsonstring.encode('utf-8')
req.add_header('Content-Length', len(jsonstring_bytes))
try:
    response = urllib.request.urlopen(req, jsonstring_bytes, timeout=3)
except urllib.error.URLError as e:
    print(e.reason)

