"use strict";

var ws_socket;

$(document).ready(function() {
    if (!("WebSocket" in window)){
        console.log("browser does not support web sockets");
        return;
    } else {
        initWebSockets();
    }
});

function wsOnMessage(event){
    var jdata = JSON.parse(event.data);
    if  ('peer' in jdata){
        processPeerData(jdata['peer']);
    }
    if ('destinations' in jdata){
        processDestinationData(jdata['destinations']);
    }
}

function wsOnOpen(event){
    ws_socket.send("ready-for-update");
}


function initWebSockets(){
    try {
        ws_socket = new WebSocket('ws://' + window.location.host + '/ws');
    }
    catch(err)
    {
        try {
            ws_socket = new WebSocket('wss://' + window.location.host + '/ws');
        }
        catch(exception){
            console.log('Error' + exception);
        }
    }

    ws_socket.onmessage = wsOnMessage;
    ws_socket.onopen = wsOnOpen;
}


function processPeerData(jsonData){
    console.log("process peer");
    let output = document.getElementById("peer-table");

    let str = '<table class="table table-sm table-hover"' + 
        '<tr><td><b>IPv4-address</b></td><td>' + jsonData['ipv4-address']+ '</td></tr>' +
        '<tr><td><b>TCP-Port</b></td><td>' + jsonData['tcp_port'] + '</td></tr>' +
        '<tr><td><b>Interface</b></td><td>' + jsonData['interface'] + '</td></tr>' +
        '<tr><td><b>Max. Datarate Tx</b></td><td>' + jsonData['max_datarate_tx'] + '</td></tr>' +
        '<tr><td><b>Max. Datarate Rx</b></td><td>' + jsonData['max_datarate_rx'] + '</td></tr>' +
        '<tr><td><b>Heartbeat Interval</b></td><td>' +jsonData['latency'] + '</td></tr>' +
        '</table>';

    output.innerHTML = str;
}
function processDestTableHeader(){
    return '<table class="table table-sm table-hover"' +
        '<thead><tr>' +
        '<th>MAC-Address</th>' +
        '<th>IPv4 Address</th>' +
        '<th>Max. Datarate RX</th>' +
        '<th>Max. Datarate TX</th>' +
        '<th>Latency</th>' +
        '</tr></thead><tbody>'
}

function processTableEntry(entry){
    return '<tr>' +
        '<td>' + entry['mac-address'] + '</td>' +
        '<td>' + entry['ipv4-address'] + '</td>' +
        '<td>' + entry['max_datarate_rx'] + '</td>' +
        '<td>' + entry['max_datarate_tx'] + '</td>' +
        '<td>' + entry['latency'] + '</td>' +
        '</tr>';
}

function processDestinationData(jsonData){
    console.log("process dest");
    let output = document.getElementById("destination-table");

    let str = processDestTableHeader();
    for (let entry of jsonData){
        str += processTableEntry(entry);
    }
    str += '</tbody></table>';
    output.innerHTML = str;
}
