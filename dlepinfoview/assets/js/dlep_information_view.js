"use strict";

var ws_socket;
var known_interfaces = [];
var first_interface_set = false;

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
    var interface_index = 0;
    if  ('peer' in jdata){
        interface_index = getInterfaceId(jdata['peer']['interface']);
        processPeerData(jdata['peer'], interface_index);
    }
    if ('destinations' in jdata){
        processDestinationData(jdata['destinations'], interface_index);
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


function createNewContentSection(index){
    console.log("creating new section");
    let output = document.getElementById("content");

    output.innerHTML +=
		'<hr />' +
		'<hr />' +
        '<div class="row">' +
		'<div class="col-6">' +
		'<div class="card border-light">' +
		'<h5 class="card-header">' +
		'Peer Information' +
		'</h5>' +
		'<div class="card-body">' +
		'<div id="peer-table-' + index + '">' +
		'<table class="table table-sm table-hover">' +
		'<tr><td><b>Currently no data available</b></td></tr>' +
		'</table>' +
		'</div>' +
		'</div>' +
		'</div>' +
		'</div> <!-- col -->' +
		'</div> <!-- row -->' +
		'<hr />' +
        '<div class="row">' +
        '<div class="col-12">' +
        '<div class="card border-light">' +
        '<h5 class="card-header">' +
        'Destinations' +
        '</h5>' +
        '<div class="card-body">' +
        '<div id="destination-table-' + index + '">' +
        '<table class="table table-sm table-hover">' +
        '<td>Currently no data available</td>' +
        '</table>' +
        '</div>' +
        '</div>' +
        '</div>' +
        '</div> <!-- col -->' +
        '</div> <!-- row -->';

}


function getInterfaceId(interface_name){
    var index = null;
    for (var i = 0; i < known_interfaces.length; i++){
        if (known_interfaces[i] == interface_name){
            index = i;
            break;
        }
    }
    if (index == null){
        if (first_interface_set){
            index = known_interfaces.length;
            known_interfaces.push(interface_name);
            createNewContentSection(index);
        }
        else{
            known_interfaces.push(interface_name);
            index = 0;
            first_interface_set = true;
        }
    }

    return index;
}


function processPeerData(jsonData, interface_index){
    console.log("process peer");

    let output = document.getElementById("peer-table-" + interface_index);

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

function processDestinationData(jsonData, interface_index){
    console.log("process dest");
    let output = document.getElementById("destination-table-" + interface_index);

    let str = processDestTableHeader();
    for (let entry of jsonData){
        str += processTableEntry(entry);
    }
    str += '</tbody></table>';
    output.innerHTML = str;
}
