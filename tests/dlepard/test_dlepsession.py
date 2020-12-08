from unittest import mock

from rsb_dlep.data_items.core import HeartbeatInterval, Latency
from rsb_dlep.message import MessagePdu, MessageType

from dlepard import DLEPSession, DlepSessionState

A_NUMBER = 42


def test_assemble_message2(mocker):
    msg1 = MessagePdu(MessageType.SESSION_INITIALISATION_RESPONSE_MESSAGE)
    msg1.append_data_item(HeartbeatInterval(A_NUMBER))
    msg2 = MessagePdu(MessageType.DESTINATION_UP_MESSAGE)
    msg2.append_data_item(Latency(A_NUMBER))
    buffer = msg1.to_buffer() + msg2.to_buffer() + b"foo"
    conf = {"local_ipv4addr": [], "discovery": None}

    mocker.patch.object(DLEPSession, "_process_in_session_tcp_message")

    session = DLEPSession(conf, "")
    session.state = DlepSessionState.IN_SESSION_STATE
    session.on_tcp_receive(buffer)

    mock_obj = session._process_in_session_tcp_message  # type: mock.MagicMock
    assert mock_obj.call_count == 2
    calls = mock_obj.call_args_list
    assert calls[0][0][0].to_buffer() == msg1.to_buffer()
    assert calls[1][0][0].to_buffer() == msg2.to_buffer()
    assert len(session._msg_buffer) == len(b"foo")
