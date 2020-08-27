import socket, ssl
import struct

from modbus_tk import LOGGER
from modbus_tk.hooks import call_hooks
from modbus_tk import modbus_tcp
from modbus_tk.utils import flush_socket, to_data
from modbus_tk.modbus import Master

class TcpMaster(Master):
    """Subclass of Master. Implements the Modbus TCP MAC layer"""

    def __init__(self, host="127.0.0.1", port=502, timeout_in_sec=5.0):
        """Constructor. Set the communication settings"""
        super(TcpMaster, self).__init__(timeout_in_sec)
        self._host = host
        self._port = port
        self._sock = None

    def _do_open(self):
        """Connect to the Modbus slave"""
        if self._sock:
            self._sock.close()
        
        context = ssl.SSLContext(ssl.PROTOCOL_TLS)
        # load certificate file
        context.load_verify_locations("./certificate.pem")
        # prohibit the use of TLSv1.0, TLSv1.1, TLSv1.2 -> use TLSv1.3
        context.options |= (ssl.OP_NO_TLSv1 | ssl.OP_NO_TLSv1_1 | ssl.OP_NO_TLSv1_2)
        # open socket and connect TBAS
        with context.wrap_socket(socket.socket(socket.AF_INET, socket.SOCK_STREAM)) as self._sock:
            self._sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.set_timeout(self.get_timeout())
            self._sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            call_hooks("modbus_tcp.TcpMaster.before_connect", (self, ))
            self._sock.connect((self._host, self._port))
            call_hooks("modbus_tcp.TcpMaster.after_connect", (self, ))

        # if self._sock:
        #     self._sock.close()
        # self._sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        # self.set_timeout(self.get_timeout())
        # self._sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        # call_hooks("modbus_tcp.TcpMaster.before_connect", (self, ))
        # self._sock.connect((self._host, self._port))
        # call_hooks("modbus_tcp.TcpMaster.after_connect", (self, ))

    def _do_close(self):
        """Close the connection with the Modbus Slave"""
        if self._sock:
            call_hooks("modbus_tcp.TcpMaster.before_close", (self, ))
            self._sock.close()
            call_hooks("modbus_tcp.TcpMaster.after_close", (self, ))
            self._sock = None
            return True

    def set_timeout(self, timeout_in_sec):
        """Change the timeout value"""
        super(TcpMaster, self).set_timeout(timeout_in_sec)
        if self._sock:
            self._sock.setblocking(timeout_in_sec > 0)
            if timeout_in_sec:
                self._sock.settimeout(timeout_in_sec)

    def _send(self, request):
        """Send request to the slave"""
        retval = call_hooks("modbus_tcp.TcpMaster.before_send", (self, request))
        if retval is not None:
            request = retval
        try:
            flush_socket(self._sock, 3)
        except Exception as msg:
            #if we can't flush the socket successfully: a disconnection may happened
            #try to reconnect
            LOGGER.error('Error while flushing the socket: {0}'.format(msg))
            self._do_open()
        self._sock.send(request)

    def _recv(self, expected_length=-1):
        """
        Receive the response from the slave
        Do not take expected_length into account because the length of the response is
        written in the mbap. Used for RTU only
        """
        response = to_data('')
        length = 255
        while len(response) < length:
            rcv_byte = self._sock.recv(1)
            if rcv_byte:
                response += rcv_byte
                if len(response) == 6:
                    to_be_recv_length = struct.unpack(">HHH", response)[2]
                    length = to_be_recv_length + 6
            else:
                break
        retval = call_hooks("modbus_tcp.TcpMaster.after_recv", (self, response))
        if retval is not None:
            return retval
        return response

    def _make_query(self):
        """Returns an instance of a Query subclass implementing the modbus TCP protocol"""
        return modbus_tcp.TcpQuery()
