from ._template import __fc_server__, __fc_thread__

try:
    from sc_data import *
    from sc_db import *
except ImportError:
    from ..sc_data import *
    from ..sc_db import *

import sys, socket


def stdout(data: str, __pr: str = '') -> int:
    return sys.stdout.write(f'[{__name__}{" " if len(__pr) else ""}{__pr}] {data}\n')


def stderr(data: str, __pr: str = '') -> int:
    return sys.stderr.write(f'[{__name__}{" " if len(__pr) else ""}{__pr}] {data}\n')


class LegacyServer(__fc_server__):
    def __init__(self, ip: str, *args, **kwargs) -> None:
        self.__t = __fc_thread__()
        self.__mcv__ = 0
        __fc_server__.__init__(self, (ip, Constants.TCP.L_PORT), self.__t, *args, **kwargs)

        # __connectors__:   Dict[str, Tuple[__fc_thread__, socket.socket, Tuple[str, int]]]
        # __sessions__:     Dict[str, Tuple[Tuple[str, rsa.PublicKey, rsa.PrivateKey], Any]]

    def run(self) -> None:
        self.bind()
        self.start_listener(Constants.TCP.BKLOG)

    def _on_capture_event_(self, c_name: str) -> None | str:
        """
        On Capture Event
        Uses sf_execute to call potentially unsafe/error-prone functions.

        :param c_name:      Connection ID
        :return:            None (normally) or "PASS" if c_name == None (test case)
        """

        if c_name is None:
            return 'PASS'

        new_conn_code = b'NW_CON'
        default_recv_len = 1024

        thread, conn, addr = self.__connectors__[c_name]

        recv = conn.recv(1024)

        if recv[:len(new_conn_code)] == new_conn_code:
            # Session to create a new connection.
            raise NotImplemented

        elif recv[:Constants.SZ.DATE].decode().isnumeric():
            # GET P DET request.
            raise NotImplemented

        else:
            # Invalid request
            # Note that HTTP requests should be handled w/ _reply_to_http

            d, r = self.sf_execute(self._reply_to_http, _rcv=recv, _conn=conn, _addr=addr)

            if not d:
                stderr(r, f'SERVER<%s, %d> @_reply_to_http' % self.__net__)

