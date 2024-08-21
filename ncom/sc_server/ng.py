from ._template import __fc_server__, __fc_thread__

try:
    from sc_data import *
    from sc_db import *
except ImportError:
    from ..sc_data import *
    from ..sc_db import *

import sys, rsa, hashlib, json
from typing import cast, Tuple
from time import sleep


def stdout(data: str, __pr: str = '') -> int:
    return sys.stdout.write(f'[{__name__}{" " if len(__pr) else ""}{__pr}] {data}\n')


def stderr(data: str, __pr: str = '') -> int:
    return sys.stderr.write(f'[{__name__}{" " if len(__pr) else ""}{__pr}] {data}\n')


class NGServer(__fc_server__):
    def __init__(self, ip: str, pt_db: PTDatabase, user_db: UserDatabase, *args, **kwargs) -> None:
        self.__t = __fc_thread__()
        self.__mcv__ = 20240814000000
        __fc_server__.__init__(self, (ip, Constants.TCP.PORT), self.__t, *args, **kwargs)
        self.__pt_db__ = pt_db
        self.__u_db__ = user_db

        # __connectors__:   Dict[str, Tuple[__fc_thread__, socket.socket, Tuple[str, int]]]
        # __sessions__:     Dict[str, Dict[str, Any]]

    def run(self) -> None:
        self.bind()
        self.start_listener(Constants.TCP.BKLOG)

    def _log_as_client(self, addr: Tuple[str, int], st: str | None, message: str) -> int:
        if st is None:
            return stdout(f'<%s, %d> {message}' % addr, 'SERVER<%s, %d>' % self.__net__)
        else:
            return stdout(f'<%s, %d :: ST %s> {message}' % (*addr, st), 'SERVER<%s, %d>' % self.__net__)

    def _err_as_client(self, addr: Tuple[str, int], st: str | None, message: str):
        if st is None:
            return stderr(f'<%s, %d> {message}' % addr, 'SERVER<%s, %d>' % self.__net__)
        else:
            return stderr(f'<%s, %d :: ST %s> {message}' % (*addr, st), 'SERVER<%s, %d>' % self.__net__)

    def _get_ng_header(self, recv: bytes) -> Header.NGHeader:
        recv = recv.strip()
        assert len(recv) >= Header.NGHeaderItems.header_length()

        rx_hdr = recv[:Header.NGHeaderItems.header_length()]
        return Header.HeaderUtils.load_ng_header(rx_hdr)

    def _detect_header(self, recv: bytes, addr: Tuple[str, int]) -> bool:
        # NG Headers do not contain any whitespace; remove it all.
        recv = recv.replace(b' ', b'').replace(b'\t', b'').replace(b'\n', b'').replace(b'\r', b'')

        if len(recv) < Header.NGHeaderItems.header_length():
            return False

        tests = (
            [Header.NGHeaderItems.MSGINTENT, lambda x: x in (b'C', b'S')],
            [Header.NGHeaderItems.H_APP_VIS, lambda x: cast(bytes, x).decode().isnumeric()],
            [Header.NGHeaderItems.H_MC_TYPE, lambda x: cast(bytes, x) in (b'0', b'1')],
            [Header.NGHeaderItems.H_TX_TIME, lambda x: cast(bytes, x).decode().isnumeric()],
        )

        results = [1 if t(recv[T.INDEX:T.INDEX+T.SIZE:]) else 0 for T, t in tests]
        s = sum(results) == len(tests)

        self._log_as_client(addr, None, f'Exec _DH tests ({"PASS" if s else "FAIL"}) w/ res={results}')
        return s

    def _new_conn(self, c_name: str, hdr: Header.NGHeader, recv: bytes) -> None:
        # TODO: Log transmissions.
        assert False, Constants.RESPONSES.ERRORS.GENERAL

    def _con_conn(self, c_name: str, hdr: Header.NGHeader, recv: bytes) -> None:
        # TODO: Log transmissions.
        assert False, Constants.RESPONSES.ERRORS.GENERAL

    def _on_capture_event_(self, c_name: str) -> None | str:
        """
        On Capture Event (LEGACY server)
        Uses sf_execute to call potentially unsafe/error-prone functions.

        :param c_name:      Connection ID
        :return:            None (normally) or "PASS" if c_name == None (test case)
        """

        if c_name is None:
            return 'PASS'

        default_recv_len = AppInfo.APPINFO.SRVC_TCP_DEFAULT_RCV_LEN if \
            (AppInfo.APPINFO.SRVC_TCP_DEFAULT_RCV_LEN >= Header.NGHeaderItems.header_length()) \
            else Header.NGHeaderItems.header_length()

        thread, conn, addr = self.__connectors__[c_name]
        recv = conn.recv(default_recv_len)

        # All communications must have the NG header.
        # If not, call _reply_to_http (the method will detect HTTP requests and respond appropriately).

        # Check if the bytes can possibly be an NG header;
        pos_ng_hdr = self._detect_header(recv, addr)

        if not pos_ng_hdr:
            if not self._reply_to_http(recv, conn, addr):
                self._err_as_client(addr, None, 'Unknown communication protocol [1].')
                # _reply_to_http already sent an error code to the client.

            thread.done()
            return

        *_, hdr = self.sf_execute(self._get_ng_header, recv, sfe_echo_tb=True)  # DO echo errors

        if not isinstance(hdr, Header.NGHeader):
            conn.send(Constants.RESPONSES.ERRORS.BAD_HEADER.encode())
            self._err_as_client(addr, None, 'Unknown communication protocol [2].')

        else:
            self._log_as_client(addr, hdr.H_SES_TOK, 'Received a valid NG header.')

            if hdr.MSGINTENT == 'C':
                s1, d1 = self.sf_execute(self._con_conn, c_name, hdr, recv)

            else:
                s1, d1 = self.sf_execute(self._new_conn, c_name, hdr, recv)

            if not s1:
                self._err_as_client(
                    addr,
                    hdr.H_SES_TOK,
                    f"Error - Execute<INTENT={hdr.MSGINTENT}> \u27F9 Send<{d1} as BYTEARRAY>"
                )

                if isinstance(d1, str):
                    d1 = d1.encode()
                elif not isinstance(d1, bytes):
                    d1 = str(d1).encode()

                conn.send(d1)

            else:
                self._log_as_client(
                    addr,
                    hdr.H_SES_TOK,
                    f"Success - Execute<INTENT={hdr.MSGINTENT}>"
                )

        thread.done()
