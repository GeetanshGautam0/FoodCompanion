from ._template import __fc_server__, __fc_thread__

try:
    from sc_data import *
    from sc_db import *
except ImportError:
    from ..sc_data import *
    from ..sc_db import *

import sys, rsa, hashlib, json
from typing import Tuple
from time import sleep


class LegacyServer(__fc_server__):
    def __init__(self, ip: str, pt_db: PTDatabase, logger: Logger, *args, **kwargs) -> None:
        self.__t = __fc_thread__()
        self.__mcv__ = 20240708000000
        __fc_server__.__init__(self, (ip, Constants.TCP.L_PORT), self.__t, logger, *args, **kwargs)
        self.__ncc__ = b'NW_CON'
        self.__pt_db__ = pt_db

        # __connectors__:   Dict[str, Tuple[__fc_thread__, socket.socket, Tuple[str, int]]]
        # __sessions__:     Dict[str, Dict[str, Any]]

        # Memoize the COM_CHK value for a faster response to the first message.
        _ = Header.HeaderUtils.get_com_chk()

    def run(self) -> None:
        self.bind()
        self.start_listener(Constants.TCP.BKLOG)

    def _log_as_client(self, addr: Tuple[str, int], st: str | None, message: str) -> None:
        if st is None:
            self.log_sc(LoggingLevel.INFO, f'CLIENT<{addr[0]},{addr[1]}> {message}', 'LGSRV')
        else:
            self.log_sc(LoggingLevel.INFO, f'CLIENT<{addr[0]},{addr[1]} :: ST{st}> {message}', 'LGSRV')

    def _err_as_client(self, addr: Tuple[str, int], st: str | None, message: str):
        if st is None:
            self.log_sc(LoggingLevel.ERROR, f'CLIENT<{addr[0]},{addr[1]}> {message}', 'LGSRV')
        else:
            self.log_sc(LoggingLevel.ERROR, f'CLIENT<{addr[0]},{addr[1]} :: ST{st}> {message}', 'LGSRV')

    def _handle_new_conn(self, c_name: str, recv: bytes) -> None:
        thread, conn, addr = self.__connectors__[c_name]

        recv = recv.strip()

        assert not thread.is_done, Constants.RESPONSES.GENERAL
        assert recv[:len(self.__ncc__)] == self.__ncc__, Constants.RESPONSES.ERRORS.BAD_REQUEST
        assert len(recv) == (len(self.__ncc__) + Constants.SZ.DATETIME), Constants.RESPONSES.ERRORS.BAD_REQUEST
        assert recv[len(self.__ncc__)::].decode().isnumeric(), Constants.RESPONSES.ERRORS.BAD_REQUEST

        cvi = int(recv[len(self.__ncc__)::].decode())
        assert self._is_compatible(cvi), Constants.RESPONSES.ERRORS.INCOMPATIBLE_VERSION

        # App version okay. Create session.

        st = self._gen_ses_tok('ST')
        i = 0
        while st in self.__sessions__ and i <= 1_000:
            st = self._gen_ses_tok('ST')
            i += 1

            sleep(0.1)

        self.on_msg_capt(addr, st, recv)

        if st in self.__sessions__:
            self._log_as_client(addr, None, 'Failed to generate session token.')
            assert False, Constants.RESPONSES.ERRORS.GENERAL

        C2SPubKey, C2SPrivKey = rsa.newkeys(512)
        pubKey = C2SPubKey.save_pkcs1("PEM")

        self.__sessions__[st] = {
            'C2SKey': {  # For C->S communications.
                'PublicKey':    C2SPubKey,
                'PrivateKey':   C2SPrivKey,
                'PublicKey_PEM': pubKey,
                'PubKey_CHK': hashlib.md5(pubKey).hexdigest()
            },
            'ConnHistory': {
                c_name:         (thread, conn, addr)
            },
            'IsActive':         True,
            'attr':             (
                f'{cvi=}',
                'mode_legacy'
            )
        }

        out = f'{self.__ncc__.decode()}{st}'.encode()
        out += pubKey

        self._log_as_client(addr, None, f"NW_CON Success<{cvi=}>; Reply<{out=}>")
        conn.send(out)

    def _handle_old_conn(self, c_name: str, recv: bytes) -> None:
        thread, conn, addr = self.__connectors__[c_name]

        hash_length = 64
        recv = recv.strip()

        assert not thread.is_done, Constants.RESPONSES.ERRORS.GENERAL
        assert len(recv) >= Header.LegacyHeaderItems.header_length(), Constants.RESPONSES.ERRORS.BAD_TRANSMISSION

        s, hdr = self.sf_execute(
            Header.HeaderUtils.load_legacy_header,
            recv[:Header.LegacyHeaderItems.header_length()]
        )

        assert s, Constants.RESPONSES.ERRORS.BAD_HEADER
        assert isinstance(hdr, Structs.LegacyHeader), Constants.RESPONSES.ERRORS.BAD_HEADER
        assert not hdr.H_MC_TYPE, Constants.RESPONSES.ERRORS.BAD_REQUEST
        assert hdr.H_SES_TOK in self.__sessions__.keys(), Constants.RESPONSES.ERRORS.INVALID_SESSION_ID

        session = self.__sessions__[hdr.H_SES_TOK]
        assert hdr.H_MSG_LEN > 0, Constants.RESPONSES.ERRORS.BAD_REQUEST
        assert session.get('IsActive', False), Constants.RESPONSES.ERRORS.BAD_REQUEST
        assert 'mode_legacy' in session.get('attr', ()), Constants.RESPONSES.ERRORS.BAD_REQUEST
        assert f'cvi={hdr.H_APP_VIS}' in session.get('attr', ()), Constants.RESPONSES.ERRORS.BAD_REQUEST

        total_msg_len = Header.LegacyHeaderItems.header_length() + hash_length + hdr.H_MSG_LEN

        if len(recv) >= total_msg_len:
            self._log_as_client(addr, hdr.H_SES_TOK, 'Success<Legacy.__hoc.HeaderRead>; Proc<Message>')

        else:
            n = total_msg_len - len(recv)
            self._log_as_client(
                addr,
                hdr.H_SES_TOK,
                f'Success<Legacy.__hoc.HeaderRead>; Recv<{n=} for L={total_msg_len}>; then: Proc<Message>.'
            )

            recv += conn.recv(n)
            recv.strip()

        assert len(recv) == total_msg_len, Constants.RESPONSES.ERRORS.BAD_TRANSMISSION

        TX_CHK = recv[Header.LegacyHeaderItems.header_length():Header.LegacyHeaderItems.header_length() + hash_length]
        TX_MSG = recv[Header.LegacyHeaderItems.header_length() + hash_length::]

        e_chk = hashlib.sha256(TX_MSG).hexdigest().encode()
        assert e_chk == TX_CHK, Constants.RESPONSES.ERRORS.BAD_TRANSMISSION

        self._log_as_client(addr, hdr.H_SES_TOK, f'Validate<TX_MSG :: {TX_CHK=}>')

        priv_key = session.get('C2SKey', {}).get('PrivateKey', None)
        assert isinstance(priv_key, rsa.PrivateKey), Constants.RESPONSES.ERRORS.INVALID_SESSION_ID

        dec = rsa.decrypt(TX_MSG, priv_key).decode()
        self.on_msg_capt(addr, hdr.H_SES_TOK, dec)
        data = dec.split('~')

        assert len(data) == 3, Constants.RESPONSES.ERRORS.BAD_REQUEST
        data = [d.strip() for d in data]
        dchk = [1 if len(d) else 0 for d in data]
        assert sum(dchk) == len(data), Constants.RESPONSES.ERRORS.BAD_REQUEST

        s0, iid = self.sf_execute(Structs.InstitutionID, data[0])
        s1, dob = self.sf_execute(Structs.FormattedDate, data[1])
        s2, pid = self.sf_execute(Structs.PatientID, data[2])

        assert s0 & s1 & s2, Constants.RESPONSES.ERRORS.BAD_REQUEST
        assert pid.value > 0, Constants.RESPONSES.ERRORS.RECORD_NOT_FOUND  # The LEGACY SPEC requires that PID >= 1
        diet = self.__pt_db__.get_patient_diet(pid=pid, iid=iid, dob=dob)

        # Constants.RESPONSES.ERRORS.RECORD_NOT_FOUND (this was changed)
        assert isinstance(diet, Structs.DietOrder), 'ERR.PTNF'
        self._log_as_client(addr, hdr.H_SES_TOK, f'PT<{pid=}; {iid=}; {dob=}>. Found P-RCD; SendOrder<{diet}>.')

        self.__sessions__[hdr.H_SES_TOK]['IsActive'] = False  # session ID may not be used anymore.

        meal_options = legacy_mo_format(get_meal_options(diet.id))
        self._log_as_client(addr, hdr.H_SES_TOK, f'Send: LegacyMOFormat<{meal_options}>')

        conn.send(json.dumps(meal_options, indent=4).encode())

    def _on_capture_event_(self, c_name: str) -> None | str:
        """
        On Capture Event (LEGACY server)
        Uses sf_execute to call potentially unsafe/error-prone functions.

        :param c_name:      Connection ID
        :return:            None (normally) or "PASS" if c_name == None (test case)
        """

        if c_name is None:
            return 'PASS'

        default_recv_len = Header.LegacyHeaderItems.header_length()  # Does not follow ncom.config

        thread, conn, addr = self.__connectors__[c_name]

        recv = conn.recv(default_recv_len)

        if recv[:len(self.__ncc__)] == self.__ncc__:
            # Session to create a new connection.
            s, d = self.sf_execute(self._handle_new_conn, c_name, recv)

            if not s:
                self._err_as_client(addr, None, f'REQ_AS_NS Error<{d.__class__.__name__}, {str(d)}>')
                conn.send(str(d).encode())

            self._log_as_client(addr, None, f'REQ_AS_NS Done.')

        elif recv[:Constants.SZ.DATE].decode().isnumeric():
            # GET-P-DET request.
            s, d = self.sf_execute(self._handle_old_conn, c_name, recv)
            if not s:
                self._err_as_client(addr, None, f'REQ_AS_OS Error<{d.__class__.__name__}, {str(d)}>')
                conn.send(str(d).encode())

            self._log_as_client(addr, None, f'REQ_AS_OS Done.')

        else:
            # Invalid request
            # Note that HTTP requests should be handled w/ _reply_to_http

            d, r = self.sf_execute(self._reply_to_http, _rcv=recv, _conn=conn, _addr=addr)

            if not d:
                self.log_sc(LoggingLevel.ERROR, f' @_reply_to_http E({r})', 'LGSRV')

            elif not r:
                self._err_as_client(addr, None, 'Received an invalid, non-HTTP request.')
                # TODO: Create a system to blacklist IP:PORT combinations if invalid requests are sent too frequently.

        thread.done()

    def _shutdown(self) -> None:
        # Shutdown tasks
        # Log sessions
        self.log_sessions()
