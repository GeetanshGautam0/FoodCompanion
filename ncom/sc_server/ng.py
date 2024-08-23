from ._template import __fc_server__, __fc_thread__

try:
    from sc_data import *
    from sc_db import *
except ImportError:
    from ..sc_data import *
    from ..sc_db import *

import sys, rsa, hashlib, uuid, json
from typing import cast, Tuple
from time import sleep


def stdout(data: str, __pr: str = '') -> int:
    return Functions.STDOUT(data, __pr)


def stderr(data: str, __pr: str = '') -> int:
    return Functions.STDERR(data, __pr)


class NGServer(__fc_server__):
    def __init__(self, ip: str, pt_db: PTDatabase, user_db: UserDatabase, *args, **kwargs) -> None:
        self.__t = __fc_thread__()
        self.__mcv__ = 20240814000000
        __fc_server__.__init__(self, (ip, Constants.TCP.PORT), self.__t, *args, **kwargs)
        self.__pt_db__ = pt_db
        self.__u_db__ = user_db

        # __connectors__:   Dict[str, Tuple[__fc_thread__, socket.socket, Tuple[str, int]]]
        # __sessions__:     Dict[str, Dict[str, Any]]

        # Memoize the COM_CHK value for a faster response to the first message.
        _ = Header.HeaderUtils.get_com_chk()

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

    def _get_tx(self, c_name: str, hdr: Header.NGHeader, recv: bytes) -> Structs.Transmission:
        thread, conn, addr = self.__connectors__[c_name]

        tl = Header.NGHeaderItems.header_length() + hdr.EXT_HDR_L + hdr.H_HSH_LEN + hdr.H_MSG_LEN

        if (l2r := tl - len(recv)) > 0:
            recv += conn.recv(l2r)

        tx_section_length = [hdr.EXT_HDR_L, hdr.H_HSH_LEN, hdr.H_MSG_LEN]
        tx_sections, cntr = [], Header.NGHeaderItems.header_length()

        for L in tx_section_length:
            tx_sections.append(recv[cntr:(cntr + L)])
            cntr += L

        tx_sections = [s if len(s) else None for s in tx_sections]

        if tx_sections[0] is None:
            assert tx_section_length[0] == 0
            exh = None

        else:
            exh = Header.HeaderUtils.load_exh(tx_sections[0])

        tx_sections[-2] = tx_sections[-2].decode()
        return Structs.Transmission(hdr, exh, *tx_sections[-2::])

    def _compatible_com_chk(self, com_chk: str, addr: Tuple[str, int], st: str | None) -> bool:
        warn = ('0' * Header.NGHeaderItems.H_COM_CHK.SIZE, )
        comp = (Header.HeaderUtils.get_com_chk(), )

        if com_chk in comp:
            return True

        elif com_chk in warn:
            self._err_as_client(addr, st, f'[WARN] Experimental COM_CHK value. Compatability cannot be assured')
            return True

        self._err_as_client(addr, st, 'Incompatible COM_CHK value.')
        return False

    def _create_tx(
        self,
        ses_tok: str,
        clt_uid: str,
        message_body: str | bytes,
        sf_mode: bool = True
    ) -> bytes:
        if sf_mode:
            s, tx = self.sf_execute(self._create_tx, ses_tok, clt_uid, message_body, sf_mode=False)
            if not s:
                return Constants.RESPONSES.ERRORS.GENERAL.encode()
            else:
                return tx

        if isinstance(message_body, str):
            message_body = message_body.encode()

        assert isinstance(message_body, bytes)

        hdr, exh, chk = Header.HeaderUtils.create_ng_bytes(
            'C',
            True,
            message_body,
            ses_tok,
            clt_uid,
            None,
            include_exh=False       # The server does not send an EXH
        )

        return hdr + exh + chk.encode() + message_body

    def _new_conn(self, c_name: str, hdr: Header.NGHeader, recv: bytes) -> None:
        # TODO: Log transmissions.

        thread, conn, addr = self.__connectors__[c_name]

        s, rx = self.sf_execute(self._get_tx, c_name, hdr, recv)
        assert s and isinstance(rx, Structs.Transmission), \
            f'{Constants.RESPONSES.ERRORS.GENERAL} E001   Could not load Rx struct.'

        assert rx.hdr.MSGINTENT == 'S', f'{Constants.RESPONSES.ERRORS.BAD_HEADER} E002-A Bad intent.'
        assert rx.hdr.H_SES_TOK == ('0' * Header.NGHeaderItems.H_SES_TOK.SIZE), \
            f'{Constants.RESPONSES.ERRORS.INVALID_SESSION_ID} E002-B SESTOK'
        assert rx.hdr.H_CLT_UID == ('0' * Header.NGHeaderItems.H_CLT_UID.SIZE), \
            f'{Constants.RESPONSES.ERRORS.INVALID_SESSION_ID} E002-C CUID'

        assert self._compatible_com_chk(rx.hdr.H_COM_CHK, addr, rx.hdr.H_SES_TOK), \
            f'{Constants.RESPONSES.ERRORS.INCOMPATIBLE_VERSION} E003-A Bad ComCHK value.'
        assert self._is_compatible(rx.hdr.H_APP_VIS), \
            f'{Constants.RESPONSES.ERRORS.INCOMPATIBLE_VERSION} E003-B Incompatible app.'

        assert isinstance(rx.exh, Structs.ExtendedHeader), \
            f'{Constants.RESPONSES.ERRORS.BAD_REQUEST} E004   No ExtHeader found.'
        assert rx.exh.EXH_KEY_MD5 is None, f'{Constants.RESPONSES.ERRORS.INVALID_SESSION_ID} E005   PKCHK'

        m_hsh = hashlib.sha256(rx.msg).hexdigest()
        assert len(rx.chk) == 64, f'{Constants.RESPONSES.ERRORS.BAD_TRANSMISSION} E006-A {m_hsh}'
        assert m_hsh == rx.chk, f'{Constants.RESPONSES.ERRORS.BAD_TRANSMISSION} E006-B {m_hsh}'

        assert rx.msg.startswith(b'<EstCon>'), f'{Constants.RESPONSES.ERRORS.BAD_REQUEST} E007   <EstCon>'

        rsa_pub_key_pem = rx.msg.lstrip(b'<EstCon>')
        vKey, S2CPubKey = self.sf_execute(
            rsa.PublicKey.load_pkcs1,
            rsa_pub_key_pem,
            'PEM'
        )
        assert vKey, f'{Constants.RESPONSES.ERRORS.BAD_REQUEST} E008   E2E-Encryption: !vPEM S2CPubKey'

        C2SPubKey, C2SPrivKey = Functions.GET_RSA_KEYS()
        ses_tok = self._gen_ses_tok("ST")
        cuid = uuid.uuid4().__str__()

        rsp = (
            Constants.RESPONSES.NORMAL.CONNECTION_ESTABLISHED.encode() + b' ' +
            b":DELIM:".join([ses_tok.encode(), cuid.encode(), C2SPubKey.save_pkcs1("PEM")])
        )

        rsp = Functions.BLOCK_ENCRYPT_DATA(rsp, cast(rsa.PublicKey, S2CPubKey))
        conn.send(self._create_tx(ses_tok, cuid, rsp, sf_mode=True))

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
                if not isinstance(d1, bytes):
                    d1 = str(d1).encode()

                if not d1.startswith(b'ERR.'):
                    d1 = Constants.RESPONSES.ERRORS.GENERAL.encode() + b' ' + d1

                self._err_as_client(
                    addr,
                    hdr.H_SES_TOK,
                    f"Error - Execute<INTENT={hdr.MSGINTENT}> \u27F9 Send<{d1}>"
                )

                conn.send(d1)

            else:
                self._log_as_client(
                    addr,
                    hdr.H_SES_TOK,
                    f"Success - Execute<INTENT={hdr.MSGINTENT}>"
                )

        thread.done()
