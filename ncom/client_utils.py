import rsa, socket, hashlib
from std_imports import *


def auto_query_attr(attr_name: str, raise_error=False, rv=None, do_not_set=False):
    def _decorator(func):
        def _wrapper(self, *args, **kwargs):
            self.__attr__ = getattr(self, '__attr__', ())  # Define __attr__ if it hasn't been already.

            if attr_name in self.__attr__:
                if raise_error:
                    raise Exception(f"Cannot run function '{func.__name__}' now.")

                return rv

            out = func(self, *args, **kwargs)

            if not do_not_set:
                self.__attr__ = (*self.__attr__, attr_name)

            return out

        return _wrapper
    return _decorator


class ClientUtil:
    def __init__(self, logger: Logger) -> None:
        assert isinstance(logger, Logger)

        self.__lg__ = logger
        self.__keys__: Dict[str, Type[None] | rsa.Privatekey | rsa.PublicKey] = {
            'S2CPub':   None,
            'S2CPriv':  None,
            'C2SPub':   None,
        }

        self.__c_data__: Dict[str, Any] = {}
        self.__attr__ = ()
        self.__socket__: socket.socket

        self.__net__ = (
            Constants.TCP.CIP,
            Constants.TCP.PORT
        )

    def log(self, ll: LoggingLevel, data: str, sc: str = 'ClientUtils') -> None:
        self.__lg__.log(ll, sc, f'CLIENT<{self.__net__[0]},{self.__net__[1]}> {data}')

    def echo_traceback(self) -> None:
        lines = traceback.format_exc().split('\n')
        tb = '\n'.join([f' {("%d" % (i + 1)).ljust(len(f"{len(lines) + 1}"))}  | {l}' for i, l in enumerate(lines)])

        self.log(LoggingLevel.ERROR, f'Exception ignored:\n{tb}'.strip())

    def sf_execute(self, fnc, *args, **kwargs) -> Tuple[bool, Any]:
        """
        Runs `fnc` and captures any errors.

        Note: any KWARGS prepended w/ sfe_ will be treated as arguments for sf_execute

        :param fnc:    Function to execute.
        :param args:   args (for fnc)
        :param kwargs: keyword args (for sf_execute and fnc)

        :keyword sfe_echo_tb: [Def: TRUE; Type: BOOL]   Choose whether the traceback information is formatted and printed to stderr on error.
        :return: Tuple[bool, Any]                       (Success?, Returned value / Error)
        """

        kw_self = {k: v for k, v in kwargs.items() if k.startswith('sfe_')}
        kwargs = {k: v for k, v in kwargs.items() if k not in kw_self}

        try:
            return True, fnc(*args, **kwargs)

        except Exception as E:
            if kw_self.get('sfe_echo_tb', True):
                self.echo_traceback()

            return False, E

    @property
    def sock(self) -> socket.socket | None:
        return getattr(self, "__socket__", None)

    def send_message(
            self,
            tx_msg: bytes | str,
            intent_create_new=False,
            encrypt=True
    ) -> Tuple[bool, Any]:
        if encrypt:  # Session must be established.
            assert '__est__' in self.__attr__, 'Connection not established.'

        if self.sock is None:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.connect(self.__net__)

            setattr(self, '__socket__', s)

        if isinstance(tx_msg, str):
            tx_msg = tx_msg.encode()

        assert isinstance(tx_msg, bytes)

        if encrypt:
            tx_msg = Functions.BLOCK_ENCRYPT_DATA(tx_msg, self.__keys__['C2SPub'])

        st = self.__c_data__.get('ST')
        cuid = self.__c_data__.get('CUID')
        pub_key = self.__keys__.get('C2SPub')

        tx_hdr, tx_exh, tx_chk = Header.HeaderUtils.create_ng_bytes(
            ('S' if intent_create_new else 'C'),
            False,
            tx_msg,
            st,
            cuid,
            pub_key
        )

        out = tx_hdr + tx_exh + tx_chk.encode() + tx_msg
        print(st, cuid, pub_key, out)
        return self.sf_execute(self.sock.send, out)

    def get_response(self, recv_len: int) -> Tuple[bool, Any]:
        return self.sf_execute(self.sock.recv, recv_len)

    @staticmethod
    def _detect_header(recv: bytes) -> bool:
        _ = [recv := recv.replace(substr, b'') for substr in (b' ', b'\t', b'\n', b'\r')]

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

        return s

    def parse(self, recv: bytes) -> Structs.Transmission:
        if not self._detect_header(recv):
            return Structs.Transmission(None, None, '', recv)

        assert isinstance(recv, bytes), type(recv)
        assert len(recv) >= Header.NGHeaderItems.header_length(), len(recv)
        rx_hdr = recv[:Header.NGHeaderItems.header_length():]

        hdr = Header.HeaderUtils.load_ng_header(rx_hdr)
        total_rx_length = Header.NGHeaderItems.header_length() + hdr.EXT_HDR_L + hdr.H_HSH_LEN + hdr.H_MSG_LEN

        assert isinstance(self.sock, socket.socket)

        if (l2r := total_rx_length - len(recv)) > 0:
            recv += self.sock.recv(l2r)

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

        tx_sections = [*tx_sections[:-2:], *[s if s is not None else b'' for s in tx_sections[-2::]]]
        tx_sections[-2] = tx_sections[-2].decode()

        return Structs.Transmission(hdr, exh, *tx_sections[-2::])

    def _v(self, rx: Structs.Transmission) -> bytes:
        if rx.hdr is None:
            return rx.msg

        assert rx.exh is None,                                          'E000'  # The server never sends an EXH
        assert rx.hdr.EXT_HDR_L == 0,                                   'E000b'
        assert hashlib.sha256(rx.msg).hexdigest() == rx.chk,            'E001'
        assert (pr := self.__keys__.get('S2CPriv')) is not None,        'E002'
        assert (msg := self.sf_execute(Functions.BLOCK_DECRYPT_DATA, rx.msg, pr))[0], 'E003'
        assert rx.hdr.H_SES_TOK == self.__c_data__.get('ST'),           'E004'
        assert rx.hdr.H_CLT_UID == self.__c_data__.get('CUID'),         'E005'
        assert rx.hdr.MSGINTENT == 'C',                                 'E006'
        assert rx.hdr.H_MC_TYPE == 0,                                   'E007'

        msg = cast(bytes, msg[1]).strip()
        return msg

    def verify(self, rx: Structs.Transmission) -> Tuple[bool, bytes]:
        return self.sf_execute(self._v, rx)

    def close_socket(self) -> None:
        self.sf_execute(self.sock.close)
        setattr(self, '__socket__', None)

    @property
    def connection_established(self) -> bool:
        return '__est__' in self.__attr__

    @auto_query_attr('__est__', True, do_not_set=True)
    def establish_session(self) -> None | Tuple[bool, str, str]:
        try:
            self._gen_keys()  # type: ignore

            assert isinstance((s2cPub := self.__keys__.get('S2CPub')), rsa.PublicKey)

            conn_est_code = b'<EstCon>'
            tx_msg = conn_est_code + cast(rsa.PublicKey, s2cPub).save_pkcs1('PEM')

            assert (d := self.send_message(tx_msg, intent_create_new=True, encrypt=False))[0], \
                f'Could not send message: {d[-1]}'
            s, rx = self.get_response(Header.NGHeaderItems.header_length())
            assert not rx.startswith(b'ERR.'), rx.decode()
            assert self._detect_header(rx), f'Bad RX'
            rx = self.parse(rx)

            # In rare cases, the message can be an unencrypted error string (ERR.*)

            _ERR_STATE_0 = rx.msg.startswith(b'ERR.')
            if not _ERR_STATE_0:
                s, rx_msg = self.sf_execute(Functions.BLOCK_DECRYPT_DATA, rx.msg, self.__keys__['S2CPriv'])
                if not s:
                    _ERR_STATE_0 = True
                    rx_msg = Constants.RESPONSES.ERRORS.GENERAL.encode()

                rx.msg = rx_msg

            # Note: error/status codes are always 8 characters long.
            status = rx.msg[:8].decode()
            if status.startswith('ERR.'):
                _ERR = (True, status, rx.msg[8::].strip())
            elif status != Constants.RESPONSES.NORMAL.CONNECTION_ESTABLISHED:
                _ERR = (True, Constants.RESPONSES.ERRORS.GENERAL, 'Could not establish connection.')

            else:
                # Connection established.
                assert len(val := rx.msg[8::].strip().split(b':DELIM:')) == 3  # ST, CUID, PKEY

                st, cuid, pkey = val

                st = st.decode()
                cuid = cuid.decode()

                assert (sfs := self.sf_execute(rsa.PublicKey.load_pkcs1, pkey, 'PEM'))[0]
                pkey = sfs[-1]

                self.__keys__['C2SPub'] = pkey
                self.__c_data__ = {
                    'ST':       st,
                    'CUID':     cuid
                }

                self.log(LoggingLevel.INFO, f"Established connection w/ SERVER<{self.__net__[0],self.__net__[1]}> {st=} {cuid=}")

                self.__attr__ = (*self.__attr__, '__est__')

                self.close_socket()
                return None

            self.log(LoggingLevel.ERROR, f"Failed to establish connection w/ SERVER<{self.__net__[0],self.__net__[1]}>: {status=}; {_ERR[-1]}")

            self.close_socket()
            return _ERR

        except Exception as E:
            self.log(
                LoggingLevel.ERROR,
                f"Failed to establish connection w/ SERVER<{self.__net__[0],self.__net__[1]}>: ERR-000 {E.__class__.__name__}({str(E)})"
            )

            self.close_socket()
            return True, Constants.RESPONSES.ERRORS.GENERAL, (
                str(E) if len(str(E)) else 'ERR-000'
            )

    def close_session(self) -> None:
        # Delete all info created/stored
        # Close socket.

        self.__attr__ = ()
        setattr(self, '__socket__', None)
        self.__keys__ = {k: None for k in self.__keys__.keys()}
        self.__c_data__ = {}

        if isinstance(self.sock, socket.socket):
            self.close_socket()

    @auto_query_attr('__gen_keys__', False, None)
    def _gen_keys(self) -> None:
        pb, pr = Functions.GET_RSA_KEYS()

        self.__keys__['S2CPub'] = pb
        self.__keys__['S2CPriv'] = pr
