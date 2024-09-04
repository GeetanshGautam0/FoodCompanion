try:
    from sc_data import *
    from sc_db import *
except ImportError:
    from ..sc_data import *
    from ..sc_db import *


import sys, socket, re, select, rsa, hashlib, traceback, random, json
from time import sleep, strftime, gmtime
from datetime import datetime
from threading import Thread, Event, Timer
from typing import cast, Tuple, Dict, Any, List, LiteralString


class __fc_thread__(Thread):
    def __init__(self, *args, **kwargs) -> None:
        super(__fc_thread__, self).__init__(*args, **kwargs)
        self.__event_1__ = Event()

    def done(self) -> None:
        self.__event_1__.set()

    @property
    def is_done(self):
        return self.__event_1__.is_set()

    def join_sf(self, timeout: int = 0) -> None:
        try:
            self.join(timeout)
        except RuntimeError:
            pass


class __fc_server__:
    def __init__(
            self,
            network: Tuple[str, int],
            server_thread: __fc_thread__,
            logger: Logger,
            *args,
            **kwargs
    ) -> None:
        assert isinstance(logger, Logger)

        self.__logger__ = logger
        self.__sc__ = 'ServerTemplate'
        self.__s_thread__ = server_thread
        self.__args__ = args
        self.__kwargs__ = kwargs

        self.__net__ = network
        self.__sock__: socket.socket

        self.__is_alive__ = True
        self.__sessions__: Dict[str, Dict[str, Any]] = {}
        self.__connectors__: Dict[str, Tuple[__fc_thread__, socket.socket, Tuple[str, int]]] = {}
        self.__cost_task__: Timer | None = None
        self.__cost_timer__ = AppInfo.APPINFO.COST_TIMER
        self.__attr__ = ()

        self.__shutdown_tasks__ = []

        self._on_init()

    @property
    def logger(self) -> Logger:
        return self.__logger__

    def log(self, ll: LoggingLevel, data: str) -> None:
        self.logger.log(ll, self.__sc__, ('SERVER<%s,%d> ' % self.__net__) + data)

    def log_sc(self, ll: LoggingLevel, data: str, sc: str) -> None:
        self.logger.log(ll, sc, ('SERVER<%s,%d> ' % self.__net__) + data)

    def request_shutdown(self) -> None:
        self.log(
            LoggingLevel.INFO,
            'Shutdown request created.'
        )

        self.__s_thread__.done()
        self._socket.close()
        self.__is_alive__ = False

        self.sf_execute(self.__cost_task__.cancel)
        self.sf_execute(self._close_all_sockets)
        self.sf_execute(self._shutdown)

        for task in self.__shutdown_tasks__:
            self.logger.log(
                LoggingLevel.INFO,
                'TemplateServer',
                f'PLUGINS.EXIT; SFTask<{task}> -> {self.sf_execute(task)}'
            )

    def _close_all_sockets(self) -> None:
        for c_name, (thread, conn, addr) in self.__connectors__.items():
            s = self.sf_execute(thread.done)[0]
            s |= self.sf_execute(thread.join, 0)[0]
            s |= self.sf_execute(conn.close)[0]

            self.log(LoggingLevel.DEBUG, f'CAS<{c_name}, {addr}>')

    def bind(self) -> None:
        if not self._configured[0]:
            return

        self.__attr__ = (*self.__attr__, 'bind')
        self._socket.bind(self.__net__)

    def start_listener(self, n: int) -> None:
        if not self._configured[0]:
            return

        assert 'bind' in self.__attr__,              'Bind to the address first by executing __fc_server__.bind'
        assert 'listen' not in self.__attr__,        'Listener active at provided address.'
        assert f'net-check-{self.__net__}' in self.__attr__, 'Unverified network address.'
        assert self._test_listener(self.on_capture), 'Listener "on_capture(str | None) -> None" not defined properly.'

        self.__attr__ = (*self.__attr__, 'listen')

        self._socket.listen(n)
        # self._socket.setblocking(False)
        self.log(LoggingLevel.INFO, "Listening for connections w/ bklog=%d" % n)

        # Secondary loop: C-OST
        self.__cost_task__ = Timer(self.__cost_timer__, lambda: self.sf_execute(self._clear_ost))
        self.__cost_task__.start()

        # Primary loop
        while self.__is_alive__ & (~self.__s_thread__.is_done):
            _ss, res = self.sf_execute(
                select.select,
                [
                    self._socket,
                    *[
                        c[1] for c in self.__connectors__.values()
                        if not c[0].is_done
                    ]
                ],  # __rlist
                [], # __wlist
                [], # __xlist
                Constants.TCP.S_TOUT  # timeout
            )

            if not _ss:
                self.log(LoggingLevel.ERROR, f'PREcOST: {res.__class__.__name__}({str(res)})')
                self.sf_execute(self._clear_ost)

                continue  # Go back to the top

            (read, *_) = res  # Unpack read, write, and errors

            for r in read:
                if (not self.__is_alive__) or self.__s_thread__.is_done:
                    break

                if r == self._socket:
                    conn, addr = cast(socket.socket, r).accept()
                    # conn.setblocking(False)

                    c_name = f'CNAME_{addr[0]}_{datetime.now().strftime("%Y%M%D%H%m%S")}'

                    thread = __fc_thread__(target=self.on_capture, args=(c_name, ))
                    self.__connectors__[c_name] = (thread, conn, addr)

                    thread.start()

        else:
            self.log(LoggingLevel.WARN, 'Closing Server')

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

    # -------- Internal Functions --------

    def log_sessions(self) -> None:
        if len(self.__sessions__):
            lines = [f'{s}: {d}' for s, d in self.__sessions__.items()]
            frmt_lines = '\n'.join([f' {("%d" % (i + 1)).ljust(len(f"{len(lines) + 1}"))}  | {l}' for i, l in enumerate(lines)])
            self.logger.log(LoggingLevel.INFO, 'ServerTemplate', f'ServerManager<{self.__net__[0]},{self.__net__[1]}> - SESSIONS:\n{frmt_lines}')

        else:
            self.logger.log(LoggingLevel.WARN, 'ServerTemplate', f'ServerManager<{self.__net__[0]},{self.__net__[1]}> - No sessions to log.')

    def _shutdown(self) -> None:
        raise Exception("Not Implemented.")

    def _close_socket(self, c_name: str) -> None:
        if c_name not in self.__connectors__:
            return

        t, s, *_ = self.__connectors__[c_name]
        t.done()
        s.close()

    def _clear_ost(self) -> None:
        p = 0
        for k, (t, s, *_) in {**self.__connectors__}.items():  # Copy to avoid runtime errors.
            if t.is_done:
                self.sf_execute(s.close)
                p += 1
                self.__connectors__.pop(k)

        if p > 0:
            self.log(LoggingLevel.DEBUG, f'R{p} L{len(self.__connectors__)} w{self.__cost_timer__}')

        self.__cost_task__ = Timer(self.__cost_timer__, lambda: self.sf_execute(self._clear_ost))
        self.__cost_task__.start()

    def _gen_ses_tok(self, __salt: str = '') -> str:
        return hashlib.md5(f'{__salt}{random.random()}{datetime.now().strftime("%Y%M%D%H%m%S")}'.encode()).hexdigest()

    def _reply_to_http(self, _rcv: bytes, _conn: socket.socket, _addr: Tuple[str, int]) -> bool:
        def read_file(file: str) -> str:
            with open(file, 'r') as fIn:
                out = fIn.read()
                fIn.close()

            return out

        def file_content(file: str) -> str:
            r = read_file(file).split('\n')

            lines = [
                '| %s |  %s' % (
                    f'{i + 1}'.rjust(len(f'{len(r) + 1}')),
                    line.replace('<', '&lt').replace('>', '&gt').replace('%', '%%')
                ) for i, line in enumerate(r)
            ]

            return '%s\n<br>%s<br>\n%s\n%s\n%s' % (
                '-' * max(map(lambda x: len(x), lines)),
                f'Content of {file}',
                '-' * max(map(lambda x: len(x), lines)),
                '\n'.join(lines).strip(),
                '-' * max(map(lambda x: len(x), lines))
            )

        def format_as_p(d: List[str]) -> str:
            return '\n'.join([f'<p>{l}</p>' for l in d])

        if b'GET' in _rcv and b'HTTP' in _rcv:
            self.log(LoggingLevel.INFO, f"Replying to {_addr} as an HTTP request.")

            # Data not used.
            # hdrs, sep, body = _rcv.partition(b'\r\n\r\n')
            # hdrs = hdrs.decode()

            css = read_file('sc_server/_html/help.css')
            html = read_file('sc_server/_html/help.html')

            com_spec = file_content('ng_com_spec')
            changelog = file_content('com.CHANGELOG')
            license = file_content('../LICENSE')
            help_html = format_as_p([com_spec, changelog, license])

            tx_time = datetime.now().strftime(f'{Constants.FRMT.DATETIME} UTC{strftime("%z", gmtime())}')
            phdr = f'GeetanshGautam / TX@{tx_time} / FC<{AppInfo.APPINFO.APP_VERSION}>\n{Header.HeaderUtils.get_com_chk()}'

            html = html % (css, phdr, self.__net__[1], help_html)

            hdrs = ''.join('%s: %s\r\n' % (h, v) for h, v in {
                'Content-Type': 'text/html; encoding=utf8',
                'Content-Length': len(html),
                'Connection': 'close'
            }.items())

            protocol = 'HTTP/1.1'
            status = '200'
            status_text = 'OK'

            _conn.sendall(('%s %s %s' % (protocol, status, status_text)).encode())
            _conn.sendall(b'\r\n')
            _conn.sendall(hdrs.encode())
            _conn.sendall(b'\r\n')
            _conn.sendall(html.encode())

            sleep(0.5)
            return True

        else:
            _conn.send(Constants.RESPONSES.ERRORS.BAD_REQUEST.encode())  # Bad request.

        return False

    def _is_compatible(self, vi: int) -> bool:
        return vi >= self.min_comp_ver

    def _on_init(self) -> None:
        s, r = self._configured

        if not s:
            formatted_r = r[0] if len(r) == 1 else (
                'Unknown error' if len(r) == 0 else (
                    ('\n\t%s' % '\n\t'.join(r)).rstrip()
                )
            )
            self.log(LoggingLevel.ERROR, 'OI test(s) failed: %s' % formatted_r)

        self._net_check()
        self.__sock__ = socket.socket(socket.AF_INET, socket.SOCK_STREAM)  # Setup for TCP connection

    def _net_check(self) -> None:
        self.__attr__ = (*self.__attr__, f'net-check-{self.__net__}')

        if self.__net__[0] != 'localhost':
            _nip = re.search(r'^((25[0-5]|(2[0-4]|1[0-9]|[1-9]|)[0-9])(\.(?!$)|$)){4}$', self.__net__[0])
            assert _nip is not None, f'Invalid Server IP "{self.__net__[0]}".'

            self.__net__ = (_nip.string, self.__net__[-1])

        assert isinstance(self.__net__[-1], int), f'Invalid Server PORT "{self.__net__[-1]}" (1).'
        assert (self.__net__[-1] <= 65535) & (self.__net__[-1] >= 0), f'Invalid Server PORT "{self.__net__[-1]}" (2).'

        self.log(LoggingLevel.INFO, '%s:%d - NetCheck PASS' % self.__net__)

    def _test_listener(self, listener) -> bool:
        try:
            match listener:
                case self.on_capture:
                    return self.on_capture(None) == 'PASS'

        except Exception as _:
            pass

        return False

    # -------- Getters --------

    @property
    def min_comp_ver(self) -> int:
        return getattr(self, '__mcv__', -1)

    @property
    def _socket(self) -> socket.socket | None:
        return getattr(self, '__sock__', None)

    @property
    def _configured(self) -> Tuple[bool, List[str]]:
        r = []

        if getattr(self, '__mcv__', None) is None:
            r.append('Must define the minimum compliant version (integer) as __mcv__.')

        if getattr(self, '_on_capture_event_', None) is None:
            r.append('Must the "on_capture(str | None) -> None" event listener as  _on_capture_event_.')

        return not len(r), r

    @property
    def is_done(self):
        return self.__s_thread__.is_done

    def get_conn_info(self, conn_name: str) -> Tuple[__fc_thread__, socket.socket, Tuple[str, int]] | None:
        return self.__connectors__.get(conn_name)

    # -------- Event Listeners --------

    def on_capture(self, c_name: str | None) -> None | LiteralString:
        """
        Child classes must define _on_capture_event_(str | None) -> None with the following behaviour.

        Expected behaviour:
            * Handle any incoming messages
            * Request more data if needed manually using __fc_server__.recv(N)
            * If c_name is None, return Literal(PASS) immediately as this is a test to check if the listener is defined.
            * If a session key is provided:
                A. If the token is valid, add the c_name to __sessions__
                B. If the token is invalid, return RESPONSES.ERRORS.INVALID_SESSION_ID

            Handle the data as needed.

        Note:
            It is recommended to run subroutines or exception-raising commands using __fc_server__.sf_execute to avoid
            any threading errors.

        :param c_name:      Connector name/ID (str / None)
        :return:            None

        :raises Exception:  Not Implemented Error
        """

        oce = getattr(self, '_on_capture_event_', None)

        if oce is None:
            return None

        # return oce(c_name)
        return self.sf_execute(oce, c_name)[-1]
