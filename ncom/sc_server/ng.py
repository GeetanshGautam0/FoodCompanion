from ._template import __fc_server__, __fc_thread__

try:
    from sc_data import *
    from sc_db import *
except ImportError:
    from ..sc_data import *
    from ..sc_db import *

import sys, rsa, hashlib, uuid, json
from datetime import datetime, timedelta
from typing import cast, Tuple, List, Set
from threading import Timer


class Forms:
    class FormItems:
        pid = ('pid', 'PatientID', Structs.PatientID)
        iid = ('iid', 'InstitutionID', Structs.InstitutionID)
        dob = ('dob', 'DateOfBirth', Structs.FormattedDate)

        name = ('name', 'Name', Structs.FormattedName)
        bld = ('bld', 'BLD', str)
        cat = ('cat', 'FoodCategory', int)
        cal = ('cal', 'Calories', float)
        cst = ('cst', 'Starches', float)
        csu = ('csu', 'Sugars', float)
        cfi = ('cfi', 'Fiber', float)
        ftr = ('ftr', 'Trans Fat', float)
        fsa = ('fsa', 'Saturated Fat', float)
        pco = ('pco', 'Complete Protein Source', bool)
        pro = ('pro', 'Protein', float)
        ssc = ('ssc', 'Serving Size Count', float)
        ssu = ('ssu', 'Serving Size Unit', int)
        odiets = ('odiets', 'OmittedDietOrders', List[int])
        id = ('id', 'ID', int)
        diet = ('diet', 'DietOrder', int)
        pname = ('pname', 'PatientName', Structs.FormattedName)
        field = ('field', 'FieldName', str)
        value = ('value', 'Value', str)
        userID = ('userID', 'UserID', int)
        userAC = ('userAC', 'User Access Code', str)
        txTime = ('txTime', 'Transmission Time', int)
        nUserAC = ('nUserAC', 'UAC2', str)
        nUserID = ('nUserID', 'UID2', int)
        access = ('access', 'AccessLevels', str)
        newAC = ('newAC', 'NewAC', str)

    __std_auth = [FormItems.iid, FormItems.userID, FormItems.userAC, FormItems.txTime]
    __last_upd = 20240903194700

    ptr_1a = {FormItems.pid, FormItems.iid, FormItems.dob}
    ptr_1b = {*__std_auth}
    ptr_1c = {FormItems.pid, FormItems.iid, FormItems.dob, *__std_auth}
    ptr_2  = {FormItems.pid, FormItems.iid, FormItems.dob, FormItems.pname, FormItems.diet, *__std_auth}
    ptr_3a = {FormItems.pid, FormItems.iid, FormItems.dob, FormItems.diet, *__std_auth}
    ptr_3b = {FormItems.pid, FormItems.iid, FormItems.dob, FormItems.field, FormItems.value, *__std_auth}
    ptr_4  = {FormItems.pid, FormItems.iid, FormItems.dob, *__std_auth}

    fdr_1  = {
        FormItems.name, FormItems.bld, FormItems.cat, FormItems.cal, FormItems.cst, FormItems.csu, FormItems.cfi,
        FormItems.ftr, FormItems.fsa, FormItems.pco, FormItems.pro, FormItems.ssc, FormItems.ssu, FormItems.odiets,
        *__std_auth
    }
    fdr_2  = {FormItems.field, FormItems.value, *__std_auth}
    fdr_3a = {FormItems.id, FormItems.diet, *__std_auth}
    fdr_3b = {FormItems.id, FormItems.diet, *__std_auth}
    fdr_4  = {FormItems.name, *__std_auth}
    fdr_5  = {FormItems.iid}

    urc_1a = {*__std_auth, FormItems.nUserID}
    urc_1b = {*__std_auth}
    urc_2a = {*__std_auth, FormItems.nUserID, FormItems.nUserAC, FormItems.access}
    urc_2b = {*__std_auth, FormItems.nUserID, FormItems.nUserAC}
    urc_3p = {*__std_auth, FormItems.nUserID, FormItems.access}
    urc_3r = {*__std_auth, FormItems.nUserID, FormItems.access}
    urc_4  = {*__std_auth, FormItems.nUserID, FormItems.nUserAC, FormItems.newAC}

    @staticmethod
    def last_upd() -> int:
        return Forms.__last_upd

    @staticmethod
    def get_form_items(form_name: str) -> Set[FormItems]:
        return cast(
            Set[Forms.FormItems],
            {*(getattr(Forms, form_name.replace('-', '_').lower(), []))}
        )

    @staticmethod
    def get_form_str(form_name: str, certificate: str) -> str:
        items = Forms.get_form_items(form_name)
        assert len(items), f'Could not get form items for "{form_name}"'

        fmt = '%s<{form_items}> >> {cert} >> {fud}' % form_name.ljust(6, ' ')
        items = '.'.join([f'[&{item};]' for (item, *_) in items])

        return fmt.format(**{
            'form_items':   items,
            'fud':          Forms.__last_upd,
            'cert':         certificate
        })


class NGServer(__fc_server__):
    def __init__(self, ip: str, pt_db: PTDatabase, user_db: UserDatabase, logger: Logger, *args, **kwargs) -> None:
        self.__t = __fc_thread__()
        self.__mcv__ = 20240814000000
        __fc_server__.__init__(self, (ip, Constants.TCP.PORT), self.__t, logger, *args, **kwargs)
        self.__pt_db__ = pt_db
        self.__u_db__ = user_db

        self.__loops__ = []
        (_l_task := Timer(10, self._check_r_loops)).start()
        self._l_task = _l_task

        self.__shutdown_tasks__.append(self._l_task.cancel)

        # __connectors__:   Dict[str, Tuple[__fc_thread__, socket.socket, Tuple[str, int]]]
        # __sessions__:     Dict[str, Dict[str, Any]]

        # Memoize the COM_CHK value for a faster response to the first message.
        _ = Header.HeaderUtils.get_com_chk()

    def _check_r_loops(self) -> None:
        if not self.__is_alive__:
            return

        self._l_task = Timer(10, self._check_r_loops)
        now = datetime.now()

        for i, (name, lp, start_time, brk) in enumerate(self.__loops__):
            if lp > Settings.SETTINGS.LOOP_MAX_ITER and not brk:
                self.__loops__[i][-1] = True  # Call for break.
                self.log(LoggingLevel.ERROR, f'Loop "{name}" iterated too many times (> {Settings.SETTINGS.LOOP_MAX_ITER}).')

            elif (now - start_time).total_seconds() >= (Settings.SETTINGS.LOOP_MAX_TIME_MIN * 60) and not brk:
                self.__loops__[i][-1] = True  # Call for break.
                self.log(LoggingLevel.ERROR, f'Loop "{name}" took too long (> {Settings.SETTINGS.LOOP_MAX_TIME_MIN * 60}s).')

        self.log(LoggingLevel.INFO, f'_check_r_loop done; Start<{now}>')
        self._l_task.start()

    def register_loop(self, name: str) -> int:
        self.__loops__.insert(index := len(self.__loops__), [name, 0, datetime.now(), False])
        return index

    def run(self) -> None:
        self.bind()
        self.start_listener(Constants.TCP.BKLOG)

    def _log_as_client(self, addr: Tuple[str, int], st: str | None, message: str) -> None:
        if st is None:
            self.log_sc(LoggingLevel.INFO, f'CLIENT<{addr[0]},{addr[1]}> {message}', 'NGSRV')
        else:
            self.log_sc(LoggingLevel.INFO, f'CLIENT<{addr[0]},{addr[1]} :: ST{st}> {message}', 'NGSRV')

    def _err_as_client(self, addr: Tuple[str, int], st: str | None, message: str):
        if st is None:
            self.log_sc(LoggingLevel.ERROR, f'CLIENT<{addr[0]},{addr[1]}> {message}', 'NGSRV')
        else:
            self.log_sc(LoggingLevel.ERROR, f'CLIENT<{addr[0]},{addr[1]} :: ST{st}> {message}', 'NGSRV')

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
        rx = Structs.Transmission(hdr, exh, *tx_sections[-2::])

        self._log_as_client(addr, hdr.H_SES_TOK, f'{c_name=} rx<{rx.hdr}; {rx.exh}; {rx.chk}; {rx.msg}>')
        return rx

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

        self.on_msg_capt(addr, rx.hdr.H_SES_TOK, rx.msg)

        rsa_pub_key_pem = rx.msg.lstrip(b'<EstCon>')
        vKey, S2CPubKey = self.sf_execute(
            rsa.PublicKey.load_pkcs1,
            rsa_pub_key_pem,
            'PEM'
        )
        assert vKey, f'{Constants.RESPONSES.ERRORS.BAD_REQUEST} E008   E2E-Encryption: !vPEM S2CPubKey'
        assert isinstance(S2CPubKey, rsa.PublicKey), f'{Constants.RESPONSES.ERRORS.BAD_REQUEST} E008   E2E-Encryption: !vPEM S2CPubKey'

        C2SPubKey, C2SPrivKey = Functions.GET_RSA_KEYS()
        ses_tok = self._gen_ses_tok("ST")
        cuid = uuid.uuid4().__str__()

        rsp = (
            Constants.RESPONSES.NORMAL.CONNECTION_ESTABLISHED.encode() + b' ' +
            b":DELIM:".join([ses_tok.encode(), cuid.encode(), C2SPubKey.save_pkcs1("PEM")])
        )

        rspe = Functions.BLOCK_ENCRYPT_DATA(rsp, cast(rsa.PublicKey, S2CPubKey))
        tx_data = self._create_tx(ses_tok, cuid, rspe, sf_mode=True)

        self.__sessions__[ses_tok] = {
            'C2SKey': {  # For C->S communications.
                'PrivatePEM':   C2SPrivKey.save_pkcs1('PEM'),
                'PublicPEM':    C2SPubKey.save_pkcs1('PEM'),
                'PublicCHK':    hashlib.md5(C2SPubKey.save_pkcs1('PEM')).hexdigest()
            },
            'S2CKey': {  # For S->C com
                'PublicPEM':    S2CPubKey.save_pkcs1('PEM'),
                'PublicCHK':    hashlib.md5(S2CPubKey.save_pkcs1('PEM')).hexdigest()
            },
            'ComHistory': {
                (f_com_id := self.com_hist_key(ses_tok, rx.hdr.H_TX_TIME)): (
                    rx.hdr,
                    rx.exh,
                    rx.chk,
                    rx.msg,
                    thread, addr, c_name
                ),
            },
            'ReplyHistory': {
                f_com_id: (rsp, rspe, tx_data),
            },
            'IsActive': True,
            'Attributes':
                [
                    f'{rx.hdr.H_APP_VIS=}',
                    f'{cuid=}',
                    'mode_NG',
                    f'{rx.hdr.H_COM_CHK=}',
                ],
            'Forms':
                [],
            'SecAccess':
                [],
            'fComID': f_com_id
        }

        conn.send(tx_data)

    def com_hist_key(self, st: str, tx_time: int) -> str:
        lInd = self.register_loop('com_hist_key')
        # Just go 'til Settings.SETTINGS.LOOP_MAX_ITER (managed by _check_r_loops)
        while (i := self.__loops__[lInd][1]) >= 0 and not self.__loops__[lInd][-1]:
            s = str(i).rjust(6, '0')
            if (out := f'{tx_time}-{s}') not in self.__sessions__.get(st, {}).get('ComHistory', []):
                self.__loops__[lInd][-1] = True
                return out

            self.__loops__[lInd][1] += 1

        self.__loops__[lInd][-1] = True
        raise Exception("Cannot log ComHistory entry")

    def _handle_commands(self, c_name: str, intent: str, message: bytes, hdr: Header.NGHeader) -> str:
        self.log(LoggingLevel.INFO, f'Handling command {message} w/ {intent=}')

        try:
            match intent:
                case 'ECC':
                    return self._manage_ecc(c_name, message, hdr)

                case 'RFF':
                    return self._manage_form_reply(c_name, message, hdr)

                case 'OTHER':
                    raise Exception('NotImplemented')

                case _:
                    assert False, f'Intent<{intent}>'

        except AssertionError as E:
            assert False, f'{Constants.RESPONSES.ERRORS.BAD_REQUEST} {str(E)}'

        except Exception as E:
            self.echo_traceback()
            assert False, f'{Constants.RESPONSES.ERRORS.GENERAL} Exception@_handler<{E.__class__.__name__}, {str(E)}>'

    def _generate_ecc_cert(self, form: str, client_uid: str) -> str:
        # TODO: replace w/ a cryptographic certificate, eventually.
        # temporarily: MD5(client-uid) + expiration

        base = hashlib.md5(form.encode() + client_uid.encode()).hexdigest()
        expiration = (datetime.now() + timedelta(days=2)).strftime(Constants.FRMT.DATETIME)  # you have 2 days to respond.

        return base + expiration

    def _manage_ecc(self, c_name: str, message: bytes, hdr: Header.NGHeader) -> str:
        assert message.count(b'-') == 2, 'FORMAT_ECC_COMMAND'
        assert (sfs := self.sf_execute(message.decode))[0], 'CODEC_ERROR'
        _, message = cast(Tuple[bool, str], sfs)

        command, selector, modifier = message.split('-')
        assert (command := command.strip().upper()) in ('GET', 'NEW', 'UPD', 'DEL'), f'Command<{command}>'
        assert (selector := selector.strip().upper()) in ('P', 'F', 'U'), f'Selector<{selector}>'
        assert (modifier := modifier.strip().upper()) in (
        'RCD', 'DET', 'LST', 'OMI', 'ACC', 'PSW'), f'Modifier<{modifier}>'

        # assert (fnc := getattr(self, f'_{command.lower()}', None)) is not None, f'Command<{command}>'
        # return cast(str, fnc(c_name, selector, modifier, hdr))

        ecc_map = {
            'NEW': {
                'P': {'RCD': 'PTR-2'},
                'F': {'RCD': 'FDR-1', 'OMI': 'FDR-3a', 'DET': 'FDR-4'},
                'U': {'RCD': 'URC-2a', 'ACC': 'URC-3P'},
            },
            'GET': {
                'P': {'RCD': 'PTR-1c', 'DET': 'PTR-1a', 'LST': 'PTR-1b'},
                'F': {'LST': 'FDR-5', 'DET': 'FDR-5'},
                'U': {'RCD': 'URC-1a', 'LST': 'URC-1b'},
            },
            'UPD': {
                'P': {'DET': 'PTR-3a', 'RCD': 'PTR-3b'},
                'F': {'RCD': 'FDR-2'},
                'U': {'PSW': 'URC-4'},
            },
            'DEL': {
                'P': {'RCD': 'PTR-4'},
                'F': {'OMI': 'FDR-3b'},
                'U': {'RCD': 'URC-2b', 'ACC': 'URC-3R'},
            }
        }

        assert (form := ecc_map.get(command, {}).get(selector, {}).get(modifier)) is not None, \
            f'ECC.Command<{command}> ECC.Selector<{selector}> ECC.Modifier<{modifier}>'
        self.__sessions__[hdr.H_SES_TOK]['Forms'] = [
            *self.__sessions__[hdr.H_SES_TOK].get('Forms', []),
            (form, cert := self._generate_ecc_cert(hdr.H_CLT_UID, form))
        ]

        return Forms.get_form_str(form, cert)

    def _manage_form_reply(self, c_name: str, msg: bytes, hdr: Header.NGHeader) -> str:
        vsl = len(vs := str(Forms.last_upd()))
        msg = msg.strip()

        assert msg.count(fDelim := b'>>') == 2, 'E000 fSect<3>'
        fsect = msg.split(fDelim)
        fsect = [s.strip() for s in fsect][-3::]
        assert not sum(e := [1 if not len(s) else 0 for s in fsect]), f'E001 fFill {e}'
        body, cert, fud = fsect

        assert len(body) > 6, f'E002a fIDL'
        assert body.endswith(b'>'), f'E002a-2 fID-E'
        assert len(cert) == (32 + Constants.SZ.DATETIME), f'E002b fCertL'
        assert len(fud) == vsl, f'E002c fFUDL'
        assert fud.decode() == vs, f'E002c-2 fFUDc'

        form_id = body[:6].strip().decode()
        forms_sent = self.__sessions__[hdr.H_SES_TOK].get('Forms', [])
        t = ()

        self.log(LoggingLevel.INFO, f'RFF-CHECK: Comparing against {forms_sent=}')
        assert len(forms_sent), 'E003-0 CERTIFICATE_ERROR'
        for form_sent, cert_sent in forms_sent:
            if (form_sent == form_id) and (cert_sent == cert.decode()):
                t = (form_sent, cert_sent)

        assert len(t) == 2, ' E003-2 CERTIFICATE_ERROR'
        # assert (t := (form_id, e_cert)) in self.__sessions__[hdr.H_SES_TOK].get('Forms', []), 'E003-2 CERTIFICATE_ERROR'

        self.log(LoggingLevel.INFO, f'RFF-CHECK: Successfully verified RFF req w/ {form_id=} cert={t[-1]}')
        self.__sessions__[hdr.H_SES_TOK]['Forms'].pop(self.__sessions__[hdr.H_SES_TOK]['Forms'].index(t))

        return 'NotImplemented'

    def _con_conn(self, c_name: str, hdr: Header.NGHeader, recv: bytes) -> None:
        thread, conn, addr = self.__connectors__[c_name]

        s, rx = self.sf_execute(self._get_tx, c_name, hdr, recv)
        assert s and isinstance(rx, Structs.Transmission), \
            f'{Constants.RESPONSES.ERRORS.GENERAL} E001   Could not load Rx struct. Recv<{hdr, recv}>'

        assert rx.hdr.MSGINTENT == 'C', f'{Constants.RESPONSES.ERRORS.BAD_HEADER} MSGINTENT'

        assert (si := self.__sessions__[rx.hdr.H_SES_TOK]) is not None, f'{Constants.RESPONSES.ERRORS.INVALID_SESSION_ID} SESTOK'
        assert f'cuid=\'{rx.hdr.H_CLT_UID}\'' in si['Attributes'], f'{Constants.RESPONSES.ERRORS.INVALID_SESSION_ID} CUID'
        assert (pkchk := si.get('C2SKey', {}).get('PublicCHK')) is not None, f'{Constants.RESPONSES.ERRORS.INVALID_SESSION_ID} PKCHK'
        assert pkchk == rx.exh.EXH_KEY_MD5, f'{Constants.RESPONSES.ERRORS.INVALID_SESSION_ID} PKCHK'
        assert si['IsActive'], f'{Constants.RESPONSES.ERRORS.INVALID_SESSION_ID} Session deactivated.'

        assert f'{rx.hdr.H_APP_VIS=}' in si["Attributes"], f'{Constants.RESPONSES.ERRORS.INCOMPATIBLE_VERSION} E-001A'
        assert f'{rx.hdr.H_COM_CHK=}' in si["Attributes"], f'{Constants.RESPONSES.ERRORS.INCOMPATIBLE_VERSION} E-001B'
        assert rx.hdr.H_MC_TYPE == 1, f'{Constants.RESPONSES.ERRORS.BAD_TRANSMISSION} E-002 Send from client.'

        fcom_exh = si['ComHistory'][si['fComID']][1]
        assert fcom_exh.EXH_MACHINE == rx.exh.EXH_MACHINE, f'{Constants.RESPONSES.ERRORS.BAD_REQUEST} E-003A'
        assert fcom_exh.EXH_PLATFORM == rx.exh.EXH_PLATFORM, f'{Constants.RESPONSES.ERRORS.BAD_REQUEST} E-003B'
        assert fcom_exh.EXH_MAC_ADDR == rx.exh.EXH_MAC_ADDR, f'{Constants.RESPONSES.ERRORS.BAD_REQUEST} E-003C'

        assert len(mh := hashlib.sha256(rx.msg).hexdigest()) == 64, f'{Constants.RESPONSES.ERRORS.BAD_TRANSMISSION} E-004A {mh}'
        assert mh == rx.chk, f'{Constants.RESPONSES.ERRORS.BAD_TRANSMISSION} E-004B {mh}'

        assert (sd := self.sf_execute(rsa.PrivateKey.load_pkcs1, si['C2SKey']['PrivatePEM'], 'PEM'))[0], f'{Constants.RESPONSES.ERRORS.GENERAL} E-006 (fatal)'
        _, priv_c2s_key = sd
        assert (sd := self.sf_execute(rsa.PublicKey.load_pkcs1, si['S2CKey']['PublicPEM'], 'PEM'))[0], f'{Constants.RESPONSES.ERRORS.GENERAL} E-006b (fatal)'
        _, pub_s2c_key = sd
        assert (sd1 := self.sf_execute(Functions.BLOCK_DECRYPT_DATA, data=rx.msg, private_key=priv_c2s_key))[0], f'{Constants.RESPONSES.ERRORS.BAD_REQUEST} E-007'
        _, dec_msg = sd1

        self.on_msg_capt(addr, rx.hdr.H_SES_TOK, dec_msg)
        assert len(dec_msg) >= 4, f'{Constants.RESPONSES.ERRORS.BAD_REQUEST} E-005A'
        assert (intent := dec_msg[:4].strip().decode()) in ('ECC', 'RFF', ''), f'{Constants.RESPONSES.ERRORS.BAD_REQUEST} E-005B {intent=}'

        if intent == '':
            intent = 'OTHER'

        self.__sessions__[rx.hdr.H_SES_TOK]['ComHistory'][key := self.com_hist_key(rx.hdr.H_SES_TOK, rx.hdr.H_TX_TIME)] = (
            rx.hdr,
            rx.exh,
            rx.chk,
            rx.msg,
            thread, addr, c_name,
            {
                'intent': intent,
                'dec_msg': dec_msg
            }
        )

        rsp = "" + self._handle_commands(c_name, intent, dec_msg[4::], rx.hdr)
        rspe = Functions.BLOCK_ENCRYPT_DATA(rsp.encode(), pub_s2c_key)
        tx_data = self._create_tx(rx.hdr.H_SES_TOK, rx.hdr.H_CLT_UID, rspe, sf_mode=True)
        self._log_as_client(addr, rx.hdr.H_SES_TOK, f'{c_name=} Send<{rsp}>')
        self.__sessions__[rx.hdr.H_SES_TOK]['ReplyHistory'][key] = (rsp, rspe, tx_data)

        conn.send(tx_data)

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
        conn.close()

    def _shutdown(self) -> None:
        # Shutdown tasks
        # Log sessions
        self.log_sessions()
