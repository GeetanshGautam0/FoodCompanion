import hashlib, platform, uuid
from .enum import H_TYPE, H_PAD_MODE
from .struct import H_ITEM, LegacyHeader, NGHeader, ExtendedHeader
from .constants import SZ, HDR, FRMT
from .appinfo import APPINFO
from .functions import memoize
from typing import Tuple, List, Dict, Union
from datetime import datetime


class NGHeaderItems:
    # Message Intent
    #   C: Continue a session
    #   S: Create a new session
    MSGINTENT = H_ITEM('MSGINTENT', H_TYPE.STR, 1, 0, H_PAD_MODE.NONE)

    # App Version Info String
    #   14-character, base-10 app version (date + time of app compilation)
    H_APP_VIS = H_ITEM('H_APP_VIS', H_TYPE.INT, SZ.DATETIME, (MSGINTENT.INDEX + MSGINTENT.SIZE), H_PAD_MODE.NONE)

    # Hash to validate the communication specification.
    #   32-character, hex string (concat MD5 of _template, _legacy, _ng)
    H_COM_CHK = H_ITEM('H_COM_CHK', H_TYPE.STR, 32 * 3, (H_APP_VIS.INDEX + H_APP_VIS.SIZE), H_PAD_MODE.NONE)

    # Header Version
    #   3-character, hexadecimal (base-16) header version
    H_HDR_VER = H_ITEM('H_HDR_VER', H_TYPE.STR, 3, (H_COM_CHK.INDEX + H_COM_CHK.SIZE), H_PAD_MODE.PREPEND)

    # Machine Type
    #   1: Client
    #   0: Server
    H_MC_TYPE = H_ITEM('H_MC_TYPE', H_TYPE.BIT, 1, (H_HDR_VER.INDEX + H_HDR_VER.SIZE), H_PAD_MODE.NONE)

    # Session Token
    #   Session token sent by the server.
    #   If creating a new session, pad w/ 0
    H_SES_TOK = H_ITEM('H_SES_TOK', H_TYPE.STR, SZ.HDR_SESSION_TOKEN, (H_MC_TYPE.INDEX + H_MC_TYPE.SIZE), H_PAD_MODE.NONE)

    # Message Transmit Time
    #   Time when the message was sent. Use the 14-character base-10 datetime format
    H_TX_TIME = H_ITEM('H_TX_TIME', H_TYPE.INT, SZ.DATETIME, (H_SES_TOK.INDEX + H_SES_TOK.SIZE), H_PAD_MODE.NONE)

    # Client UID
    #   Client UID sent by server (to verify session).
    H_CLT_UID = H_ITEM('H_CLT_UID', H_TYPE.STR, 34, (H_TX_TIME.INDEX + H_TX_TIME.SIZE), H_PAD_MODE.NONE)

    # Message Length
    #   Length of message transmitted.
    #   Hexadecimal (base-16)
    H_MSG_LEN = H_ITEM('H_MSG_LEN', H_TYPE.STR, SZ.MSG_LEN_DESCRIPTOR, (H_CLT_UID.INDEX + H_CLT_UID.SIZE), H_PAD_MODE.PREPEND)

    # Message Hash Length
    #   Length of message hash appended after the extended header.
    #   Hexadecimal (base-16)
    H_HSH_LEN = H_ITEM('H_HSH_LEN', H_TYPE.STR, SZ.MSG_LEN_DESCRIPTOR, (H_MSG_LEN.INDEX + H_MSG_LEN.SIZE), H_PAD_MODE.PREPEND)

    # Extended header length
    #   Length of the extended header
    #   Hexadecimal (base-16)
    EXT_HDR_L = H_ITEM('EXT_HDR_L', H_TYPE.STR, 3, (H_HSH_LEN.INDEX + H_HSH_LEN.SIZE), H_PAD_MODE.PREPEND)

    @staticmethod
    def items() -> List[H_ITEM]:
        return [
            NGHeaderItems.MSGINTENT,
            NGHeaderItems.H_APP_VIS,
            NGHeaderItems.H_COM_CHK,
            NGHeaderItems.H_HDR_VER,
            NGHeaderItems.H_MC_TYPE,
            NGHeaderItems.H_SES_TOK,
            NGHeaderItems.H_TX_TIME,
            NGHeaderItems.H_CLT_UID,
            NGHeaderItems.H_MSG_LEN,
            NGHeaderItems.H_HSH_LEN,
            NGHeaderItems.EXT_HDR_L,
        ]

    @staticmethod
    def name_item_map() -> Dict[str, H_ITEM]:
        yield {item.NAME: item for item in NGHeaderItems.items()}

    @staticmethod
    def header_length() -> int:
        return sum([i.SIZE for i in NGHeaderItems.items()])


class ExtendedHeaderItems:
    # Platform ID of client/server
    #   platform.platform()
    EXH_PLATFORM = H_ITEM('EXH_PLATFORM', H_TYPE.STR, -1, -1, H_PAD_MODE.NONE)

    # Machine type
    #   platform.machine()
    EXH_MACHINE = H_ITEM('EXH_MACHINE', H_TYPE.STR, -1, -1, H_PAD_MODE.NONE)

    # Machine Mac Address
    #   hashlib.md5(uuid.getnode()).hexdigest()
    EXH_MAC_ADDR = H_ITEM('EXH_MAC_ADDR', H_TYPE.STR, -1, -1, H_PAD_MODE.NONE)

    # Public Key MD5 Hash
    EXH_KEY_MD5 = H_ITEM('EXH_KEY_MD5', H_TYPE.STR, -1, -1, H_PAD_MODE.NONE)

    @staticmethod
    def items() -> List[H_ITEM]:
        return [
            ExtendedHeaderItems.EXH_PLATFORM,
            ExtendedHeaderItems.EXH_MACHINE,
            ExtendedHeaderItems.EXH_MAC_ADDR,
            ExtendedHeaderItems.EXH_KEY_MD5,
        ]

    @staticmethod
    def name_item_map() -> Dict[str, H_ITEM]:
        yield {item.NAME: item for item in ExtendedHeaderItems.items()}


class LegacyHeaderItems:
    #                | Name         | Type     | Size                   | Start Index                         |  Padding Mode
    #                ---------------------------------------------------------------------------------------------------------
    H_TX_TIME = H_ITEM('H_TX_TIME', H_TYPE.INT, SZ.DATETIME,            0,                                      H_PAD_MODE.NONE)
    H_MC_TYPE = H_ITEM('H_MC_TYPE', H_TYPE.BIT, 1,                      (H_TX_TIME.INDEX + H_TX_TIME.SIZE),     H_PAD_MODE.NONE)
    H_SES_TOK = H_ITEM('H_SES_TOK', H_TYPE.STR, SZ.HDR_SESSION_TOKEN,   (H_MC_TYPE.INDEX + H_MC_TYPE.SIZE),     H_PAD_MODE.NONE)
    H_APP_VIS = H_ITEM('H_APP_VIS', H_TYPE.INT, SZ.DATETIME,            (H_SES_TOK.INDEX + H_SES_TOK.SIZE),     H_PAD_MODE.NONE)
    H_MSG_LEN = H_ITEM('H_MSG_LEN', H_TYPE.INT, SZ.MSG_LEN_DESCRIPTOR,  (H_APP_VIS.INDEX + H_APP_VIS.SIZE),     H_PAD_MODE.PREPEND)

    @staticmethod
    def items() -> List[H_ITEM]:
        return [
            # NOTE: The order in which the following items are listed is the order they will be in
            #       in the final header.

            LegacyHeaderItems.H_TX_TIME,
            LegacyHeaderItems.H_MC_TYPE,
            LegacyHeaderItems.H_SES_TOK,
            LegacyHeaderItems.H_APP_VIS,
            LegacyHeaderItems.H_MSG_LEN
        ]

    @staticmethod
    def name_item_map() -> Dict[str, H_ITEM]:
        yield {item.NAME: item for item in LegacyHeaderItems.items()}

    @staticmethod
    def header_length() -> int:
        return sum([i.SIZE for i in NGHeaderItems.items()])


class _NGHeader:
    @staticmethod
    def load_from_bytes(__bytes: bytes) -> NGHeader:
        raise NotImplemented

    @staticmethod
    def load_exh_from_bytes(__bytes: bytes) -> ExtendedHeader:
        raise NotImplemented

    @staticmethod
    def create_bytes(__ngh: NGHeader, __exh: ExtendedHeader, __hash: str) -> Tuple[bytes, bytes]:
        # Returns header, hash
        exh_delim = '<EXH_DELIM>'
        exh_null = '<EXH_NO_DATA>'

        # TODO: create EXH bytes, compute length, and finally use that as opposed to __ngh.EXT_HDR_L.
        raise NotImplemented


class _LegacyHeader:
    @staticmethod
    def load_from_bytes(__bytes: bytes, __padding: bytes) -> LegacyHeader:
        raise NotImplemented

    @staticmethod
    def create_bytes(__header: LegacyHeader) -> bytes:
        _hdr_data = {
            # NOTE: The order in which the following items are listed is the order they will be in
            #       in the final header.

            'H_TX_TIME': (__header.H_TX_TIME, LegacyHeaderItems.H_TX_TIME),
            'H_MC_TYPE': (__header.H_MC_TYPE, LegacyHeaderItems.H_MC_TYPE),
            'H_SES_TOK': (__header.H_SES_TOK, LegacyHeaderItems.H_SES_TOK),
            'H_APP_VIS': (__header.H_APP_VIS, LegacyHeaderItems.H_APP_VIS),
            'H_MSG_LEN': (__header.H_MSG_LEN, LegacyHeaderItems.H_MSG_LEN),
        }

        assert len(_hdr_data) == len(LegacyHeaderItems.items()), \
            'Function ncom.sc_data.header.create_bytes not up to date.'

        def _ass(__data: Union[int, bool, str, bytes], __item: H_ITEM) -> bytes:
            padding = HDR.PAD_BYTE

            dout: bytes
            draw: bytes

            match __item.TYPE:
                case H_TYPE.INT:
                    assert isinstance(__data, int)
                    draw = str(__data).encode()

                case H_TYPE.STR:
                    assert isinstance(__data, (str, bytes))
                    if isinstance(__data, str):
                        draw = __data.encode()
                    else:
                        draw = __data

                case H_TYPE.BIT:
                    assert isinstance(__data, (bool, int))
                    draw = b'1' if __data else b'0'

                case _:
                    raise TypeError("Unexpected H_TYPE.")

            if __item.PAD == H_PAD_MODE.NONE:
                assert len(draw) == __item.SIZE
                dout = draw

            else:
                assert len(draw) <= __item.SIZE
                dout = HeaderUtils.pad(draw, __item.SIZE, padding, __item.PAD)

            return dout

        return b''.join([_ass(hd, hi) for (hd, hi) in _hdr_data.values()])


class HeaderUtils:

    @staticmethod
    def pad(__data: bytes, __size: int, _pb: bytes, _pm: H_PAD_MODE) -> bytes:
        assert len(__data) <= __size
        assert _pm is not H_PAD_MODE.NONE

        match _pm:
            case H_PAD_MODE.PREPEND:
                return (_pb * (__size - len(__data))) + __data

            case H_PAD_MODE.APPEND:
                return __data + (_pb * (__size - len(__data)))

            case _:
                raise ValueError('Invalid padding mode.')

    @staticmethod
    def create_legacy_bytes(__message: bytes | str, __session_token: str, __is_server: bool) -> bytes:
        _time = datetime.now().strftime(FRMT.DATETIME)

        return _LegacyHeader.create_bytes(
                LegacyHeader(
                    int(_time),
                    __is_server,
                    __session_token,
                    APPINFO.APP_VERSION,
                    len(__message)
                )
        )

    @staticmethod
    def load_legacy_header(__hdr_bytes: bytes, __padding: bytes) -> LegacyHeader:
        return _LegacyHeader.load_from_bytes(__hdr_bytes, __padding)

    @staticmethod
    def create_ng_bytes(
            __intent: str,
            __tx_is_server: bool,
            __message: bytes | str,
            __session_token: str,
            __client_uid: str,
            __public_key: bytes | None,
    ) -> Tuple[bytes, bytes]:  # Returns NGHeader+EXH, TX_CHK
        assert __intent in ('C', 'S')

        mc_type = str(int(not __tx_is_server))  # 1: Client, 0: Server
        hdr_ver = 1
        hash_s = hashlib.sha256(__message.encode() if isinstance(__message, str) else __message).hexdigest()
        time = int(datetime.now().strftime(FRMT.DATETIME))

        extended_header = ExtendedHeader(
            EXH_PLATFORM=platform.platform(),
            EXH_MACHINE=platform.machine(),
            EXH_MAC_ADDR=hashlib.md5(uuid.getnode()).hexdigest(),
            EXH_KEY_MD5=(None if __public_key is None else hashlib.md5(__public_key).hexdigest())
        )

        ng_header = NGHeader(
            MSGINTENT=__intent,
            H_APP_VIS=APPINFO.APP_VERSION,
            H_COM_CHK=HeaderUtils.get_com_chk(),
            H_HDR_VER=hdr_ver,
            H_MC_TYPE=mc_type,
            H_SES_TOK=__session_token,
            H_TX_TIME=time,
            H_CLT_UID=__client_uid,
            H_MSG_LEN=len(__message),
            H_HSH_LEN=len(hash_s),
            EXT_HDR_L=-1
        )

        return _NGHeader.create_bytes(ng_header, extended_header, hash_s)

    @staticmethod
    def load_ng_header(__hdr_bytes: bytes) -> NGHeader:
        return _NGHeader.load_from_bytes(__hdr_bytes)

    @staticmethod
    def load_exh(__exh_bytes: bytes) -> ExtendedHeader:
        return _NGHeader.load_exh_from_bytes(__exh_bytes)

    @staticmethod
    @memoize
    def get_com_chk() -> str:
        def get_file_hash(file_name: str) -> str:
            with open(file_name, 'rb') as iFile:
                h = hashlib.md5(iFile.read()).hexdigest()
                iFile.close()

            return h

        _template = get_file_hash('sc_server/_template.py')
        _legacy = get_file_hash('sc_server/legacy.py')
        _ng = get_file_hash('sc_server/ng.py')

        return _template + _legacy + _ng
