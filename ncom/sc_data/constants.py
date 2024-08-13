import socket
from typing import Any, Dict
from dataclasses import dataclass


class Constants:
    class ConstantReassignmentError(Exception):
        pass

    def __setattr__(self, name, value) -> None:
        if self.__dict__.get(name) is not None:
            raise self.ConstantReassignmentError(f'Cannot reassign value of "{name}"')

        self.__dict__[name] = value

    @property
    def name_value_map(self) -> Dict[str, Any]:
        return self.__dict__


# Size Constants
@dataclass
class SZ_t(Constants):

    HDR_HASH:               int
    HDR_SESSION_TOKEN:      int
    APP_VERSION:            int
    MSG_LEN_DESCRIPTOR:     int
    DATETIME:               int
    DATE:                   int
    TIME:                   int


SZ = SZ_t(
    MSG_LEN_DESCRIPTOR=6,
    HDR_SESSION_TOKEN=32,
    APP_VERSION=6,
    HDR_HASH=64,
    DATETIME=14,
    DATE=8,
    TIME=6,
)


# Date/Time Format
@dataclass
class FRMT_t(Constants):
    TIME:               str
    DATE:               str
    DATETIME:           str


FRMT = FRMT_t(
    TIME='%H%M%S',
    DATE='%Y%m%d',
    DATETIME='%Y%m%d%H%M%S'
)


# Header
@dataclass
class HDR_t(Constants):
    RSA_KEY_TYPE:           str
    PAD_BYTE:               bytes


HDR = HDR_t(
    RSA_KEY_TYPE='PEM',
    PAD_BYTE=b'='
)


# Message
@dataclass
class MSG_t(Constants):
    NEW_CONNECTION_CODE:    bytes
    DELIMITER_BYTE:         bytes


MSG = MSG_t(
    NEW_CONNECTION_CODE=b'<EstCon>',
    DELIMITER_BYTE=b'~'
)


# Responses
@dataclass
class RERR_t(Constants):
    GENERAL:                str
    BAD_HEADER:             str
    BAD_REQUEST:            str
    BAD_TRANSMISSION:       str
    RECORD_NOT_FOUND:       str
    INVALID_SESSION_ID:     str
    INCOMPLETE_MESSAGE:     str
    INCOMPATIBLE_VERSION:   str


@dataclass
class RNRM_t(Constants):
    CONNECTION_ESTABLISHED: str
    OKAY:                   str


@dataclass
class RESP_t(Constants):
    ERRORS: RERR_t
    NORMAL: RNRM_t


T_RERR = RERR_t(
    GENERAL='ERR.GNRL',
    BAD_HEADER='ERR.HEDR',
    BAD_REQUEST='ERR.RQST',
    RECORD_NOT_FOUND='ERR.RCNF',
    BAD_TRANSMISSION='ERR.TRNS',
    INVALID_SESSION_ID='ERR.SESS',
    INCOMPLETE_MESSAGE='ERR.INCM',
    INCOMPATIBLE_VERSION='ERR.CAVR'
)


T_RNRM = RNRM_t(
    CONNECTION_ESTABLISHED='RSP.CEST',
    OKAY='RSP.OKAY'
)

RESPONSES = RESP_t(T_RERR, T_RNRM)


# Networking
@dataclass
class TCP_t(Constants):
    SIP:    str
    CIP:    str
    PORT:   int
    L_PORT: int
    S_TOUT: float
    BKLOG:  int


TCP = TCP_t(
    SIP='0.0.0.0',
    CIP=socket.gethostbyname(socket.gethostname()),
    PORT=5005,
    L_PORT=12345,
    S_TOUT=0.5,
    BKLOG=20,                                               # Allow up to 20 connections in the backlog.
)

