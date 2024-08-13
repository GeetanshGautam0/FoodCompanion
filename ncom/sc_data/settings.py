from .constants import Constants
from .appinfo import APPINFO
from dataclasses import dataclass


@dataclass
class Settings(Constants):
    SRVC_CLT_PROMPT_IP:                 bool

    SRVC_TCP_DEFAULT_RCV_LEN:           int
    SRVC_TCP_MAX_CONCUR_CONN:           int
    SRVC_TCP_SELECT_TIMEOUT:            int


SETTINGS = Settings(
    SRVC_CLT_PROMPT_IP=APPINFO.SRVC_CLT_PROMPT_IP,
    SRVC_TCP_DEFAULT_RCV_LEN=APPINFO.SRVC_TCP_DEFAULT_RCV_LEN,
    SRVC_TCP_MAX_CONCUR_CONN=APPINFO.SRVC_TCP_MAX_CONCUR_CONN,
    SRVC_TCP_SELECT_TIMEOUT=APPINFO.SRVC_TCP_SELECT_TIMEOUT,
)

