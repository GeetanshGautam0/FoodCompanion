from .constants import Constants
from .appinfo import APPINFO
from dataclasses import dataclass


@dataclass
class Settings(Constants):
    SRVC_CLT_PROMPT_IP:                 bool

    SRVC_TCP_DEFAULT_RCV_LEN:           int
    SRVC_TCP_MAX_CONCUR_CONN:           int
    SRVC_TCP_SELECT_TIMEOUT:            int

    # Logging Settings
    LG_INTERVAL:                        int
    LG_LOG_ERROR:                       bool
    LG_LOG_WARN:                        bool
    LG_LOG_INFO:                        bool
    LG_LOG_DEBUG:                       bool


SETTINGS = Settings(
    SRVC_CLT_PROMPT_IP=APPINFO.SRVC_CLT_PROMPT_IP,
    SRVC_TCP_DEFAULT_RCV_LEN=APPINFO.SRVC_TCP_DEFAULT_RCV_LEN,
    SRVC_TCP_MAX_CONCUR_CONN=APPINFO.SRVC_TCP_MAX_CONCUR_CONN,
    SRVC_TCP_SELECT_TIMEOUT=APPINFO.SRVC_TCP_SELECT_TIMEOUT,
    LG_INTERVAL=APPINFO.LG_INTERVAL,
    LG_LOG_ERROR=APPINFO.LG_LOG_ERROR,
    LG_LOG_WARN=APPINFO.LG_LOG_WARN,
    LG_LOG_INFO=APPINFO.LG_LOG_INFO,
    LG_LOG_DEBUG=APPINFO.LG_LOG_DEBUG,
)

