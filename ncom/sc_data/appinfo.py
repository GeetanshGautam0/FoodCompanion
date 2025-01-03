import appdirs
from typing import cast
from .constants import Constants
from dataclasses import dataclass


@dataclass
class AppInfo(Constants):
    # Config Items
    APP_VERSION:                int

    SRVC_CLT_PROMPT_IP:         bool
    SRVC_TCP_DEFAULT_RCV_LEN:   int
    SRVC_TCP_MAX_CONCUR_CONN:   int
    SRVC_TCP_SELECT_TIMEOUT:    int
    COST_TIMER:                 float

    LOG_TRANSMISSIONS: bool
    LG_INTERVAL: int
    LG_LOG_ERROR: bool
    LG_LOG_WARN: bool
    LG_LOG_INFO: bool
    LG_LOG_DEBUG: bool

    LOOP_MAX_TIME_MIN: float
    LOOP_MAX_ITER:     int

    # Additional Items
    APP_DATA_PATH:              str


with open('ncom.config', 'r') as __config_file:
    __tp_map = {
        '<INT': int,
        '<STR': str,
        '<BYTES': lambda x: str(x).encode(),
        '<BOOL': lambda x: True if int(x) else False,
        '<FLOAT': float
    }

    __config_items = {

            l.split('=')[0].split('>')[-1].strip():
            __tp_map.get(l.split('>')[0], lambda x: x)(
                l.replace(f"{l.split('=')[0]}=", '', 1).strip()
            )

        for l in __config_file.readlines()
        if len(l.strip()) and not l.strip().startswith('#')
    }

__additional_items = {
    'APP_DATA_PATH': appdirs.user_data_dir('Food Companion', 'Geetansh Gautam', str(__config_items['VIS']), False)
}


# Automatically load all config items into an IMMUTABLE-DATACLASS struct.
APPINFO = AppInfo(*__config_items.values(), *__additional_items.values())
