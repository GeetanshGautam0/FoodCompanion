"""
sys
os
traceback
typing.cast

sc_data:
    Constants
    ConstantClass
    Functions
    Enums
    Structs
    Settings
    Header
    AppInfo

sc_db:
    JSONDatabase
    SQLDatabase
    TABLE_DESCRIPTORS

New methods/functions/classes:
    (class) PTDatabase
"""
import sqlite3, sys, os
import traceback

from sc_data import *
from sc_db import *

from typing import (
    cast,
    List, Tuple, Set,
    Dict,
    Type,
    Any,
    Callable
)

from enum import Enum
from dataclasses import dataclass

ConstantClass = Constants.Constants


@dataclass
class ServerData(ConstantClass):
    logger: Logger
    patient_database: PTDatabase
    user_database: UserDatabase
    shutdown_tasks: List[Callable[[], Any]]


def stdout(__data: str, __pr: str = "") -> int:
    return Functions.STDOUT(__data, __pr)


def stderr(__data: str, __pr: str = "") -> int:
    return Functions.STDERR(__data, __pr)


class DummyLogger:
    log = lambda *_, **__: 'DummyLogger'


def echo_traceback(logger: Logger | DummyLogger) -> None:
    lines = traceback.format_exc().split('\n')
    tb = '\n'.join([f' {("%d" % (i + 1)).ljust(len(f"{len(lines) + 1}"))}  | {l}' for i, l in enumerate(lines)])

    logger.log(LoggingLevel.ERROR, f'Exception ignored:\n{tb}'.strip())


def sf_execute(logger: Logger | DummyLogger, fnc, *args, **kwargs) -> Tuple[bool, Any]:
    """
    Runs `fnc` and captures any errors.

    Note: any KWARGS prepended w/ sfe_ will be treated as arguments for sf_execute

    :param logger: Logger instance.
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
            echo_traceback(logger)

        return False, E
