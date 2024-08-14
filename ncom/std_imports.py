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


def stdout(__data: str, __pr: str = "") -> int:
    return sys.stdout.write(f'[{__name__}%s{__pr}] {__data}\n' % (' ' if len(__pr) else ''))


def stderr(__data: str, __pr: str = "") -> int:
    return sys.stderr.write(f'[{__name__}%s{__pr}] {__data}\n' % (' ' if len(__pr) else ''))

