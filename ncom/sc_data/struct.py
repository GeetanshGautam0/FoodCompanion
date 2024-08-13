import os.path

from .enum import *
from .constants import SZ, Constants
from dataclasses import dataclass
from typing import List, Tuple

from datetime import datetime


# Transmission
@dataclass
class H_ITEM:
    NAME:   str
    TYPE:   H_TYPE
    SIZE:   int
    INDEX:  int
    PAD:    H_PAD_MODE


@dataclass
class LegacyHeader:
    H_TX_TIME: int
    H_MC_TYPE: bool
    H_SES_TOK: str
    H_APP_VIS: int
    H_MSG_LEN: int


@dataclass
class NGHeader:
    MSGINTENT: str  # 1-char        'C' or 'S'
    H_APP_VIS: int  # 14-char
    H_COM_CHK: str  # 32-char
    H_HDR_VER: int  # -> Hex Str    3-char
    H_MC_TYPE: str  # 1-char        '0' or '1'
    H_SES_TOK: str  # 32-char
    H_TX_TIME: int  # 14-char
    H_CLT_UID: str  # 34-char
    H_MSG_LEN: int  # -> Hex Str    6-char
    H_HSH_LEN: int  # -> Hex Str    6-char
    EXT_HDR_L: int  # -> Hex Str    3-char


@dataclass
class ExtendedHeader:           # Only used by clients.
    EXH_PLATFORM: str           # platform.platform()
    EXH_MACHINE:  str           # platform.machine()
    EXH_MAC_ADDR: str           # hashlib.md5(uuid.getnode()).hexdigest()
    EXH_KEY_MD5:  str | None    # public key MD5 hash.


@dataclass
class Transmission:
    hdr:    NGHeader | LegacyHeader
    exh:    ExtendedHeader | None       # Servers do not send an EXH
    chk:    str                         # Message hash
    msg:    bytes


# Food
@dataclass
class Carbohydrates:
    starches:       float
    fiber:          float
    sugars:         float


@dataclass
class Fats:
    trans:          float
    saturated:      float


@dataclass
class Macro:
    carbohydrates:  Carbohydrates
    proteins:       float
    fats:           Fats


@dataclass
class DietOrder:
    id:             int
    name:           str


@dataclass
class ServingSize:
    count:          float
    unit:           ServingSizeUnit


@dataclass
class Food:
    id:             int
    name:           str
    category:       FoodCategory
    serving_size:   ServingSize

    calories:       float
    macros:         Macro

    allowed_diets:  List[DietOrder]
    meals:          List[Meal]


@dataclass
class SQLColumn:
    column_name:    str
    type:           SQLType
    flags:          List[SQLFlags]

    @property
    def check(self) -> bool:
        self.column_name = self.column_name.strip()

        return bool(len(self.column_name)) & isinstance(self.type, SQLType)

    @property
    def name(self) -> str:
        return self.column_name

    @property
    def as_string(self) -> str:
        assert self.check

        lowercase_type_names = [SQLType.TEXT]
        type_name = self.type.name if self.type not in lowercase_type_names else self.type.name.lower()
        flags_list = ' '.join(f.name.replace('_', ' ') for f in self.flags).strip()

        if len(flags_list):
            type_name = f'{type_name} {flags_list}'

        return f'{self.name} {type_name}'


@dataclass
class _lck_sql_tbl_desc(Constants):
    table_name: str
    columns: List[SQLColumn]


class SQLTableDescriptor:
    def __init__(self, table_name: str, columns: List[SQLColumn]):
        self.__attr__ = ()

        table_name = table_name.strip()
        columns = [c for c in columns if isinstance(c, SQLColumn)]  # Make sure only valid entries are left.
        columns = [c for c in columns if c.check]  # Make sure only valid entries are left.

        # Save attributes
        self.__in__ = (table_name, columns)
        self.__attr__ = (*self.__attr__, f'c{ "1" if bool(len(columns)) & bool(len(table_name)) else "0"}')

        # Generate a locked (immutable) descriptor
        self.__locked__ = _lck_sql_tbl_desc(*self.__in__)

    @property
    def table_name(self):
        return self.__locked__.table_name

    @property
    def columns(self):
        return self.__locked__.columns

    @property
    def check(self):
        return 'c1' in self.__attr__

    @property
    def format_columns(self) -> str:
        assert self.check

        as_str = [c.as_string for c in self.columns]
        f = as_str.pop()

        # o = (('\t%s,\n' % ',\n\t'.join(as_str)) + f) if len(as_str) else f
        o = (('%s, ' % ', '.join(as_str)) + f) if len(as_str) else f

        return o


# Backend
class File:
    def __init__(self, file_path: str, mode: str = 'f', *_, **__) -> None:
        """
        Cases handled:
            1. No path; only file/dir name
            2. Relative paths ('.\\')
            3. Absolute paths
            4. Files with or without an extension.

        Properties:
            1. file_path    Absolute path to file/dir
            2. file_name    Name of file (w/ ext if applicable) or dir
            3. extension    Complete extension of file name (starts w/ '.', includes ALL extensions)
            4. file_type    Type of file (last extension as an uppercase string; if no extension then returns None)
            5. mode         Returns FileMode.FILE or FileMode.DIR
            6. full_path    Complete path of file/dir.

        :param file_path:   Path to file/dir OR file/dir name
        :param mode:        Mode to operate in; accepts 'f' or 'd' for FILE and DIR modes, respectively.

        :returns: None
        """

        self.__m  = mode
        self.__fp = file_path

        self.__efd: str
        self.__efn: str
        self.__ext: str
        self.__eft: str

        self._run_tasks()

    def _run_tasks(self) -> None:
        self.__fp = self.__fp.strip()
        assert len(self.__fp)
        assert self.__m.upper() in ('F', 'D')

        # 1. Change all '/' characters to a '\' and strip whitespace
        self.__fp = self.__fp.replace('/', '\\')

        # 2. Extract file name, path, extension, and file type
        efn = self.__fp.split('\\')[-1]
        efd = os.path.abspath(self.__fp[::-1][len(efn)::][::-1])

        if '.' in efn:
            ext = self.__fp.replace(self.__fp.split('.')[0], '')
            eft = ext.split('.')[-1].upper()
        else:
            ext = ''
            eft = ''

        self.__efn = efn
        self.__efd = efd
        self.__ext = ext
        self.__eft = eft

    @property
    def file_name(self) -> str:
        return self.__efn

    @property
    def file_path(self) -> str:
        return self.__efd

    @property
    def file_type(self) -> str | None:
        return self.__eft if len(self.__eft) else None

    @property
    def extension(self) -> str:
        return self.__ext

    @property
    def mode(self) -> FileMode:
        return FileMode.FILE if self.__m.upper() == 'F' else FileMode.DIR

    @property
    def full_path(self) -> str:
        return f'{self.file_path}\\{self.file_name}'

    def __str__(self) -> str:
        return f'File("{self.file_name}", "{self.file_path}", "{self.extension}", "{self.file_type}", {self.mode})'


# Patient Management
class InstitutionID(str):
    def __init__(self, iid) -> None:
        self.__value__ = iid
        str.__init__(iid)

    @property
    def value(self) -> str:
        return self.__value__


class PatientID(int):
    def __init__(self, dob) -> None:
        self.__value__ = dob
        int.__init__(dob)

    @property
    def value(self) -> int:
        return self.__value__


class FormattedDate(int):
    def __init__(self, v) -> None:
        self.__value__ = v
        int.__init__(v)  # type: ignore

        self._on_init()  # Check the format.

    def _on_init(self) -> None:
        sv = str(self.__value__)

        # Make sure that the format is correct.
        # Also make sure that the expected format is still 8 characters long.
        assert len(sv) == SZ.DATE == 8

        y = int(sv[:4])                             # YYYY----
        m = int(sv[4:6])                            # ----MM--
        d = int(sv[6::])                            # ------DD

        cy = int(datetime.now().strftime('%Y'))     # Current year

        assert 1900 <= y <= cy  # Make sure that the year is between 1900 and the current year.
        assert 1 <= m <= 12     # Make sure that the month is in the right range
        assert 1 <= d <= 31     # Make sure that the date is in the right range

    @property
    def value(self) -> int:
        return self.__value__


class FormattedName(str):
    def __init__(self, name: str) -> None:
        str.__init__(name)
        self.__value__ = name

        self._on_init()

    def _on_init(self) -> None:
        v = self.__value__.strip()
        assert len(v), 'No name provided.'

        if ',' not in v:
            # Not formatted as LAST, first yet.
            tokens = v.split()
            last = tokens.pop()

            self.__value__ = ' '.join([f'{last.upper()},', *[t.title() for t in tokens]])

    @property
    def value(self):
        return self.__value__

    def __str__(self) -> str:
        return self.value


@dataclass
class PT:
    IID:            InstitutionID
    PID:            PatientID
    DOB:            FormattedDate
    DIET:           DietOrder
    name:           FormattedName

