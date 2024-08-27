try:
    from sc_data import *

except ImportError:
    from ..sc_data import *

import sqlite3, json, os, sys, traceback
from .diets import get_diet_name
from dataclasses import dataclass
from enum import Enum
from typing import Any, Callable, List, Dict, Type, Tuple


SLogger: Logger


class __database__:

    class CouldNotCreateDatabase(Exception):
        pass

    class InvalidRequest(Exception):
        pass

    class BehaviourNotDefined(Exception):
        pass

    def __init__(
            self,
            file_path: Structs.File | str,
            database_type: Enums.DatabaseType,
            logger: Logger
    ) -> None:
        global SLogger

        assert isinstance(logger, Logger)

        self.__fp__ = file_path if isinstance(file_path, Structs.File) else Structs.File(file_path, mode='f')
        self.__type__ = database_type
        self.__logger__ = logger
        SLogger = logger

        assert database_type in (Enums.DatabaseType.JSON, Enums.DatabaseType.SQLITE), 'Class __database__ not up to date.'

        self.__is_ready = False

        self.run()

    def _sql_command_(
        self,
        command: str,
        additional_command: str | None = None
    ) -> Tuple[bool, Any | Type[BaseException]]:
        assert self._configured_  # Makes sure that __connector__ is defined

        with sqlite3.connect(self.__fp__.full_path) as self.__connector__:
            cur = self.__connector__.cursor()
            out = self._execute_(cur.execute, True, command)

            if isinstance(additional_command, str):
                if additional_command.startswith('fetch_'):
                    n = additional_command.replace('fetch_', '', 1)

                    match n:
                        case '*':
                            com = cur.fetchall

                        case '1' | 'one':
                            com = cur.fetchone

                        case _:
                            com = None

                            if n.isnumeric():
                                if int(n) > 0:
                                    com = lambda: cur.fetchmany(int(n))

                if com is not None:
                    out = self._execute_(com, True)

            cur.close()
            self.__connector__.commit()

        return out

    @staticmethod
    def _execute_(
            fnc: Callable[[Any], Any],
            __echo_command: bool,
            *args: Any,
            **kwargs: Any
    ) -> Tuple[bool, Any | Type[BaseException]]:
        global SLogger

        if __echo_command:
            def _fmt_arg(__d: Any) -> Any:
                if isinstance(__d, str):
                    return f'"{__d}"'

                return __d

            SLogger.log(
                LoggingLevel.INFO,
                'DBManager.execute',
                f'Executing {fnc.__name__.__str__()}(%s%s%s)' % (
                    (', '.join([_fmt_arg(a) for a in args])) if len(args) else '',
                    ', ' if len(args) and len(kwargs) else '',
                    (', '.join([f"{k}={_fmt_arg(v)}" for k, v in kwargs.items()])) if len(kwargs) else ''
                )
            )

        try:
            return True, fnc(*args, **kwargs)

        except Exception as E:
            SLogger.log(
                LoggingLevel.ERROR,
                'DBManager.execute',
                f'ERR @{fnc}: {E.__class__.__name__}({str(E)})'
            )
            return False, E

    @property
    def _configured_(self) -> Tuple[bool, List[str]]:
        # out = True
        reasons = []

        if self.__type__ == Enums.DatabaseType.SQLITE:
            # out &= '__connector__' in dir(self)

            if '__connector__' not in dir(self):
                # out &= False
                reasons.append('SQLite-based child classes of __database__ must define __connector__\n')

            if '__desc__' not in dir(self):
                reasons.append('SQLite-based child classes of __database__ must define __desc__\n')

            elif not isinstance(self.__desc__, Structs.SQLTableDescriptor):
                reasons.append('SQLite-based child classes of __database__ must define __desc__ as a SQLTableDescriptor\n')

        return not bool(len(reasons)), reasons

    @staticmethod
    def _format_rs_(__r: List[str]) -> str:
        return '\n\t* %s' % '\t* '.join(__r)

    def run(self) -> None:
        c, _r = self._configured_; assert c, __database__._format_rs_(_r)

        # Check file mode, if the file does not exist then create it.
        assert self.__fp__.mode == Enums.FileMode.FILE

        if not os.path.isfile(self.__fp__.full_path):
            self.__logger__.log(LoggingLevel.DEBUG, 'DBManager', f'Creating database file "{self.__fp__.file_name}"')

            try:
                if not os.path.isdir(self.__fp__.file_path):    # Make sure that the directory exists.
                    os.makedirs(self.__fp__.file_path)

                open(self.__fp__.full_path, 'x').close()        # Create the file.

            except Exception as E:
                raise self.CouldNotCreateDatabase(E.__class__.__name__)

        if self.__type__ == Enums.DatabaseType.SQLITE:
            self._sql_command_(f"CREATE TABLE IF NOT EXISTS {self.__desc__.table_name} ({self.__desc__.format_columns});")

        self.__is_ready = True

    def write_to_json(self, *_, **__) -> None: raise self.BehaviourNotDefined('Task.WriteToJSON')
    def write_to_sqlite(self, *_, **__) -> None: raise self.BehaviourNotDefined('Task.WriteToSQLite')

    def write(self, *args, **kwargs) -> Tuple[bool, Any]:
        if not self.__is_ready:
            return False, 'DB not ready.'

        self.__is_ready = False

        match self.__type__:
            case Enums.DatabaseType.JSON:
                s, v = __database__._execute_(self.write_to_json, False, *args, **kwargs)

            case Enums.DatabaseType.SQLITE:
                s, v = __database__._execute_(self.write_to_sqlite, False, *args, **kwargs)

            case _:
                return False, BaseException

        if not s and '__class__' in dir(v):
            # An error occurred.
            self.__logger__.log(LoggingLevel.ERROR, 'DBManager', f'Could not write to database: {v.__class__.__name__}({str(v)})')

        self.__is_ready = True
        return s, v

    def read_from_json(self, *_, **__) -> None: raise self.BehaviourNotDefined('Task.ReadFromJSON')
    def read_from_sqlite(self, *_, **__) -> None: raise self.BehaviourNotDefined('Task.ReadFromSQLite3')

    def read(self, *args, **kwargs) -> Tuple[bool, Any]:
        if not self.__is_ready:
            return False, 'DB not ready.'

        self.__is_ready = False

        match self.__type__:
            case Enums.DatabaseType.JSON:
                s, v = __database__._execute_(self.read_from_json, False, *args, **kwargs)

            case Enums.DatabaseType.SQLITE:
                s, v = __database__._execute_(self.read_from_sqlite, False, *args, **kwargs)

            case _:
                return False, BaseException

        if not s and '__class__' in dir(v):
            # An error occurred.
            self.__logger__.log(LoggingLevel.ERROR, 'DBManager', f'Could not read from database: {v.__class__.__name__}({str(v)})')

        self.__is_ready = True

        return s, v

    def _sqlite_close_conn_(self) -> None:
        assert self._configured_[0]

        try:
            self.__connector__.close()

        except Exception as E:
            self.__logger__.log(LoggingLevel.ERROR, 'DBManager', f'SCC->commit@{self.__desc__.table_name} {E.__class__.__name__}({str(E)})')

        self.__connector__ = None

    def log(self, ll: LoggingLevel, sc: str, data: str) -> None:
        self.__logger__.log(ll, sc, data)

    def __del__(self) -> None:
        if self._configured_[0] and self.__type__ == Enums.DatabaseType.SQLITE:
            self.__logger__.log(LoggingLevel.INFO, 'DBManager.del', f'Committing changes and closing SQLite connector.')

            # A properly-configured SQLite database; try to close the connector (if it's not already close).
            try:
                self.__connector__.close()

            except (AttributeError, NameError):
                # The connector was not initialized or was already closed.
                pass


class JSONDatabase(__database__):
    def __init__(self, file_path: Structs.File | str):
        __database__.__init__(self, file_path, Enums.DatabaseType.JSON)


class SQLWriteMode(Enum):
    (
        UPDATE,
        ADD,
        DELETE
    ) = range(3)


class SQLReadMode(Enum):
    (
        FETCH_ONE,
        FETCH_ALL
    ) = range(2)


@dataclass
class SQLFetchN:
    n: int


class SQLDatabase(__database__):
    def __init__(self, file_path: Structs.File | str, table_descriptor: Structs.SQLTableDescriptor, logger: Logger):
        self.__connector__ = None
        self.__desc__      = table_descriptor

        assert self.__desc__.check, 'Invalid table descriptor.'

        __database__.__init__(self, file_path, Enums.DatabaseType.SQLITE, logger)

    #
    # ------------------- HELPER FUNCTIONS -------------------
    #

    @staticmethod
    def _frmt_as(__type: Enums.SQLType, __data: Any) -> str:
        match __type:
            case Enums.SQLType.NULL:
                return 'NULL'

            case Enums.SQLType.INTEGER:
                assert isinstance(__data, int)
                return str(__data)

            case Enums.SQLType.REAL:
                assert isinstance(__data, float)
                return str(__data)

            case Enums.SQLType.TEXT | Enums.SQLType.BLOB:
                return f'"{__data}"'

            case _:
                raise AttributeError(f"Unknown SQLite type {__type.name}.")

    #
    # ------------------- WRITE FUNCTIONS -------------------
    #

    def _update(
            self,
            column: Structs.SQLColumn,
            new_data: Any,
            **criteria: Dict[str, Tuple[Type[Any], Any]]
    ) -> bool:

        # Make sure that the column exists in this table
        if column not in self.__desc__.columns:
            self.log(LoggingLevel.ERROR, 'DBManager.SQLDB.upd', "UPD.ERR<1>      Invalid column")
            return False

        # We must have at least one criterion provided in order to be able to update records.
        if not len(criteria):
            self.log(LoggingLevel.ERROR, 'DBManager.SQLDB.upd', "UPD.ERR<2>      Provide at least one criterion")
            return False

        # Make sure that the data type is correct.
        if not isinstance(new_data, Enums.SQLType.map_to_data_type(column.type)):
            self.log(LoggingLevel.ERROR, 'DBManager.SQLDB.upd', "UPD.ERR<3>      Invalid data type")
            return False

        c_name = {c.name: c.type for c in self.__desc__.columns}
        assert len(criteria) <= len(c_name)

        if sum([
            1 if
            k in c_name.keys() and
            isinstance(v, Enums.SQLType.map_to_data_type(c_name.get(k, Enums.SQLType.TEXT)))
            else 0
            for k, v in criteria.items()
        ]) != len(criteria):
            self.log(LoggingLevel.ERROR, 'DBManager.SQLDB.upd', f"UPD.ERR<4>      Invalid criterion/a")
            return False

        command = "UPDATE %s SET %s = %s WHERE %s" % (
            self.__desc__.table_name,
            column.name,
            SQLDatabase._frmt_as(column.type, new_data),
            ' AND '.join(
                [
                    f'{k}={v}'
                    for k, v in {
                        n: SQLDatabase._frmt_as(t, criteria[n])
                        for n, t in c_name.items()
                        if n in criteria
                    }.items()
                ]
            )
        )

        return self._sql_command_(command)[0]

    def _delete(
            self,
            **criteria: Dict[str, Tuple[Type[Any], Any]]
    ) -> bool:
        c_name = {c.name: c.type for c in self.__desc__.columns}
        assert len(criteria) <= len(c_name)

        if not len(criteria):
            self.log(LoggingLevel.ERROR, 'DBManager.SQLDB.del', "DEL.ERR<1>      Provide at least one criterion")
            return False

        if sum([
            1 if
            k in c_name.keys() and
            isinstance(v, Enums.SQLType.map_to_data_type(c_name.get(k, Enums.SQLType.NULL)))
            else 0
            for k, v in criteria.items()
        ]) != len(criteria):
            self.log(LoggingLevel.ERROR, 'DBManager.SQLDB.del', "DEL.ERR<2>      Invalid criterion/a")
            return False

        command = "DELETE FROM %s WHERE %s" % (
            self.__desc__.table_name,
            ' AND '.join(
                [
                    f'{k}={v}'
                    for k, v in {
                        n: SQLDatabase._frmt_as(t, criteria[n])
                        for n, t in c_name.items()
                        if n in criteria
                    }.items()
                ]
            )
        )

        return self._sql_command_(command)[0]

    def _add(
            self,
            **data: Dict[str, Any]
    ) -> bool:

        # Make sure that the connector is ready
        if not isinstance(self.__connector__, sqlite3.Connection):
            self.log(LoggingLevel.ERROR, 'DBManager.SQLDB.add', "ADD.ERR<1>      DB.CON not ready")
            return False

        # Use a 'scoring' system to check the integrity of the data inputted.
        #
        #   Assign a score of 1 if all the following conditions are met:
        #       Upon iterating through the list of columns in the table descriptor, if
        #       A.  The column's name matches a key in the 'data' dictionary; and,
        #       B.  That entry (in 'data') has the correct type as indicated by the column descriptor.
        #
        #   Otherwise, we assign a score of 0. If the sum of all of these scores is equal to the number of columns
        #   in the table, and if the length of 'data' is equal to the number of columns (to make sure too much data was
        #   not provided), then we are good to continue. Otherwise, we return False to indicate an error occurred.
        #
        #   As indicated by the return type of the function, no information on the error should be returned.

        if (len(data) != len(self.__desc__.columns) or sum([
            1 if
            c.name in data.keys() and
            (
                    isinstance(data.get(c.name), Enums.SQLType.map_to_data_type(c.type)) or
                    ((data.get(c.name, 'null') is None) if Enums.SQLFlags.NOT_NULL not in c.flags else False)
            )
            else 0
            for c in self.__desc__.columns
        ]) != len(self.__desc__.columns)
        ):
            self.log(LoggingLevel.ERROR, 'DBManager.SQLDB.add', "ADD.ERR<2>      Invalid Data")
            return False

        c_data: Dict[str, str] = {}

        for c in self.__desc__.columns:
            if Enums.SQLFlags.AUTOINCREMENT in c.flags:
                data.pop(c.name)

            else:
                c_data[c.name] = SQLDatabase._frmt_as(c.type, data[c.name])

        command = "INSERT INTO %s (%s) values (%s)" % (
            self.__desc__.table_name,
            ','.join(c_data.keys()).rstrip(','),
            ','.join(c_data.values()).rstrip(',')
        )

        return self._sql_command_(command)[0]

    def close(self) -> None:
        self._sqlite_close_conn_()

    def write_to_sqlite(self, mode: SQLWriteMode, *args, **kwargs) -> bool:
        try:
            match mode:
                case SQLWriteMode.ADD:
                    assert self._add(**kwargs)

                case SQLWriteMode.UPDATE:
                    assert self._update(*args, **kwargs)

                case SQLWriteMode.DELETE:
                    assert not len(args), 'Only use K/W-ARGS for delete commands.'
                    assert self._delete(**kwargs)

                case _:
                    raise AttributeError("Unexpected write mode.")
        except:
            return False

        return True

    #
    # ------------------- READ FUNCTIONS -------------------
    #

    def read_from_sqlite(self, mode: SQLReadMode | SQLFetchN, **criteria) -> Tuple[bool, Any]:
        if isinstance(mode, SQLFetchN):
            assert mode.n > 0
            a_com = f'fetch_{mode.n}'
        elif mode == SQLReadMode.FETCH_ALL:
            a_com = 'fetch_*'
        elif mode == SQLReadMode.FETCH_ONE:
            a_com = 'fetch_one'
        else:
            raise AttributeError("Unknown fetch mode.")

        if len(criteria):
            # Check that the criteria provided is valid
            valid_columns = {c.name: c.type for c in self.__desc__.columns}
            assert len(valid_columns) >= len(criteria)

            assert sum([
                1 if
                    k in valid_columns.keys() and
                    isinstance(v, Enums.SQLType.map_to_data_type(valid_columns.get(k, Enums.SQLType.TEXT)))
                    else 0
                    for k, v in criteria.items()
            ]) == len(criteria), 'Invalid selection criterion/a.'

            c_crt = ['%s=%s' % (k, SQLDatabase._frmt_as(valid_columns[k], v)) for k, v in criteria.items()]

            command = "SELECT * FROM %s WHERE %s" % (
                self.__desc__.table_name,
                ' AND '.join(c_crt)
            )

            return self._sql_command_(command, a_com)

        else:
            # No criteria provided
            command = f"SELECT * FROM {self.__desc__.table_name}"
            return self._sql_command_(command, a_com)


@dataclass
class __tbl_desc(Constants.Constants):
    pt_table:   Structs.SQLTableDescriptor
    user_table: Structs.SQLTableDescriptor


TABLE_DESCRIPTORS = __tbl_desc(
    pt_table=Structs.SQLTableDescriptor(
        "PTs",
        [
            Structs.SQLColumn('n',      Enums.SQLType.INTEGER, [Enums.SQLFlags.PRIMARY_KEY, Enums.SQLFlags.AUTOINCREMENT]),
            Structs.SQLColumn('pid',    Enums.SQLType.INTEGER, [Enums.SQLFlags.NOT_NULL]),
            Structs.SQLColumn('name',   Enums.SQLType.TEXT,    [Enums.SQLFlags.NOT_NULL]),
            Structs.SQLColumn('diet',   Enums.SQLType.INTEGER, [Enums.SQLFlags.NOT_NULL]),
            Structs.SQLColumn('iid',    Enums.SQLType.TEXT, [Enums.SQLFlags.NOT_NULL]),
            Structs.SQLColumn('dob',    Enums.SQLType.INTEGER, [Enums.SQLFlags.NOT_NULL]),
        ]
    ),
    user_table=Structs.SQLTableDescriptor(
        "USER",
        [
            Structs.SQLColumn('n', Enums.SQLType.INTEGER, [Enums.SQLFlags.PRIMARY_KEY, Enums.SQLFlags.AUTOINCREMENT]),
            Structs.SQLColumn('uid', Enums.SQLType.INTEGER, [Enums.SQLFlags.NOT_NULL]),
            Structs.SQLColumn('iid', Enums.SQLType.TEXT, [Enums.SQLFlags.NOT_NULL]),
            Structs.SQLColumn('name', Enums.SQLType.TEXT, [Enums.SQLFlags.NOT_NULL]),
            Structs.SQLColumn('access', Enums.SQLType.TEXT, [Enums.SQLFlags.NOT_NULL]),  # List of integers;delim w/ "|"    Determines what the user has access to.
            Structs.SQLColumn('psw', Enums.SQLType.TEXT, [Enums.SQLFlags.NOT_NULL]),     # Save psw hash, not plaintext.
        ]
    )
)


class UserDatabase(SQLDatabase):
    def __init__(self, logger: Logger) -> None:
        self.__file_name__ = "db/users.db"
        super().__init__(self.__file_name__, TABLE_DESCRIPTORS.user_table, logger)

    def _uid_in_db(self, uid: int, iid: str) -> bool:
        return len(self.read(SQLReadMode.FETCH_ALL, uid=uid, iid=iid)[-1][-1]) > 0

    def validate_credentials(self, uid: int, iid: str, psw: str) -> bool:
        # True: valid user
        # False: invalid user

        if not self._uid_in_db(uid, iid):
            return False

        s, r = self._execute_(self.get_user_record, False, uid, iid, psw)

        return s & isinstance(r, Structs.UserRecord)

    def get_user_record(
            self,
            uid: int,
            iid: str,
            psw: str
    ) -> Structs.UserRecord | None:
        if not self._uid_in_db(uid, iid):
            return None

        res = self.read(
            SQLReadMode.FETCH_ALL,
            uid=uid,
            iid=iid,
            psw=psw
        ) #[-1][-1]

        if isinstance(res, tuple):
            res = res[-1]
        else:
            return None

        if isinstance(res, tuple):
            res = res[-1]
        else:
            return None

        if not len(res):
            return None

        user, *_ = res
        ca_map = {
            'UID': (1, Structs.UserID),
            'IID': (2, Structs.InstitutionID),
            'name': (3, Structs.FormattedName),
            'ACCESS': (4, lambda s: [int(a) for a in s.split(Structs.UserRecord_AccessDelim)]),
            'PSW_HASH': (5, str),
        }

        return Structs.UserRecord(**{k: t(user[i]) for k, (i, t) in ca_map.items()})

    def create_new_user(self, user: Structs.UserRecord) -> bool:
        if self._uid_in_db(user.UID.value, user.IID.value):
            self.log(LoggingLevel.ERROR, 'DBManager.UserDB.new', "UID exists at IID")
            return False

        if not len(user.name):
            self.log(LoggingLevel.ERROR, 'DBManager.UserDB.new', "Invalid user name.")
            return False

        data = {
            'n': None,
            'uid': user.UID.value,
            'iid': user.IID.value,
            'name': user.name.value,
            'access': Structs.UserRecord_AccessDelim.join([str(a) for a in user.ACCESS]).strip(Structs.UserRecord_AccessDelim),
            'psw': user.PSW_HASH
        }

        return self.write(SQLWriteMode.ADD, **data)[0]

    def delete_user(self, user: Structs.UserRecord) -> bool:
        if not self._uid_in_db(user.UID.value, user.IID.value):
            self.log(LoggingLevel.ERROR, 'DBManager.UserDB.del', "UID does not exist at IID")
            return False

        return self._sql_command_(
            "DELETE FROM %s WHERE uid=%d AND iid=\"%s\" AND psw=%s" % (
                self.__desc__.table_name,
                user.UID.value,
                user.IID.value,
                user.PSW_HASH,
            )
        )[0]

    def get_user_list(self) -> List[Structs.UserRecord]:
        o = []

        s, v = self.read(SQLReadMode.FETCH_ALL)
        if s and isinstance(v, (tuple, list)):
            s, apl = v

            if s and isinstance(apl, (tuple, list)):
                ca_map = {
                    'UID': (1, Structs.UserID),
                    'IID': (2, Structs.InstitutionID),
                    'name': (3, Structs.FormattedName),
                    'ACCESS': (4, lambda s: [int(a) for a in s.split(Structs.UserRecord_AccessDelim)]),
                    'PSW_HASH': (5, str),
                }

                for pt in apl:
                    s, user = self._execute_(Structs.UserRecord, False, **{k: t(pt[i]) for k, (i, t) in ca_map.items()})
                    if s:
                        o.append(user)
                    else:
                        self.log(LoggingLevel.ERROR, 'DBManager.UserDB.GUL', f'Failed to parse user: {user}')  # user: exception

        return o

    def update_user_data(
        self,
        user: Structs.UserRecord,
        column: str,
        new_data: Any
    ) -> bool:
        global TABLE_DESCRIPTORS

        if not self.validate_credentials(
            user.UID.value,
            user.IID.value,
            user.PSW_HASH
        ):
            return False

        conv = lambda s: [int(a) for a in s.split(Structs.UserRecord_AccessDelim)]

        ca_map = {
            'UID': (1, (int, Structs.UserID), True),
            'IID': (2, (str, Structs.InstitutionID), True),
            'NAME': (3, (str, Structs.FormattedName), True),
            'ACCESS': (4, (str, list), False),
            'PSW_HASH': (5, (str, ), False),
        }

        assert column.upper() in ca_map.keys(), column
        i, t, nv = ca_map[column.upper()]
        c = TABLE_DESCRIPTORS.user_table.columns[i]

        if not isinstance(new_data, t[-1]):
            assert isinstance(new_data, t)  # Make sure it's one of the accepted types
            f = t[-1] if t[-1] is not list else conv  # Conversion function

            new_data = f(new_data)

        if nv:
            v = new_data.value
        else:
            v = new_data

        return self.write(
            SQLWriteMode.UPDATE,
            c, v,
            pid=user.UID.value,
            iid=user.IID.value,
            psw=user.PSW_HASH,
        )[0]

    def remove_access(self, user: Structs.UserRecord, access_level: int) -> Tuple[bool, Structs.UserRecord]:
        if access_level not in user.ACCESS:
            return False, user

        old = user.ACCESS

        assert user.ACCESS.pop(user.ACCESS.index(access_level)) == access_level
        updated = self.update_user_data(user, 'access', user.ACCESS)

        if not updated:
            user.ACCESS = old

        return updated, user

    def add_access(self, user: Structs.UserRecord, access_level: int) -> Tuple[bool, Structs.UserRecord]:
        if access_level in user.ACCESS:
            return False, user

        old = user.ACCESS
        user.ACCESS.append(access_level)
        updated = self.update_user_data(user, 'access', user.ACCESS)

        if not updated:
            user.ACCESS = old

        return updated, user


class PTDatabase(SQLDatabase):
    def __init__(self, logger: Logger) -> None:
        self.__file_name__ = "db/pt.db"
        super().__init__(self.__file_name__, TABLE_DESCRIPTORS.pt_table, logger)

    def _pid_in_db(self, pid: int, iid: str) -> bool:
        return len(self.read(SQLReadMode.FETCH_ALL, pid=pid, iid=iid)[-1][-1]) > 0

    def get_patient_record(
        self,
        patient_id: Structs.PatientID,
        facility_id: Structs.InstitutionID,
        date_of_birth: Structs.FormattedDate,
    ) -> Structs.PT | None:
        # If the ID does not exist at the facility then return immediately.
        if not self._pid_in_db(patient_id, facility_id):
            return None

        res = self.read(
            SQLReadMode.FETCH_ALL,
            pid=patient_id.value,
            iid=facility_id.value,
            dob=date_of_birth.value
        ) #[-1][-1]

        if isinstance(res, tuple):
            res = res[-1]
        else:
            return None

        if isinstance(res, tuple):
            res = res[-1]
        else:
            return None

        if not len(res):
            return None

        pt, *_ = res
        ca_map = {
            'PID':  (1, Structs.PatientID),
            'name': (2, Structs.FormattedName),
            'DIET': (3, lambda x: Structs.DietOrder(x, get_diet_name(x))),
            'IID':  (4, Structs.InstitutionID),
            'DOB':  (5, Structs.FormattedDate)
        }

        return Structs.PT(**{k: t(pt[i]) for k, (i, t) in ca_map.items()})

    def create_new_record(self, patient_record: Structs.PT) -> bool:
        if self._pid_in_db(patient_record.PID.value, patient_record.IID.value):
            self.log(LoggingLevel.ERROR, 'DBManager.PTDB.new', "PID exists at IID")
            return False

        if not len(patient_record.name):
            self.log(LoggingLevel.ERROR, 'DBManager.PTDB.new', "Invalid patient name.")
            return False

        data = {
            'n':    None,
            'name': patient_record.name.value,
            'dob':  patient_record.DOB.value,
            'pid':  patient_record.PID.value,
            'iid':  patient_record.IID.value,
            'diet': patient_record.DIET.id
        }

        return self.write(SQLWriteMode.ADD, **data)[0]

    def delete_patient_record(self, patient_record: Structs.PT) -> bool:
        if not self._pid_in_db(patient_record.PID.value, patient_record.IID.value):
            self.log(LoggingLevel.ERROR, 'DBManager.PTDB.del', "PID does not exist at IID")
            return False

        return self._sql_command_(
            "DELETE FROM %s WHERE pid=%d AND iid=\"%s\" AND dob=%d" % (
                self.__desc__.table_name,
                patient_record.PID.value,
                patient_record.IID.value,
                patient_record.DOB.value,
            )
        )[0]

    def get_patient_list(self) -> List[Structs.PT]:
        o = []

        s, v = self.read(SQLReadMode.FETCH_ALL)
        if s and isinstance(v, (tuple, list)):
            s, apl = v

            if s and isinstance(apl, (tuple, list)):
                ca_map = {
                    'PID':  (1, Structs.PatientID),
                    'name': (2, Structs.FormattedName),
                    'DIET': (3, lambda x: Structs.DietOrder(x, get_diet_name(x))),
                    'IID':  (4, Structs.InstitutionID),
                    'DOB':  (5, Structs.FormattedDate)
                }

                for pt in apl:
                    s, pt = self._execute_(Structs.PT, False, **{k: t(pt[i]) for k, (i, t) in ca_map.items()})
                    if s:
                        o.append(pt)

                    else:
                        self.log(LoggingLevel.ERROR, 'DBManager.PTDB.gpl', f'Failed to parse PTr: {pt}')  # pt: exception

        return o

    def get_patient_diet(
            self,
            pid:    Structs.PatientID,
            iid:    Structs.InstitutionID,
            dob:    Structs.FormattedDate
    ) -> Structs.DietOrder | None:
        ptr = self.get_patient_record(pid, iid, dob)

        if isinstance(ptr, Structs.PT):
            return ptr.DIET

        return None

    def update_diet_option(
        self,
        patient_record: Structs.PT,
        new_diet: Structs.DietOrder
    ) -> bool:
        return self.write(
            SQLWriteMode.UPDATE,
            Structs.SQLColumn('diet', Enums.SQLType.INTEGER, [Enums.SQLFlags.NOT_NULL]),
            new_diet.id,
            pid=patient_record.PID.value,
            iid=patient_record.IID.value,
            dob=patient_record.DOB.value
        )[0]

