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


class PTDatabase(SQLDatabase):
    def __init__(self) -> None:
        self.__file_name__ = "db/pt.db"
        super().__init__(self.__file_name__, TABLE_DESCRIPTORS.pt_table)

    def _pid_in_db(self, pid: int, iid: str) -> bool:
        return len(self.read(SQLReadMode.FETCH_ALL, pid=pid, iid=iid)[-1][-1]) > 0

    def get_patient_record(
        self,
        patient_id: Structs.PatientID,
        facility_id: Structs.InstitutionID,
        date_of_birth: Structs.FormattedDate,
    ) -> Structs.PT | None:
        # If the ID does not exist at the facility then return immediately.
        res = self.read(
            SQLReadMode.FETCH_ALL,
            pid=patient_id.value,
            iid=facility_id.value,
            dob=date_of_birth.value
        )[-1][-1]

        if not len(res):
            return None

        pt, *_ = res
        ca_map = {
            'PID':  (1, Structs.PatientID),
            'name': (2, str),
            'DIET': (3, lambda x: Structs.DietOrder(x, get_diet_name(x))),
            'IID':  (4, Structs.InstitutionID),
            'DOB':  (5, Structs.FormattedDate)
        }

        return Structs.PT(**{k: t(pt[i]) for k, (i, t) in ca_map.items()})

    def create_new_record(self, patient_record: Structs.PT) -> bool:
        if self._pid_in_db(patient_record.PID.value, patient_record.IID.value):
            stderr("PID exists at IID", " @ _create_new_record")
            return False

        if not len(patient_record.name):
            stderr("Invalid patient name.", " @ _create_new_record")
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
            stderr("PID does not exist at IID", " @ _delete_patient_record")
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
                    o.append(Structs.PT(**{k: t(pt[i]) for k, (i, t) in ca_map.items()}))

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
