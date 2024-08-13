from enum import Enum
from typing import Type, Any


# ------- Header -------

class H_TYPE(Enum):
    (
        BIT,
        INT,
        STR
    ) = range(3)


class H_PAD_MODE(Enum):
    (
        NONE,
        PREPEND,
        APPEND
    ) = range(3)


# ------- Food -------


class ServingSizeUnit(Enum):
    (
        COUNT,
        PKG,
        ML,
        G
    ) = range(4)


class Meal(Enum):
    (
        BREAKFAST,
        LUNCH,
        DINNER
    ) = range(3)


class FoodCategory(Enum):
    (
        ENTREE,
        SOUP,
        STARCH,
        VEGETABLE,
        FRUIT,
        DESERT,
        BEVERAGE,
        CONDIMENT
    ) = range(8)


# ------- Backend -------


class FileMode(Enum):
    (
        FILE,
        DIR
    ) = range(2)


class SQLType(Enum):
    (
        NULL,
        INTEGER,
        REAL,
        TEXT,
        BLOB
    ) = range(5)

    @staticmethod
    def map_to_sql_type(__python_type) -> Enum:
        return {
            bytes:  SQLType.BLOB,
            str:    SQLType.TEXT,
            float:  SQLType.REAL,
            int:    SQLType.INTEGER,
            None:   SQLType.NULL,
            type(None): SQLType.NULL
        }.get(__python_type, SQLType.TEXT)  # Default to text (str) type.

    @staticmethod
    def map_to_data_type(__sql_type) -> Type[Any]:
        return {
            SQLType.BLOB:       bytes,
            SQLType.TEXT:       str,
            SQLType.REAL:       float,
            SQLType.INTEGER:    int,
            SQLType.NULL:       None
        }.get(__sql_type, str)  # Default to text (str) type.


class SQLFlags(Enum):
    (
        PRIMARY_KEY,
        AUTOINCREMENT,
        NOT_NULL
    ) = range(3)


class DatabaseType(Enum):
    (
        JSON,
        SQLITE
    ) = range(2)
