from enum import Enum as _Enum
from typing import Any


MINIMUM_UNRESERVED_ACCESS_LEVEL = 4
MINIMUM_USER_ID_VALUE = 100_000_000


class AccessLevels(_Enum):
    # Add your own access levels here!
    # Change the _ to a tuple with your own names
    # Change the 0 to however many custom levels you add.
    # () = range(MINIMUM_UNRESERVED_ACCESS_LEVEL, 0 + MINIMUM_UNRESERVED_ACCESS_LEVEL)

    pass


class ReservedAccessLevels(_Enum):
    (
        OWNER,
        ADMINISTRATOR,
        DEVELOPER,
        MODERATOR,
    ) = range(4)


# Kinda works, but it works so don't touch it :)
AccessLevels._member_names_: list[str] = [*AccessLevels._member_map_, *ReservedAccessLevels._member_map_]
AccessLevels._member_map_: dict[str, _Enum] = {**AccessLevels._member_map_, **ReservedAccessLevels._member_map_}
AccessLevels._value2member_map_: dict[Any, _Enum] = {**AccessLevels._value2member_map_, **ReservedAccessLevels._value2member_map_}
