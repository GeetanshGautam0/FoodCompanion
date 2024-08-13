from std_imports import *


TX_INIT_COMMAND = b'<C/>'
TX_INIT_MESSAGE = b'<R/>'

SIZE_LOOKUP = Constants.SZ
MSG_SETTINGS = Constants.MSG
HDR_SETTINGS = Constants.HDR
TCP_SETTINGS = Constants.TCP
FMT_SETTINGS = Constants.FRMT
TX_RESPONSES = Constants.RESPONSES


class Command(Enum):
    (GET, CRT, UPD, DEL) = range(4)

    class TSpecifier(Enum):
        (P, F) = range(2)

    class CSpecifier(Enum):
        (REC, DET, ORD, ALL) = range(4)


def decypher_message(__message: bytes) -> Command | Structs.Transmission | bytes:
    __message = __message.strip()
    assert len(__message)
    
    if __message.startswith(TX_INIT_COMMAND):
        # Parse command
        raise Exception("Not implemented")

    elif __message.startswith(TX_INIT_MESSAGE):
        # Parse message
        raise Exception("Not implemented")

    else:
        # Return bytes once completely loaded.
        raise Exception("Not implemented")
