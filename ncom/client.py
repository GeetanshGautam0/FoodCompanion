from client_utils import *
from threading import Thread


_logger = Logger(is_server=False)

#   -------------------------------------------------------------------------
#   Uncomment the following to check for the server's ability to respond to
#   multiple concurrent connections.
#   -------------------------------------------------------------------------
# cus = [ClientUtil(__logger) for _ in range(20)]  # 20 connections
#
# for cu in cus:
#     cu.establish_session()
#     cu.send_message('ECC GET-P-RCD', False, True)
#
# for i, cu in enumerate(cus):
#     if (recv := cu.get_response(Header.NGHeaderItems.header_length()))[0]:
#         print(i, cu.verify(parsed := cu.parse(recv[-1])), parsed)
#     else:
#         print(i, 'No response.')
#    cu.close_session()
#
#   -------------------------------------------------------------------------


def parse_fields(form: str) -> List[str]:
    start, end = form.index('<'), form.index('>')
    form = form[start + 1 : end]
    return [
        field.lstrip('[&').rstrip(';]')  # PS, I know that strip will keep stripping until it doesn't reach one of the characters in the string.
                                         # it is intended behaviour. Do not @ me for not using replace.
        for field in form.split('.')
    ]


def test_fields(form: str) -> None:
    expected_fields = {
        'PTR-1a': ('pid', 'iid', 'dob'),
        'PTR-1b': ('iid', 'userID', 'userAC', 'txTime'),
        'PTR-1c': ('pid', 'iid', 'dob', 'userID', 'userAC', 'txTime'),
        'PTR-2 ': ('pid', 'iid', 'dob', 'pname', 'diet', 'userID', 'userAC', 'txTime'),
        'PTR-3a': ('pid', 'iid', 'dob', 'diet', 'userID', 'userAC', 'txTime'),
        'PTR-3b': ('pid', 'iid', 'dob', 'field', 'value', 'userID', 'userAC', 'txTime'),
        'PTR-4 ': ('pid', 'iid', 'dob', 'userID', 'userAC', 'txTime'),

        'FDR-1 ': ('name', 'bld', 'cat', 'cal', 'cst', 'csu', 'cfi', 'ftr', 'fsa', 'pco',
                   'pro', 'ssc', 'ssu', 'odiets', 'iid', 'userID', 'userAC', 'txTime'),
        'FDR-2 ': ('field', 'value', 'iid', 'userID', 'userAC', 'txTime'),
        'FDR-3a': ('id', 'diet', 'iid', 'userID', 'userAC', 'txTime'),
        'FDR-3b': ('id', 'diet', 'iid', 'userID', 'userAC', 'txTime'),
        'FDR-4 ': ('name', 'iid', 'userID', 'userAC', 'txTime'),
        'FDR-5 ': ('iid', ),

        'URC-1a': ('iid', 'userID', 'userAC', 'txTime', 'nUserID'),
        'URC-1b': ('iid', 'userID', 'userAC', 'txTime'),
        'URC-2a': ('iid', 'userID', 'userAC', 'txTime', 'nUserID', 'nUserAC', 'access'),
        'URC-2b': ('iid', 'userID', 'userAC', 'txTime', 'nUserID', 'nUserAC'),
        'URC-3P': ('iid', 'userID', 'userAC', 'txTime', 'nUserID', 'access'),
        'URC-3R': ('iid', 'userID', 'userAC', 'txTime', 'nUserID', 'access'),
        'URC-4 ': ('iid', 'userID', 'userAC', 'txTime', 'nUserID', 'nUserAC', 'newAC'),
    }[form[:6]]

    got_fields = parse_fields(form)
    print(form, expected_fields)
    assert (g := len(got_fields)) == (e := len(expected_fields)), f'L<{e=} {g=}>'
    # assert not len(f := [field for field in expected_fields if field not in got_fields]), f"{form[:6].strip()}{f}"
    f = []
    for field in expected_fields:
        if field not in got_fields:
            f.append(field)

    assert not len(f), f'{form[:6].strip()}{f}'


tests = [
    ("GET-P-RCD", "PTR-1c"),
    ("GET-P-DET", 'PTR-1a'),
    ("GET-P-LST", 'PTR-1b'),
    ("NEW-P-RCD", 'PTR-2'),
    ("UPD-P-DET", 'PTR-3a'),
    ("UPD-P-RCD", 'PTR-3b'),
    ("DEL-P-RCD", 'PTR-4'),
    ("GET-F-LST", 'FDR-5'),
    ("NEW-F-RCD", 'FDR-1'),
    ("UPD-F-RCD", 'FDR-2'),
    ("NEW-F-OMI", 'FDR-3a'),
    ("DEL-F-OMI", 'FDR-3b'),
    ("GET-F-DET", 'FDR-5'),
    ("NEW-F-DET", 'FDR-4'),
    ("GET-U-RCD", 'URC-1a'),
    ("GET-U-LST", 'URC-1b'),
    ("NEW-U-RCD", 'URC-2a'),
    ("DEL-U-RCD", 'URC-2b'),
    ("NEW-U-ACC", 'URC-3P'),
    ("DEL-U-ACC", 'URC-3R'),
    ("UPD-U-PSW", 'URC-4'),
]


def test_all_commands():
    for command, form in tests:
        client = ClientUtil(_logger)  # Create a client
        client.establish_session()   # Establish connection w/ NG server

        if client.connection_established:
                sent, e = client.send_message(f'ECC {command}'.encode(), False, True)
                if not sent:
                    _logger.log(LoggingLevel.ERROR, 'NGClient', f'Could not send command {command} for test: {e}.')
                    client.close_session()
                    continue

                recv_s, recv_b = client.get_response(1024)
                if not recv_s:
                    _logger.log(LoggingLevel.ERROR, 'NGClient', f'Could not recv for {command} for test.')
                    client.close_session()
                    continue

                parsed = client.parse(recv_b)
                v, msg = client.verify(parsed)

                try:
                    assert v, 'Could not parse message (V)'
                    assert msg.startswith(form.encode()), f'Bad form "{msg[:6] if len(msg) >= 6 else msg}"'
                    # test_fields asserts as needed.
                    test_fields(msg.decode())

                    client.send_message(f'RFF {msg.decode()}', False, True)

                except Exception as E:
                    _logger.log(LoggingLevel.ERROR, 'NGClient', f'Test<{command}, {form}> failed w/ {msg=}; {str(E)}')
                    client.close_session()
                    continue

                else:
                    _logger.log(LoggingLevel.INFO, 'NGClient', f'Test<{command}, {form}> PASS')
                    client.close_session()

        else:
            _logger.log(LoggingLevel.ERROR, 'NGClient', 'Could not establish connection w/ server; ABORT.')
            client.close_session()


# for _ in range(100):
#   test_all_commands()

client = ClientUtil(_logger)
client.establish_session()

client.send_message('ECC GET-P-DET')
_, msg = client.verify(client.parse(client.get_response(1024)[-1]))
client.close_socket()

print(msg)
print(client.send_message(f'RFF {msg.decode()}'))
print(client.get_response(1024))

client.close_session()
_logger.stop()
sys.exit(0)
