from client_utils import *


__logger = Logger(is_server=False)

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

client = ClientUtil(__logger)  # Create a client
client.establish_session()   # Establish connection w/ NG server

if client.connection_established:
    client.send_message(b'ECC GET-P-RCD', False, True)
    recv_s, recv_d = client.get_response(1024)
    if recv_s:
        parsed = client.parse(recv_d)
        print('', (tL := client.verify(parsed))[-1], parsed, recv_d, sep='\n\t')

    else:
        __logger.log(LoggingLevel.ERROR, 'NGClient', 'Could not establish connection w/ server; ABORT (2).')
else:
    __logger.log(LoggingLevel.ERROR, 'NGClient', 'Could not establish connection w/ server; ABORT.')

__logger.stop()
sys.exit(0)
