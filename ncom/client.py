from client_utils import *


__logger = Logger(is_server=False)

cus = [ClientUtil(__logger) for _ in range(20)]  # 20 connections

for cu in cus:
    cu.establish_session()
    cu.send_message('ECC GET-P-RCD', False, True)

for i, cu in enumerate(cus):
    print(i, cu.get_response(1024))
    cu.close_session()

__logger.stop()
sys.exit(0)
