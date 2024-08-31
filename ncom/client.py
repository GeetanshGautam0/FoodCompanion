from client_utils import *


__logger = Logger(is_server=False)
cu = ClientUtil(__logger)

cu.establish_session()
cu.send_message('ECC GET-P-RCD', False, True)
print(cu.get_response(1024))
cu.close_session()

__logger.stop()
sys.exit(0)
