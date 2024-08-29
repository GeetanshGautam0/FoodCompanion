from client_utils import *


__logger = Logger()
cu = ClientUtil(__logger)

cu.establish_session()
cu.send_message('GET-P-DET', False, True)
