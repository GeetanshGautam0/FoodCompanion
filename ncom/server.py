from std_imports import *
from sc_server import *
from threading import Thread
import hashlib


__logger = Logger(is_server=True)
_s_data = ServerData(
    logger=__logger,
    patient_database=PTDatabase(__logger),
    user_database=UserDatabase(__logger),
    shutdown_tasks=[]
)

admin_user = Structs.UserRecord(
    Structs.InstitutionID("FC"),
    Structs.UserID(100),
    [100],
    hashlib.sha256(b'admin').hexdigest(),
    Structs.FormattedName('ADMINISTRATOR, FC')
)

if not _s_data.user_database._uid_in_db(admin_user.UID.value, admin_user.IID.value):
    __logger.log(LoggingLevel.WARN, '__main__', 'No users found. Adding default admin user.')
    _s_data.user_database.create_new_user(admin_user)


def eh(tp, *args) -> None:
    global _s_data

    if tp == KeyboardInterrupt:
        for i, f in enumerate(_s_data.shutdown_tasks):
            s, d = sf_execute(_s_data.logger, f)
            if not s:
                _s_data.logger.log(LoggingLevel.WARN, 'GEH', f"Skipped Task#{i + 1} <{d.__class__.__name__}: {str(d)}>")

        sys.exit('KB-INT')
    sys.__excepthook__(tp, *args)


sys.excepthook = eh

ls = LegacyServer(Constants.TCP.SIP, _s_data.patient_database, _s_data.logger)
ns = NGServer(Constants.TCP.SIP, _s_data.patient_database, _s_data.user_database, _s_data.logger)

(t0 := Thread(target=ls.run, name='LegacyServer')).start()
(t1 := Thread(target=ns.run, name='NGServer')).start()

_s_data.shutdown_tasks.extend([
    ls.request_shutdown, ns.request_shutdown,
    t0.join, t1.join,
    _s_data.logger.stop
])


class CLI:
    @staticmethod
    def help_message() -> None:
        global _s_data

        max_len = max([len(c) for c in CLI.commands])
        max_info_len = max([len(c) for c, *_ in CLI.commands.values()])
        n_extra = 5
        max_ttl_len = max_len + max_info_len + n_extra + 4
        max_ttl_len = max_ttl_len if max_ttl_len >= 64 else 64

        def centered(s: str) -> str:
            if (l := len(s)) >= max_ttl_len:
                return s
            else:
                return s.rjust(l + (max_ttl_len - l) // 2)

        def echo(s) -> None:
            global _s_data
            for substr in s.split('\n'):
                if substr.startswith('<C>'):
                    substr = substr.replace('<C>', '', 1).strip()
                    _s_data.logger.log(LoggingLevel.INFO, 'CLI', centered(substr))
                else:
                    _s_data.logger.log(LoggingLevel.INFO, 'CLI', substr)

        help_text = f'''\n\n
{"-" * max_ttl_len}
<C>FoodCompanion

<C>Author: Geetansh Gautam
<C>https://github.com/GeetanshGautam0/FoodCompanion

<C>Servers hosted: {Constants.TCP.SIP} Legacy<Port{Constants.TCP.L_PORT}>; NG<Port{Constants.TCP.PORT}>
{"-" * max_ttl_len}

%s

{"-" * max_ttl_len}

''' % '\n'.join([
            f'\t{command}{"." * (max_len + n_extra - len(command))}{info}'.ljust(max_ttl_len)
            for command, (info, _) in CLI.commands.items()
        ])

        echo(help_text)

    @staticmethod
    def not_impl(fnc: str) -> None:
        raise Exception(f'Function {fnc} not implemented yet.')

    @staticmethod
    def new_user() -> None:
        raise Exception

    commands = {
        'STOP':         ('Shutdown server and quit.', ls.__s_thread__.done),
        'HELP':         ('Show this information.', help_message),
        'NEW_USER':     ('Register a new user.', new_user),
        'REM_USER':     ('Remove a new user.', lambda *_, **__: CLI.not_impl('REM_USER')),
        'LIST_USER':    ('Get a user list.', lambda *_, **__: CLI.not_impl('LIST_USER')),
        'USER_ACCESS':  ('Manage user access', lambda *_, **__: CLI.not_impl('USER_ACCESS')),
    }


# Echo help message at the beginning.
CLI.help_message()

while (((not ls.__s_thread__.is_done) or (not ns.__s_thread__.is_done))
       and (inp := input('[INPUT] Enter a command at any time and press RETURN.\n').strip().upper()) != 'STOP'):

    _s_data.logger.log(LoggingLevel.INFO, 'CLI', f'Received command "{inp}"')

    if inp not in CLI.commands.keys():
        _s_data.logger.log(LoggingLevel.INFO, 'CLI', f'Invalid command -> showing HELP_TEXT.')
        CLI.help_message()

    else:
        sf_execute(_s_data.logger, CLI.commands[inp][-1], sfe_echo_tb=True)

else:
    for i, task in enumerate(_s_data.shutdown_tasks):
        try:
            task()
            _s_data.logger.log(LoggingLevel.INFO, 'CLI', f"Executed Task#{i + 1} <{task}>")
        except Exception as E:
            _s_data.logger.log(LoggingLevel.WARN, 'CLI', f"Skipped Task#{i + 1} <{E.__class__.__name__}: {str(E)}>")

    sys.exit("CMD-STOP")
