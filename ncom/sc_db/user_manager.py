import tkinter as tk
import hashlib
from tkinter import ttk
try:
    from sc_data import *
    from sc_db import *
except ImportError:
    from ..sc_data import *
    from ..sc_db import *
from threading import Thread
from typing import Tuple, Optional, Callable, Any, cast
from shared_memory_dict import SharedMemoryDict
from datetime import datetime
from prettytable import PrettyTable


MINIMUM_USER_ID_VALUE = 100_000_000


class __terminal__(Thread):
    def __init__(
            self,
            logger: Logger,
            smd: Tuple[str, int],
            messages: Tuple[Tuple[str, Optional[str]]],  # message, smd key (if is prompt)
            *_,
            **__
    ) -> None:
        super(__terminal__, self).__init__()

        self.logger = logger
        self.smd, self.msgs = SharedMemoryDict(*smd), messages

        self.root = tk.Tk()

        self.data = {}
        self.entry_string = tk.StringVar(self.root)

        self.text = tk.Listbox(self.root)
        self.input_frame = tk.Frame(self.root)
        self.entry = ttk.Entry(self.input_frame, textvariable=self.entry_string)
        self.input_desc = tk.Label(self.input_frame)

        self.style = ttk.Style(self.root)
        self.style.theme_use('default')

        self.ss = (
            self.root.winfo_screenwidth(),
            self.root.winfo_screenheight()
        )
        self.ws = (500, 700)
        self.sp = ()
        self._check_ws()

        self.start()
        self.root.mainloop()

    def _check_ws(self) -> None:
        if self.ws[0] > self.ss[0]:
            self.ws = (self.ss[0], 700//500 * self.ss[1])

        if self.ws[1] > self.ss[1]:
            self.ws = (self.ws[0], self.ss[1])

        self.sp = (
            (self.ss[0] - self.ws[0]) // 2,
            (self.ss[1] - self.ss[1]) // 2
        )

    @staticmethod
    def sf_execute(fct: Callable[[Any], Any], *args, **kwargs) -> None:
        try:
            fct(*args, **kwargs)
        except Exception as _:
            pass

    def close(self) -> None:
        self.root.after(0, lambda: __terminal__.sf_execute(self.root.destroy))
        __terminal__.sf_execute(self.join, 0)

    def _man_upd(self):
        self.root.update()
        self.root.after(1, self._man_upd)

    def run(self) -> None:
        # self.root.update()

        self.root.title('Input Terminal')
        self.root.wm_geometry(f'{self.ws[0]}x{self.ws[1]}+{self.sp[0]}+{self.sp[1]}')
        self.root.wm_protocol('WM_DELETE_WINDOW', self.close)

        self.text.pack(fill=tk.BOTH, expand=True, padx=20, pady=(10, 5))
        self.input_desc.pack(fill=tk.X, expand=False, padx=20, pady=(5, 0))
        self.entry.pack(fill=tk.X, expand=False, padx=20, pady=(2, 10))

        self.data['_inp_'] = False
        self.entry_string.set('')
        self.entry.bind('<Return>', self._on_entry_enter)

        self.root.config(bg='#ffffff')
        self.input_frame.config(bg='#ffffff')

        self.text.config(bg='#ffffff', fg='#000000', font=('Times New Roman', 10))
        self.input_desc.config(bg='#ffffff', fg='#000000', font=('Times New Roman', 10), anchor=tk.W, justify=tk.LEFT)

        self.style.configure(
            'TEntry',
            foreground='#000000',
            background='#ffffff',
            font=('Times New Roman', 10)
        )

        self.root.lift()

        self.execute()

    def execute(self) -> None:
        for (message_or_desc, smd_key) in self.msgs:
            if isinstance(smd_key, str):  # This is a prompt
                inp = self.prompt(message_or_desc)   # desc
                self.smd[smd_key] = inp
            else:  # This is a message
                self.add_message(message_or_desc)  # msg

        self.close()

    def _insert_item(self, s: str) -> None:
        self.text.insert(tk.END, s)

        self.text.select_clear(self.text.size() - 2)  # Clear the current selected item
        self.text.select_set(tk.END)  # Select the new item
        self.text.yview(tk.END)  # Set the scrollbar to the end of the listbox

    def add_message(self, msg: str) -> None:
        self.logger.log(
            LoggingLevel.INFO,
            'UserManager.Terminal.AddMessage',
            'New message: \n%s' %
            Functions.STRING_WITH_LINE_NUMBERS(msg, '\t', (0,))
        )
        _ = [self._insert_item(line) for line in msg.split('\n')]

    def disp_entry(self) -> None:
        self.input_frame.pack(fill=tk.X, expand=False)
        self.entry.focus_get()

    def hide_entry(self) -> None:
        self.input_frame.pack_forget()

    def _on_entry_enter(self, *args, **kwargs) -> None:
        self.data['_inp_'] = True
        self.hide_entry()

    def prompt(self, desc: str) -> str:
        def _wait_for_input() -> None:
            while not self.data.get('_inp_', False):
                pass

        self.input_desc.config(text=desc)
        self.disp_entry()
        _wait_for_input()

        s = self.entry_string.get().strip()  # Save space in the SMD, yk?
        self.data['_inp_'] = False
        self.entry_string.set('')
        self.hide_entry()

        return s


def CreateUserRecord(logger: Logger, user_db: UserDatabase) -> None:
    """
    Handler for creating a new user record.

    Note: user passwords will NOT be logged.

    :param logger: Logger instance.
    :param user_db: UserDatabase instance.
    :return: None
    """

    sc = 'UserManager.CUR'
    seq = (
        ('Please login to add a new user.', None),
        ('Please note that you must be AT LEAST a moderator to add a new user.', None),
        ('Enter your institution ID.', None),
        ('IID', 'iid'),
        ('Enter your user ID.', None),
        ('User ID', 'uid'),
        ('Enter your password.', None),
        ('Password', 'psw')
    )

    smd = ('CreateUserRecord', 4096)
    _ = __terminal__(logger, smd, seq)  # type: ignore

    smd = SharedMemoryDict(*smd)
    # Hash password and remove from SMD, for security
    hpsw = hashlib.sha256(smd.get('psw', '').encode()).hexdigest()
    smd['psw'] = None

    g, iuid = Functions.TRY(int, smd.get('uid', -1))
    if not g:
        logger.log(LoggingLevel.ERROR, sc, 'User not found (0).')
        return

    if not len(iid := smd.get('iid', '').strip()):
        logger.log(LoggingLevel.ERROR, sc, 'User not found (1).')
        return

    logger.log(LoggingLevel.INFO, sc, 'Retrieving user information.')

    user_record = user_db.get_user_record(iuid, iid, hpsw)
    if user_record is None:
        logger.log(LoggingLevel.ERROR, sc, 'User not found (2).')
        return

    logger.log(
        LoggingLevel.WARN,
        sc,
        'User %s <MAX_AL={%d}> attempting to create new user record.' %
        (str(user_record), max_access_level := min(user_record.ACCESS))  # Note: lower access level = more privileged user
    )

    if max_access_level > 3:
        logger.log(
            LoggingLevel.ERROR,
            sc,
            f'User {user_record.UID} ({user_record.name.value}) does not have the minimum required privilege level (3) to create a new user record.'
        )

        return

    logger.log(LoggingLevel.INFO, sc, f'User {user_record.UID.value} at {user_record.IID.value} ({user_record.name.value}) able to create a new user.')

    new_user_id = max(map(lambda s: cast(Structs.UserRecord, s).UID, user_db.get_user_list())) + 1
    new_user_id = MINIMUM_USER_ID_VALUE if new_user_id < MINIMUM_USER_ID_VALUE else new_user_id

    seq_2 = (
        (f'Creating a new user at {iid} with user id {new_user_id}.', None),
        ('Enter the following information about the new user.', None),
        ('Enter the user\'s legal name.', None),
        ('Legal Name', 'name'),
        # ("Enter the user's date of birth (YEAR ONLY)", None),
        # ('DOB - Year', 'dob_year'),
        # ("Enter the user's date of birth (MONTH, 1-12, ONLY)", None),
        # ('DOB - Month', 'dob_month'),
        # ("Enter the user's date of birth (DATE ONLY)", None),
        # ('DOB - Date', 'dob_date'),
        ("Enter a new password for the user.", None),
        ('Password', 'psw'),
        ('The following access levels are available.', None),
        *[
            ('\t%d: %s' % (al_enum.value, al_name), None) for (al_name, al_enum) in AccessLevels._member_map_.items()
        ],
        ('Enter access level(s) for the user, separate with commas if needed.', None),
        ('Access Level(s)', 'al')
    )
    smd = ('CreateUserRecord', 8192)

    __terminal__(logger, smd, seq_2)  # type: ignore

    smd = SharedMemoryDict(*smd)

    # Hash the password and remove from SMD.
    #   You can use r_psw to impose restrictions on the password.
    hpsw = hashlib.sha256(r_psw := smd.get('psw', '').encode()).hexdigest()
    smd['psw'] = None

    def failed_to_create_new_user(err: str) -> None:
        logger.log(
            LoggingLevel.ERROR,
            sc,
            f'Failed to create new user record: {err}'
        )

    if not len(r_psw.strip()):
        failed_to_create_new_user('Bad password.')
        return

    for key in ('name', 'psw', 'al',): # 'dob_year', 'dob_month', 'dob_date'):
        if key not in smd:
            failed_to_create_new_user(f'Did not provide all information requested: no "{key}".')
            return

    # Check DOB here, if needed in the future.

    access_levels_requested = smd['al'].split(',')
    d, iALR = Functions.TRY(map, lambda s: int(s.strip()), access_levels_requested)
    if not d:
        failed_to_create_new_user(f'Invalid access level(s) (A).')
        return

    iALR = list(iALR)

    for alr in iALR:
        if alr not in AccessLevels._value2member_map_.keys():  # Make sure that the thing exists!
            failed_to_create_new_user(f'Invalid access level {alr} (B).')
            return

    if min(iALR) < max_access_level:  # The user is trying to create user that is MORE privileged than itself
        failed_to_create_new_user(f'Cannot create a user that is more privileged than yourself (you are {max_access_level}, requested {min(iALR)})')
        return

    if not len(smd['name']):
        failed_to_create_new_user('No name.')
        return

    # we good!

    new_user_record = Structs.UserRecord(
        Structs.InstitutionID(iid),
        Structs.UserID(new_user_id),
        iALR,
        hpsw,
        Structs.FormattedName(smd['name'])
    )

    logger.log(LoggingLevel.INFO, sc, f'Creating user {new_user_record} (all checks PASS).')
    user_db.create_new_user(new_user_record)

    return  # :)


def ListUserRecords(logger: Logger, user_db: UserDatabase) -> None:
    """
    Handler for listing all user records.

    :param logger: Logger instance.
    :param user_db: UserDatabase instance.
    :return: None
    """

    sc = 'UserManager.LUR'
    seq = (
        ('Please login to access user records.', None),
        ('Enter your institution ID.', None),
        ('IID', 'iid'),
        ('Enter your user ID.', None),
        ('User ID', 'uid'),
        ('Enter your password.', None),
        ('Password', 'psw')
    )
    smd = ('CreateUserRecord', 4096)
    _ = __terminal__(logger, smd, seq)  # type: ignore

    smd = SharedMemoryDict(*smd)
    hpsw = hashlib.sha256(smd.get('psw', '').encode()).hexdigest()
    smd['psw'] = None

    gUID, iUID = Functions.TRY(int, smd.get('uid'))
    if not gUID:
        logger.log(LoggingLevel.ERROR, sc, 'Invalid user ID.')
        return

    iid = smd.get('iid', '').strip()
    user_record = user_db.get_user_record(iUID, iid, hpsw)
    if user_record is None:
        logger.log(LoggingLevel.ERROR, sc, 'Failed to login.')
        return
    iid = user_record.IID.value  # To make sure that it's formatted correctly.
    logger.log(LoggingLevel.INFO, sc, f'Verified identity as {iUID} at {iid} ({user_record.name.value}).')
    logger.log(LoggingLevel.WARN, sc, f'Outputting all user records at {iid} up to {datetime.now().ctime()}.')

    all_records = user_db.get_user_list()
    table = PrettyTable(['Name', 'User ID', 'Institution ID', 'Access Levels'])

    for u_record in all_records:
        if u_record.IID.value != iid:
            continue

        table.add_row(
            [
                u_record.name.value,
                u_record.UID.value,
                iid,
                ', '.join([AccessLevels._value2member_map_[al].name for al in u_record.ACCESS]).strip()
            ]
        )

    output = f'List of all users at {iid}:\n{str(table)}'
    logger.log(LoggingLevel.INFO, sc, '\n' + Functions.STRING_WITH_LINE_NUMBERS(output, '\t', (0,)))
