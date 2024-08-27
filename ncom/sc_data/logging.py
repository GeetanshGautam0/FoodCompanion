import hashlib, os
from .struct import File
from dataclasses import dataclass
from datetime import datetime
from .constants import FRMT
from .appinfo import APPINFO
from .settings import SETTINGS
from typing import List
from .functions import memoize, STDOUT, STDERR
from threading import Thread, Timer
from enum import Enum


START_BLOCK = '<!----START-BLOCK----!->'
START_DATA = '<!----START-DATA----!->'
END_BLOCK = '<!----END-BLOCK----!->'
END_DATA = '<!----END-DATA----!->'


@dataclass
class Block:
    prev_hash:      str
    time_stamp:     int
    data:           bytes
    index:          int

    def calculate_hash(self) -> str:
        hash_string = str(self.index) + str(self.time_stamp) + str(self.prev_hash)
        return hashlib.sha3_256(hash_string.encode() + self.data).hexdigest()

    def to_bytes(self) -> bytes:
        return (f'''
<!----START-BLOCK----!->
    d   <!----START-DATA----!->%b<!----END-DATA----!->
    i   {self.index}
    ts  {self.time_stamp}
    ph  {self.prev_hash}
    h   {self.calculate_hash()}
<!----END-BLOCK----!->
'''.encode() % self.data).strip()


class BlockChain:
    def __init__(self, data_file: File, hash_file: File, genesis_str: str) -> None:
        self.df, self.hf = data_file, hash_file
        self.gs = genesis_str
        self.__bc__: List[Block] = []

        self._on_init()

    def parse_entries(self) -> None:
        global START_BLOCK, START_DATA, END_BLOCK, END_DATA

        with open(self.df.full_path, 'rb') as in_file:
            r = in_file.read()
            in_file.close()

        with open(self.hf.full_path, 'r') as in_file:
            h = in_file.readlines()
            in_file.close()

        blocks = [
            b.replace(START_BLOCK.encode(), b'')
            for b in r.split(END_BLOCK.encode())
            if len(b)
        ]

        d = {}
        tp = {
            'd': lambda b: b,
            'i': lambda b: int(b.decode()),
            'ts': lambda b: int(b.decode()),
            'ph': lambda b: b.decode(),
            'h': lambda b: b.decode(),
        }

        for i, b in enumerate(blocks):
            d[i] = {
                (k := ls.split(b' ')[0]).decode(): tp[k.decode()](ls.replace(k, b'', 1).strip())
                for l in b.split(b'\n')
                if len(ls := l.strip().replace(b'\t', b' '))
            }

        assert sum([1 if D['d'].startswith(START_DATA.encode()) and D['d'].endswith(END_DATA.encode()) else 0 for D in d.values()]) == len(d)
        assert sum([1 if D['i'] == k else 0 for k, D in d.items()]) == len(d)
        assert len(blocks) == len(h)

        for k in d:
            d[k]['d'] = d[k]['d'].replace(START_DATA.encode(), b'').replace(END_DATA.encode(), b'')

        if not len(blocks):
            return

        # Parse as Blocks and save to __bc__.
        self.__bc__ = [
            Block(D['ph'], D['ts'], D['d'], D['i'])
            for D in d.values()
        ]

    def validate(self) -> None:
        with open(self.hf.full_path, 'r') as f_in:
            hfd = [l.split(' ') for l in f_in.readlines()]
            f_in.close()

        # Check all hashes w/ corresponding block in BC
        # Check all hfd hash values

        assert (Lhfd := len(hfd)) == (Lbc := len(self.__bc__)), f'{Lhfd=} {Lbc=}'
        h_const = b''

        for i, h in enumerate(hfd):
            assert len(h) == 2
            dfd_h, hfd_h = h
            hfd_h = hfd_h.strip()

            h_const += dfd_h.encode()
            e_hfd_h = hashlib.md5(h_const).hexdigest()
            assert e_hfd_h == hfd_h, f'BC.{i}.validate {i=} {e_hfd_h=}; {hfd_h=}'
            assert (b_dfd := self.__bc__[i].calculate_hash()) == dfd_h, f'BC.{i}.validate {i=} {b_dfd=}; {dfd_h=}'

            h_const += f' {e_hfd_h}\n'.encode()

    def add_genesis_block(self) -> None:
        if len(self.__bc__):
            return

        time = datetime.now().strftime(FRMT.DATETIME)
        frmt = {'time': time}

        self.__bc__ = [
            Block(
                prev_hash=hashlib.sha3_256(b'').hexdigest(),
                time_stamp=int(time),
                data=self.gs.format(**frmt).encode(),
                index=0
            )
        ]

    def h_hash(self) -> str:
        fh = open(self.hf.full_path, 'rb')
        h = hashlib.md5(fh.read()).hexdigest()
        fh.close()

        return h

    def add_data(self, data: bytes) -> None:
        assert (START_DATA.encode() not in data) and (END_DATA.encode() not in data)

        if not len(self.__bc__):
            self.add_genesis_block()

        new_block = Block(
            prev_hash=self.__bc__[-1].calculate_hash(),
            time_stamp=int(datetime.now().strftime(FRMT.DATETIME)),
            data=data,
            index=len(self.__bc__)
        )

        self.__bc__.append(new_block)

    def write(self) -> None:
        if not len(self.__bc__):
            return

        dfd = b'\n'.join([b.to_bytes() for b in self.__bc__])
        hfd = ''

        for b in self.__bc__:
            hfd += b.calculate_hash()
            hfd += f' {hashlib.md5(hfd.encode()).hexdigest()}\n'

        def write_to_file(file: File, data: bytes | str, mode: str) -> None:
            with open(file.full_path, mode) as out_file:
                out_file.write(data)
                out_file.close()

        write_to_file(self.df, dfd, 'wb')
        write_to_file(self.hf, hfd, 'w')

    def _on_init(self) -> None:
        def _mf(f: File) -> None:
            if not os.path.isdir(f.file_path):
                os.makedirs(f.file_path)

            if not os.path.isfile(f.full_path):
                open(f.full_path, 'xb').close()

        _mf(self.df)
        _mf(self.hf)

        self.parse_entries()
        self.validate()

    def __del__(self) -> None:
        self.write()


class LoggingLevel(Enum):
    ERROR = 0
    WARN  = 1
    INFO  = 2
    DEBUG = 3


@dataclass
class LogFile:
    file_struct: File
    hash_file:   File
    data:        BlockChain


class Logger(Thread):
    def __init__(self, freq: int = SETTINGS.LG_INTERVAL) -> None:
        assert freq >= 5, 'Logging frequency must be >=5s.'
        super(Logger, self).__init__()

        path = APPINFO.APP_DATA_PATH
        lf = f'{path}\\fc.{datetime.now().strftime(FRMT.DATETIME)}.FCSecLog'
        hf = f'{path}\\val\\{hashlib.sha256(lf.encode()).hexdigest()}.hf'
        gs = 'Log file created at {time}'

        self.__df__, self.__hf__ = File(lf), File(hf)
        self.__bc__ = BlockChain(self.__df__, self.__hf__, gs)
        self.__f__ = freq
        self.__buf__ = []

        self.__mdata__ = {}

        self.task = None
        self.start()

    def __del__(self) -> None:
        # Exceptions are ignored anyway.
        self.task.cancel()
        self._add_buf()
        self.join(0)

    def run(self) -> None:
        (task := Timer(self.__f__, self._add_buf)).start()
        self.task = task

    def _add_buf(self) -> None:
        if not len(self.__buf__):
            (task := Timer(self.__f__, self._add_buf)).start()
            self.task = task

            return

        buf, self.__buf__ = self.__buf__, []  # Empty self.__buf__ and copy contents to buf
        for entry in buf:
            self.__bc__.add_data(entry.encode())

        self.__bc__.write()

        (task := Timer(self.__f__, self._add_buf)).start()
        self.task = task

    @staticmethod
    @memoize
    def longest_level_name() -> int:
        level_map = {e.name: len(e.name) for e in LoggingLevel.__members__.values()}
        return max(level_map.values())

    def longest_sc_l(self, sc_l: int) -> int:
        self.__mdata__['lscl'] = sc_l if sc_l > self.__mdata__.get('lscl', 0) else self.__mdata__['lscl']
        return self.__mdata__['lscl']

    def log(
        self,
        ll: LoggingLevel,
        sc: str,
        data: str
    ) -> str:
        ll_str = ll.name.upper()
        ll_pad_l = Logger.longest_level_name() - len(ll_str)

        sc_pad_l = self.longest_sc_l(sc_l := len(sc)) - sc_l
        log_str = f'[{ll_str}]{(" " * ll_pad_l) if ll_pad_l > 0 else ""} [FC%s{sc}]{(" " * sc_pad_l) if sc_pad_l > 0 else ""}' % (
            '@' if len(sc) else ''
        )

        log_str += f' {datetime.now().strftime(FRMT.DATETIME)} {data}'
        self.__buf__.append(log_str)

        match ll:
            case LoggingLevel.ERROR:
                STDERR(log_str)

            case _:
                STDOUT(log_str)

        return log_str
