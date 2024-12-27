import hashlib, os
from .struct import File
from dataclasses import dataclass
from datetime import datetime
from .constants import FRMT, SZ
from .appinfo import APPINFO
from .settings import SETTINGS
from typing import List, Tuple, Any
from .functions import memoize, STDOUT, STDERR
from threading import Thread, Timer
from enum import Enum


START_BLOCK = '--------BEGIN-BLOCK--------'
START_DATA = '--------BEGIN-DATA--------'
START_META = '--------BEGIN-META--------'
END_BLOCK = '--------END-BLOCK--------'
END_DATA = '--------END-DATA--------'
END_META = '--------END-META--------'


@dataclass
class Block:
    prev_hash:      str
    time_stamp:     int
    data:           bytes
    index:          int

    def calculate_hash(self) -> str:
        hash_string = str(self.index) + str(self.time_stamp) + str(self.prev_hash)
        return hashlib.sha3_256(hash_string.encode() + self.data).hexdigest()

    def get_meta(self) -> str:
        return '.'.join([str(bI) for bI in [self.index, self.prev_hash, self.calculate_hash(), self.time_stamp]])

    def check_data(self) -> None:
        global START_BLOCK, START_DATA, START_META, END_BLOCK, END_DATA, END_META
        assert sum([
            self.data.count(s.encode())
            for s in (START_META, START_BLOCK, START_DATA, END_META, END_BLOCK, END_DATA)
        ]) == 0

    def to_bytes(self) -> bytes:
        global START_BLOCK, START_DATA, START_META, END_BLOCK, END_DATA, END_META
        self.check_data()

        return (f'''{START_BLOCK}{START_META}{self.get_meta()}{END_META}{START_DATA}%b{END_DATA}{END_BLOCK}'''.encode() % self.data).strip()


def _compute_hf(blocks: List[Block], f_name: str) -> str:
    const = b''

    for block in blocks:
        const += hashlib.md5(block.get_meta().encode()).hexdigest().encode()
        const += hashlib.md5(const).hexdigest().encode()

    s0 = len(const)
    s1 = hashlib.sha3_512(const).hexdigest()
    s2 = hashlib.md5(f_name.encode()).hexdigest()

    return f'BC.HF<{s0}, {s1}, {s2}>'


class BlockChain:
    def __init__(self, data_file: File, hash_file: File, genesis_str: str) -> None:
        self.df, self.hf = data_file, hash_file
        self.gs = genesis_str
        self.__bc__: List[Block] = []

        self._on_init()

    def parse_entries(self) -> None:
        global START_BLOCK, START_DATA, END_BLOCK, END_DATA, START_META, END_META

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

        for block in blocks:
            meta = block[block.index((smb := START_META.encode())) + len(smb):block.index(END_META.encode()):].decode()
            data = block[block.index((smb := START_DATA.encode())) + len(smb):block.index(END_DATA.encode()):]

            ind, ph, ch, ts = meta.split('.')
            ind = int(ind)
            assert len(self.__bc__) == ind
            self.__bc__.append(Block(ph, ts, data, ind))

        if len(self.__bc__):
            self.validate()

    def validate(self) -> None:
        with open(self.hf.full_path, 'r') as f_in:
            hf = f_in.read()
            f_in.close()

        assert hf == (chf := _compute_hf(self.__bc__, self.hf.file_name)), f'{hf} != {chf}'

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
        hfd = _compute_hf(self.__bc__, self.hf.file_name)

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
    def __init__(self, freq: int = SETTINGS.LG_INTERVAL, is_server: bool = False) -> None:
        assert freq >= 5, 'Logging frequency must be >=5s.'
        super(Logger, self).__init__()

        path = APPINFO.APP_DATA_PATH
        lf = f'{path}\\{"server" if is_server else "client"}\\fc.{datetime.now().strftime(FRMT.DATETIME)}.FCSecLog'
        hf = f'{path}\\val\\{hashlib.sha256(lf.encode()).hexdigest()}.hf'
        gs = 'Log file created at {time}'

        self.__df__, self.__hf__ = File(lf), File(hf)
        self.__bc__ = BlockChain(self.__df__, self.__hf__, gs)
        self.__f__ = freq
        self.__buf__ = []

        self.__mdata__ = {}
        self.__stopped = False

        self.task = None
        self.start()

    def __del__(self) -> None:
        # Exceptions are ignored anyway.
        self.task.cancel()
        self._add_buf()
        self.join(0)

    def stop(self) -> None:
        try:
            self.task.cancel()
        except Exception as E:
            self.log(LoggingLevel.ERROR, 'AUTO-LOG', f'Failed to execute ST_TASK_1: {E.__class__.__name__}<{str(E)}>')

        self.__stopped = True
        buf, self.__buf__ = self.__buf__, []  # Empty self.__buf__ and copy contents to buf
        for entry in buf:
            self.__bc__.add_data(entry.encode())

        self.__bc__.write()
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

        if not (logging_level_enabled := getattr(APPINFO, f'LG_LOG_{ll_str}')):
            return ''

        sc_pad_l = self.longest_sc_l(sc_l := len(sc)) - sc_l
        log_str = f'[{ll_str}]{(" " * ll_pad_l) if ll_pad_l > 0 else ""} [FC%s{sc}]{(" " * sc_pad_l) if sc_pad_l > 0 else ""}' % (
            '@' if len(sc) else ''
        )

        log_str += f' {datetime.now().strftime(FRMT.DATETIME)} {data}'

        if not self.__stopped:
            self.__buf__.append(log_str)
        else:
            log_str = f'[NOT SAVED] {log_str}'

        match ll:
            case LoggingLevel.ERROR:
                STDERR(log_str)

            case _:
                STDOUT(log_str)

        return log_str


class LogParser:
    def __init__(self, log_file: File) -> None:
        assert os.path.isfile(log_file.full_path), 'Log file not found.'
        hf = File(f'{APPINFO.APP_DATA_PATH}\\val\\{hashlib.sha256(log_file.full_path.encode()).hexdigest()}.hf')
        assert os.path.isfile(hf.full_path)

        self.__f_desc__ = (log_file, hf)
        self.__bc__ = BlockChain(self.__f_desc__[0], self.__f_desc__[1], '')

    def get_logs(self, print_progress: bool = False) -> List[Tuple[Any, ...]]:
        if print_progress:
            print('Tokenizing logs. Please be patient as this can take a long time.')

        self.__bc__.parse_entries()

        if not len(self.__bc__.__bc__):
            return []

        if print_progress:
            print('Validating logs and checking for tampering. Please be patient as this can take a long time.')

        self.__bc__.validate()
        parsed = self.__bc__.__bc__
        del self.__bc__

        def parser(l: str) -> Tuple[Any, ...]:
            s_start_ctr = 0
            s_start = []
            s_end = []
            in_s = False

            for i, c in enumerate(l):
                if print_progress and not ((i + 1) % 10):  # every 10 lines
                    print(f'Parsing log {i + 1}/{len(l)} (STEP 1/2; {(i + 1) / len(l) * 100}%)')

                if not in_s and c == '[':
                    assert s_start_ctr < 2

                    in_s = True
                    s_start_ctr += 1
                    s_start.append(i + 1)

                elif in_s and c == ']':
                    in_s = False
                    s_end.append(i)

                elif not in_s and s_start_ctr == 2 and c.isnumeric():
                    # Time code
                    #   Not in a '[' section
                    #   Already parsed to sections.

                    s_start.append(i)
                    s_start_ctr += 1
                    break

            assert len(s_start) and len(s_end) == 2, f'{s_start} {s_end} {l}'
            s_end.append(s_start[-1] + SZ.DATETIME)

            ret = [l[s:e] for s, e in zip(s_start, s_end)]
            ret.append(l[s_end[-1]::].strip())

            return (*ret, )

        out = [
            parser(block.data.decode())
            for block in parsed
            if block.index > 0
        ]

        # out.insert(0, parser(parsed[0].data.decode()))

        del self
        return out
