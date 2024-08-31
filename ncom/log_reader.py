from sc_data.logging import LogParser, File
from tkinter import filedialog
from std_imports import *

lFile = filedialog.askopenfilename(initialdir=f'{AppInfo.APPINFO.APP_DATA_PATH}')
logs = (lp := LogParser(File(lFile))).get_logs()
lines = [[t, l, s, d.replace('\u27f9', '->')] for (l, s, t, d) in logs]

labels = [
    'TIME',
    'LEVEL',
    'SC',
    'DATA'
]

lengths = [
    t if (t := max([len(l[0]) for l in lines])) > len(labels[0]) else len(labels[0]),
    t if (t := max([len(l[1]) for l in lines])) > len(labels[1]) else len(labels[1]),
    t if (t := max([len(l[2]) for l in lines])) > len(labels[2]) else len(labels[2]),
    len(labels[3])
]

const = '%s%s%s%s\n' % (
    labels[0].ljust(lengths[0] + 1),
    labels[1].ljust(lengths[1] + 1),
    labels[2].ljust(lengths[2] + 1),
    labels[3].ljust(lengths[3] + 1),
)

for t, l, s, d in lines:
    const += str(t).ljust(lengths[0] + 1)
    const += str(l).ljust(lengths[1] + 1)
    const += str(s).ljust(lengths[2] + 1)
    const += str(d)
    const += '\n'


def read_file(file: str) -> str:
    with open(file, 'r') as fIn:
        out = fIn.read()
        fIn.close()

    return out


def file_content(file: str) -> str:
    r = read_file(file).split('\n')

    lines = [
        '| %s |  %s' % (
            f'{i + 1}'.rjust(len(f'{len(r) + 1}')),
            line
        ) for i, line in enumerate(r)
    ]

    return '%s\n%s\n%s\n%s\n%s' % (
        '-' * max(map(lambda x: len(x), lines)),
        f'Content of {file}',
        '-' * max(map(lambda x: len(x), lines)),
        '\n'.join(lines).strip(),
        '-' * max(map(lambda x: len(x), lines))
    )


data = f'''From: {lp.__f_desc__[0].file_name}

Validation Data: 
{file_content(lp.__f_desc__[1].full_path)}

Logs:
{const}
'''

with open('lgparser.gitignore.txt', 'w') as outfile:
    outfile.write(data)
    outfile.close()


sf_execute(DummyLogger(), print, data)
