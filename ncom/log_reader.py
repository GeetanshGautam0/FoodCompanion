from sc_data.logging import LogParser, File
from tkinter import filedialog
from std_imports import *

lFile = filedialog.askopenfilename(initialdir=f'{AppInfo.APPINFO.APP_DATA_PATH}')
print(f'Calling LogParser on "{lFile}"')
logs = (lp := LogParser(File(lFile))).get_logs(print_progress=True)

labels = ['TIME', 'LEVEL', 'SC', 'DATA']
lengths = [len(l) for l in labels]
lines = []

RED = lambda i, t: l0 if (l0 := len(str(t))) > (l1 := lengths[i]) else l1

for i, (l, s, t, d) in enumerate(logs):
    if not ((i + 1) % 10):  # every 10 lines
        print(f'Processing log {i+1}/{len(logs)} (STEP 1/2; {(i+1)/len(logs) * 100}%)')

    lines.append((t, l, s, d.replace('\u27f9', '->')))

    lengths[0] = RED(0, t)
    lengths[1] = RED(1, l)
    lengths[2] = RED(2, s)
    lengths[3] = RED(3, d)


const = '%s%s%s%s\n' % (
    labels[0].ljust(lengths[0] + 1),
    labels[1].ljust(lengths[1] + 1),
    labels[2].ljust(lengths[2] + 1),
    labels[3].ljust(lengths[3] + 1),
)

for i, (t, l, s, d) in enumerate(lines):
    if not ((i + 1) % 10):  # every 10 lines
        print(f'Constructing logfile {i+1}/{len(logs)} (STEP 2/2; {(i+1)/len(logs) * 100}%)')

    print(lines)

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
