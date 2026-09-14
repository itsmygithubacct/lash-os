#!/usr/bin/env python3
"""Select and flatten helper sources without pulling them into unrelated lists."""
from pathlib import Path
import re
import shutil
import sys
from loadables import helpers_for

mode, root, destination, *names = sys.argv[1:]
root = Path(root)
try:
    selected, libraries = helpers_for(root, names)
except ValueError as error:
    raise SystemExit(str(error))
if mode == '--libs':
    # Revisit the builtin archive because some helper and wrapper calls form cycles.
    if libraries or any(list((root/'loadables'/h).glob('*.c')) for h in selected):
        print('-Wl,--start-group -lbuiltins ' + ' '.join(libraries) + ' -Wl,--end-group')
    raise SystemExit(0)
if mode != '--stage': raise SystemExit('expected --stage or --libs')
stage = Path(destination)
objects = []
for name in sorted(selected):
    directory = root/'loadables'/name
    if not directory.is_dir(): raise SystemExit(f'missing helper directory: {name}')
    sources = sorted(p for p in directory.iterdir() if p.is_file() and p.suffix in ['.c','.h','.data'])
    headers = {p.name: name+'_'+p.name for p in sources if p.suffix in ['.h','.data']}
    for source in sources:
        flat = name+'_'+source.name
        target = stage/'builtins'/flat
        if source.suffix == '.data':
            shutil.copyfile(source, target)
            continue
        text = source.read_text()
        def include(match):
            path = match[2]
            if path.startswith(name+'/'): path = path[len(name)+1:]
            return match[1]+'"'+headers.get(path, match[2])+'"'
        text = re.sub(r'(^\s*#\s*include\s*)"([^"\n]+)"', include, text, flags=re.M)
        target.write_text(text)
        if source.suffix == '.h': shutil.copyfile(target,stage/'examples/loadables'/flat)
        if source.suffix == '.c': objects.append(name+'_'+source.stem+'.o')
(stage/'builtins/.helper-objs').write_text(' '.join(objects)+' ')
print(f'helpers: {", ".join(sorted(selected))}; {len(objects)} objects')
