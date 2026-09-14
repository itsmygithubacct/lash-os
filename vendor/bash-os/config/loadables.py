#!/usr/bin/env python3
"""Parse loadable lists and resolve explicit build selections."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re

NAME = re.compile(r'[a-z_][a-z0-9_]*\Z')


def parse_list(path):
    entries = {}
    for number, line in enumerate(Path(path).read_text().split('\n'), 1):
        line = line.strip()
        if not line or line.startswith('#'):
            continue
        name, separator, doc = line.partition('|')
        name, doc = name.strip(), doc.strip()
        if not NAME.fullmatch(name):
            raise ValueError(f'{path}:{number}: invalid loadable name {name!r}')
        if name in entries:
            raise ValueError(f'{path}:{number}: duplicate loadable {name!r}')
        if any(ord(c) < 32 for c in doc):
            raise ValueError(f'{path}:{number}: control character in help text')
        entries[name] = doc or name
    return entries


def helpers_for(root, names):
    manifest = json.loads((root/'config/helpers.json').read_text())
    selected, libraries = set(), []
    names = list(names)

    def require(name):
        if name in selected:
            return
        if name not in manifest['helpers']:
            raise ValueError(f'unregistered helper: {name}')
        selected.add(name)
        for dependency in manifest['helpers'][name].get('requires', []):
            require(dependency)

    require('_jsmn')
    for name in names:
        entry = manifest['commands'].get(name, {})
        missing = set(entry.get('requires', [])) - set(names)
        if missing:
            raise ValueError(f'{name} requires builtin(s) in the selected list: '
                             + ', '.join(sorted(missing)))
        for helper in entry.get('helpers', []):
            require(helper)
        for library in entry.get('libs', []):
            if library not in libraries:
                libraries.append(library)
    for helper in sorted(selected):
        for library in manifest['helpers'][helper].get('libs', []):
            if library not in libraries:
                libraries.append(library)
    return sorted(selected), libraries


def words(values):
    result = []
    for value in values:
        for name in value.replace(',', ' ').split():
            if not NAME.fullmatch(name):
                raise ValueError(f'invalid loadable name {name!r}')
            result.append(name)
    return result


def selection(root, args):
    catalog = parse_list(root/'config/bash-loadables.list')
    profiles = json.loads((root/'config/profiles.json').read_text())
    for directory in os.environ.get('EXTRA_LOADABLES', '').split():
        directory = Path(directory)
        if not directory.is_absolute():
            directory = root/directory
        if not directory.is_dir():
            raise ValueError(f'EXTRA_LOADABLES: no such directory: {directory}')
        for source in directory.glob('*.c'):
            if NAME.fullmatch(source.stem):
                catalog.setdefault(source.stem, source.stem)

    def known(names):
        unknown = set(names) - catalog.keys()
        if unknown:
            raise ValueError('unknown loadable(s): '+', '.join(sorted(unknown)))
        return {name: catalog[name] for name in names}

    def profile(name, stack=()):
        if name not in profiles:
            raise ValueError(f'unknown profile {name!r}; use --list-profiles')
        if name in stack:
            raise ValueError('profile cycle: '+' -> '.join((*stack, name)))
        spec = profiles[name]
        entries = profile(spec['extends'], (*stack, name)) if 'extends' in spec else {}
        if 'list' in spec:
            entries.update(parse_list(root/'config'/spec['list']))
        entries.update(known(spec.get('include', [])))
        return entries

    if args.list_profiles:
        result = []
        for name, spec in profiles.items():
            entries = profile(name)
            helpers_for(root, entries)
            result.append({'name': name, 'count': len(entries), **spec})
        return result
    if args.list_loadables:
        return catalog
    if args.level is not None:
        if args.profile or args.list:
            raise ValueError('--level cannot be combined with --profile or --list')
        args.profile = ['shell', 'pure', 'core', 'device', 'server', 'full'][args.level]
    if args.profile and args.list:
        raise ValueError('--profile and --list select alternative bases; choose one')
    changed = bool(args.include or args.include_list or args.exclude)
    base = args.profile or ('shell' if args.include or args.include_list else 'full')
    if args.list:
        entries = parse_list(args.list)
        tag = Path(args.list).stem.removeprefix('bash-loadables').removeprefix('-')
        base = 'list:'+str(Path(args.list).resolve())
    else:
        entries = profile(base)
        tag = '' if base == 'full' else base
    entries.update(known(words(args.include)))
    for path in args.include_list:
        entries.update(parse_list(path))
    known(entries)
    excluded = words(args.exclude)
    known(excluded)
    for name in excluded:
        entries.pop(name, None)
    helpers, libraries = helpers_for(root, entries)
    lines = ''.join(f'{name}|{doc}\n' for name, doc in entries.items())
    digest = hashlib.sha256(lines.encode()).hexdigest()
    if changed:
        tag = 'custom-'+digest[:12]
    if args.name:
        tag = args.name
    if tag and not re.fullmatch(r'[a-zA-Z0-9][a-zA-Z0-9_.-]*', tag):
        raise ValueError('output name must contain letters, digits, dots, underscores or hyphens; use --name')
    return {'base': base, 'tag': tag, 'names': list(entries), 'entries': entries,
            'list': lines, 'sha256': digest, 'helpers': helpers, 'libraries': libraries}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest='command', required=True)
    parse = sub.add_parser('parse')
    parse.add_argument('path')
    select = sub.add_parser('select')
    select.add_argument('--root', type=Path, default=Path(__file__).resolve().parent.parent)
    select.add_argument('--profile')
    select.add_argument('--level', type=int, choices=range(6))
    select.add_argument('--list')
    select.add_argument('--include', action='append', default=[])
    select.add_argument('--include-list', action='append', default=[])
    select.add_argument('--exclude', action='append', default=[])
    select.add_argument('--name')
    select.add_argument('--list-profiles', action='store_true')
    select.add_argument('--list-loadables', action='store_true')
    args = parser.parse_args()
    try:
        if args.command == 'parse':
            for name, doc in parse_list(args.path).items():
                print(name+'\t'+doc)
        else:
            print(json.dumps(selection(args.root.resolve(), args)))
    except (OSError, ValueError) as error:
        parser.exit(2, f'loadables: {error}\n')


if __name__ == '__main__':
    main()
