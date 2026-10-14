#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Recover official nmmp dex2c VM methods by emulating the target libraries."""
import argparse
import struct
import sys
import zipfile
from pathlib import Path

from unmmp_lib import apkprobe
from unmmp_lib.elf import Elf


HERE = Path(__file__).resolve().parent


def log(message):
    print(message, flush=True)


def load_inputs(path, prefer_abi=None):
    """Read all inputs before preparing any output directories."""
    if path.is_file():
        with zipfile.ZipFile(path) as apk:
            prefer = (prefer_abi,) if prefer_abi else apkprobe.ABI_PREFER
            nm_name, vm_name, abi = apkprobe.pick_libs(apk, prefer)
            if nm_name is None:
                raise RuntimeError('libnmmp.so/libnmmvm.so pair not found%s' %
                                   (' for ABI ' + prefer_abi if prefer_abi else ''))
            names = apkprobe.dex_files(apk)
            if not names:
                raise RuntimeError('no classes*.dex found in APK')
            nm, vm = Elf(apk.read(nm_name)), Elf(apk.read(vm_name))
            dex_inputs = [(name, apk.read(name)) for name in names]
    elif path.is_dir():
        names = sorted(path.glob('*.dex'), key=lambda p: apkprobe.dex_sort_key(p.name))
        if not names:
            raise RuntimeError('no dex files found in input directory')
        nm = Elf((path / 'libnmmp.so').read_bytes())
        vm = Elf((path / 'libnmmvm.so').read_bytes())
        abi = apkprobe.MACHINE_ABI.get(nm.machine)
        if prefer_abi and abi != prefer_abi:
            raise RuntimeError('input libraries use %s, requested %s' % (abi, prefer_abi))
        dex_inputs = [(p.name, p.read_bytes()) for p in names]
    else:
        raise RuntimeError('input does not exist: %s' % path)
    abi = apkprobe.MACHINE_ABI.get(nm.machine)
    if abi is None or vm.machine != nm.machine or vm.ptr != nm.ptr:
        raise RuntimeError('native libraries must use the same supported ABI')
    if nm.ptr != (8 if nm.machine in (183, 62) else 4):
        raise RuntimeError('ELF class does not match native architecture')
    log('[*] ABI: %s' % abi)
    return nm, vm, dex_inputs


def main(argv=None):
    parser = argparse.ArgumentParser(prog='unmmp',
                                    description='nmmp dex2c VM native-method restorer')
    parser.add_argument('input', help='APK or directory containing dex and native libraries')
    parser.add_argument('-o', '--out', required=True, help='output directory')
    parser.add_argument('--prefer-abi', choices=apkprobe.ABI_PREFER,
                        help='ABI to analyze (default order: %s)' % ', '.join(apkprobe.ABI_PREFER))
    parser.add_argument('--skip-dex', action='store_true', help='skip dex assembly')
    args = parser.parse_args(argv)

    inp, out = Path(args.input).resolve(), Path(args.out).resolve()
    if inp == out:
        parser.error('input and output paths must be different')
    # Preparing tool-owned output directories must never remove the input.
    try:
        from unmmp_lib.pipeline import is_output_directory, restore
        if out in inp.parents and is_output_directory(inp.relative_to(out).parts[0]):
            parser.error('input is inside a generated output directory')
        nm, vm, dex_inputs = load_inputs(inp, args.prefer_abi)
        restore(nm, vm, dex_inputs, str(out), str(HERE / 'tools'),
                skip_dex=args.skip_dex, log=log)
    except ImportError as exc:
        log('[!] missing dependency: %s; install requirements.txt' % exc)
        return 2
    except (OSError, RuntimeError, ValueError, IndexError, KeyError, struct.error,
            zipfile.BadZipFile) as exc:
        log('[!] %s' % exc)
        return 2
    return 0


if __name__ == '__main__':
    sys.exit(main())
