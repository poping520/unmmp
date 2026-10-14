# -*- coding: utf-8 -*-
"""Select supported native libraries and order APK dex inputs."""
import re


ABI_PREFER = ('arm64-v8a', 'armeabi-v7a', 'x86_64', 'x86')
MACHINE_ABI = {183: 'arm64-v8a', 40: 'armeabi-v7a', 62: 'x86_64', 3: 'x86'}
DEX_NAME = re.compile(r'classes(?:[2-9]|[1-9]\d+)?\.dex')


def pick_libs(apk, prefer=ABI_PREFER):
    """Return a complete library pair from the requested supported ABI list."""
    names = set(apk.namelist())
    for abi in prefer:
        nm, vm = 'lib/%s/libnmmp.so' % abi, 'lib/%s/libnmmvm.so' % abi
        if nm in names and vm in names:
            return nm, vm, abi
    return None, None, None


def dex_sort_key(name):
    """Standard classes*.dex first in numeric order, then custom dex names."""
    if DEX_NAME.fullmatch(name):
        return 0, int(name[7:-4]) if name != 'classes.dex' else 1, name
    return 1, 0, name


def dex_files(apk):
    return sorted((name for name in apk.namelist() if DEX_NAME.fullmatch(name)),
                  key=dex_sort_key)
