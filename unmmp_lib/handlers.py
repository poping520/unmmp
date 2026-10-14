# -*- coding: utf-8 -*-
"""Locate the computed-goto table used to observe VM dispatch boundaries."""
import struct

def _table_values(elf, va):
    ptr = elf.ptr
    vals = []
    for i in range(256):
        vals.append(elf.pointer(va + i * ptr))
    return vals


def _in_text_table(elf, vals):
    return all(elf.in_text(x) for x in vals)


def find_handler_table(elf):
    """Locate the 256-entry computed-goto table of libnmmvm.

    Primary: a run of >=256 consecutive R_*_RELATIVE relocations (4-byte slots
    on ELF32, 8-byte on ELF64) whose targets all land in .text. Fallback: raw
    scan of non-executable sections."""
    ptr = elf.ptr
    rel_t = elf.relative_reloc_type()
    rels = sorted(off for off, typ, _sym, _add in elf.relocs if typ == rel_t)
    runs = []
    prev = None
    start = None
    length = 0
    for off in rels:
        if prev is not None and off == prev + ptr:
            length += 1
        else:
            if length >= 100:
                runs.append((start, length))
            start = off
            length = 1
        prev = off
    if length >= 100:
        runs.append((start, length))

    cands = []
    for a, l in runs:
        for s in ({a, a + (l - 256) * ptr} if l >= 256 else {a}):
            try:
                vals = _table_values(elf, s)
            except (ValueError, struct.error):
                continue
            if _in_text_table(elf, vals):
                cands.append((s, vals))
    if not cands:
        # raw scan fallback
        for s in elf.sections:
            if s['typ'] == 8 or not s['flags'] & 2 or s['flags'] & 4:
                continue
            step = elf.ptr
            span = 256 * step
            for p in range(0, max(0, s['size'] - span + 1), step):
                try:
                    vals = _table_values(elf, s['addr'] + p)
                except (ValueError, struct.error):
                    continue
                if _in_text_table(elf, vals) and len(set(elf.code_addr(x) for x in vals)) >= 150:
                    cands.append((s['addr'] + p, vals))
                    break
            if cands:
                break
    if not cands:
        raise RuntimeError('vm handler table not found in libnmmvm.so')
    return cands[0]
