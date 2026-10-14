# -*- coding: utf-8 -*-
"""Lift decoded VM blobs to smali method bodies."""
import re
import struct

from .decoder import decode, shorty_of


def type_words(desc):
    w = 0
    i = 0
    while i < len(desc):
        c = desc[i]
        if c in 'JD':
            w += 2; i += 1
        elif c == 'L':
            w += 1; i = desc.index(';', i) + 1
        elif c == '[':
            j = i
            while desc[j] == '[':
                j += 1
            w += 1
            i = j + (desc.index(';', j) + 1 - j if desc[j] == 'L' else 1)
        else:
            w += 1; i += 1
    return w


FIELD_VARIANT = {
    'J': '-wide', 'D': '-wide', 'L': '-object', '[': '-object',
    'Z': '-boolean', 'B': '-byte', 'C': '-char', 'S': '-short',
}


def field_variant(fty, base):
    return base + FIELD_VARIANT.get(fty[0], '')


def unescape(s):
    out = []
    for ch in s:
        if ch == '\n': out.append('\\n')
        elif ch == '\r': out.append('\\r')
        elif ch == '\t': out.append('\\t')
        elif ch == '"': out.append('\\"')
        elif ch == '\\': out.append('\\\\')
        elif ord(ch) > 0xffff:
            code = ord(ch)-0x10000
            out.append('\\u%04x\\u%04x' % (0xd800+(code>>10),0xdc00+(code&1023)))
        elif ord(ch) < 0x20 or ord(ch) > 0x7e:
            out.append('\\u%04x' % ord(ch))
        else:
            out.append(ch)
    return ''.join(out)


def s16(v):
    return v - 0x10000 if v >= 0x8000 else v


def s32(v):
    return v - 0x100000000 if v >= 0x80000000 else v


def parse_tries(so, vaddr_to_off, taddr):
    if not taddr or not isinstance(taddr, int):
        return []
    off = vaddr_to_off(taddr)
    tries_size, = struct.unpack_from('<H', so, off)
    pos = off + 4
    ranges = []
    for i in range(tries_size):
        start, cnt, hoff = struct.unpack_from('<iHH', so, pos)
        pos += 8
        ranges.append((start, start + cnt, hoff))
    hbase = off + 4 + tries_size * 8

    def uleb(p):
        r = 0; sh = 0
        while True:
            b = so[p]; p += 1
            r |= (b & 0x7f) << sh
            if not (b & 0x80):
                return r, p
            sh += 7

    def sleb(p):
        r = 0; sh = 0
        while True:
            b = so[p]; p += 1
            r |= (b & 0x7f) << sh
            sh += 7
            if not (b & 0x80):
                if b & 0x40:
                    r -= 1 << sh
                return r, p

    handlers = {}
    for (_, _, hoff) in ranges:
        if hoff in handlers:
            continue
        p = hbase + hoff
        sz, p = sleb(p)
        n = sz if sz >= 0 else -sz
        lst = []
        for k in range(n):
            tidx, p = uleb(p)
            addr, p = uleb(p)
            lst.append((tidx, addr))
        if sz <= 0:
            addr, p = uleb(p)
            lst.append((None, addr))
        handlers[hoff] = lst
    return [(s, e, handlers.get(ho, [])) for (s, e, ho) in ranges]


class Lifter(object):
    """pools: resolved nmmp pools; mapping: {int: opcode-name}."""

    def __init__(self, pools, mapping, so, vaddr_to_off, minf=None):
        self.pools = pools
        self.mapping = mapping
        self.so = so
        self.vaddr_to_off = vaddr_to_off
        self.minf = minf or {}

    def lift(self, meth, th):
        pools = self.pools
        insns_ea = th['insns']
        size = th['size']
        off = self.vaddr_to_off(insns_ea)
        insns = list(struct.unpack('<%dH' % size, self.so[off: off + size * 2]))
        shorty = shorty_of(meth['sig'])
        ok, err, ops = decode(insns, size, shorty, self.mapping)
        if not ok:
            return None, err, 0
        try_ranges = parse_tries(self.so, self.vaddr_to_off, th.get('tries'))
        aliases = getattr(pools, 'semantic_aliases', {})
        if aliases:
            from .typeflow import aliases_by_type
            overrides = aliases_by_type(insns, ops, pools, meth, th, aliases, try_ranges)
            ops = [(pc, op, overrides.get(pc, name), sz) for pc, op, name, sz in ops]
        handler_starts = set()
        catch_pcs = set()
        for (s, e, hs) in try_ranges:
            catch_pcs.add(s); catch_pcs.add(e)
            for (t, a) in hs:
                handler_starts.add(a)

        def minf(cref, name, proto):
            return self.minf.get((cref, name, proto), (False, False))[:2]

        lines = []
        payload_blocks = []
        labels = {}

        def lab(pc):
            if pc not in labels:
                labels[pc] = ':L%04x' % pc
            return labels[pc]

        label_pcs = set(handler_starts) | set(catch_pcs)
        for (pc, opv, nm, sz) in ops:
            ins = insns[pc]
            f1 = insns[pc + 1] if pc + 1 < size else 0
            f2 = insns[pc + 2] if pc + 2 < size else 0
            if nm == 'goto':
                d = ins >> 8
                label_pcs.add(pc + (d - 256 if d > 127 else d))
            elif nm == 'goto/16':
                label_pcs.add(pc + s16(f1))
            elif nm == 'goto/32':
                label_pcs.add(pc + s32(f1 | (f2 << 16)))
            elif nm.startswith('if-'):
                label_pcs.add(pc + s16(f1))
            elif nm in ('packed-switch', 'sparse-switch', 'fill-array-data'):
                tgt = pc + s32(f1 | (f2 << 16))
                label_pcs.add(tgt)
                hi = insns[tgt] >> 8
                if hi == 1:
                    n = insns[tgt + 1]
                    for i in range(n):
                        t = s32(insns[tgt + 4 + 2 * i] | (insns[tgt + 5 + 2 * i] << 16))
                        label_pcs.add(pc + t)
                elif hi == 2:
                    n = insns[tgt + 1]
                    for i in range(n):
                        t = s32(insns[tgt + 2 + 2 * n + 2 * i] |
                                (insns[tgt + 3 + 2 * n + 2 * i] << 16))
                        label_pcs.add(pc + t)

        maxreg = [0]

        def R(rn):
            maxreg[0] = max(maxreg[0], rn)
            return 'v%d' % rn

        def fmt_invoke(range_fmt, midx, ins, f2, decoded_name):
            m = pools.methods[midx]
            cref = m['cls']
            key_proto = m['proto']
            stat, iface = minf(cref, m['name'], key_proto)
            known = (cref, m['name'], key_proto) in self.minf
            aw = type_words(m['proto'][m['proto'].index('(') + 1: m['proto'].rindex(')')])
            args = None
            fmt2 = range_fmt
            for attempt in range(2):
                fmt2 = range_fmt != bool(attempt)
                if not fmt2:
                    cnt = (ins >> 12) & 0xf
                    g = (ins >> 8) & 0xf
                    nib = [f2 & 0xf, (f2 >> 4) & 0xf, (f2 >> 8) & 0xf, (f2 >> 12) & 0xf, g]
                    if cnt in (aw, aw + 1) and cnt <= 5:
                        args = nib[:cnt]
                        break
                else:
                    cnt = (ins >> 8) & 0xff
                    if cnt in (aw, aw + 1):
                        args = list(range(f2, f2 + cnt))
                        break
            if args is None:
                fmt2 = range_fmt
                if not fmt2:
                    cnt = (ins >> 12) & 0xf
                    g = (ins >> 8) & 0xf
                    nib = [f2 & 0xf, (f2 >> 4) & 0xf, (f2 >> 8) & 0xf, (f2 >> 12) & 0xf, g]
                    args = nib[:cnt]
                else:
                    cnt = (ins >> 8) & 0xff
                    args = list(range(f2, f2 + cnt))
            if m['name'] == '<init>':
                kind = 'invoke-direct'
            elif decoded_name.startswith(('invoke-direct', 'invoke-super')):
                flags = self.minf.get((cref, m['name'], key_proto), ())
                private = len(flags) > 2 and flags[2]
                kind = 'invoke-direct' if private else 'invoke-super'
            elif known:
                kind = ('invoke-static' if stat else
                        'invoke-interface' if iface else 'invoke-virtual')
            else:
                kind = decoded_name.split('/')[0]
            rng = '/range' if fmt2 else ''
            if fmt2 and args and args[0] <= args[-1]:
                argstr = '{v%d .. v%d}' % (args[0], args[-1])
            elif fmt2 and args:
                argstr = '{}'
            else:
                argstr = '{' + ', '.join(R(a) for a in args) + '}'
            for a in args:
                R(a)
            return '%s%s %s, %s->%s%s' % (kind, rng, argstr, cref, m['name'], m['proto'])

        for (pc, opv, name, sz) in ops:
            ins = insns[pc]
            f1 = insns[pc + 1] if pc + 1 < size else 0
            f2 = insns[pc + 2] if pc + 2 < size else 0
            f3 = insns[pc + 3] if pc + 3 < size else 0
            f4 = insns[pc + 4] if pc + 4 < size else 0
            if pc in label_pcs:
                lines.append(lab(pc))
            P = '    '
            if name == 'nop':
                lines.append('%snop' % P)
            elif name == 'const/4':
                dest = (ins >> 8) & 0xf
                lit = (ins >> 12)
                lit = lit - 16 if lit > 7 else lit
                lines.append('%sconst/4 %s, %#x' % (P, R(dest), lit))
            elif name in ('move', 'move-wide', 'move-object'):
                lines.append('%s%s %s, %s' % (P, name, R((ins >> 8) & 0xf), R((ins >> 12) & 0xf)))
            elif name in ('move/from16', 'move-wide/from16', 'move-object/from16'):
                lines.append('%s%s %s, %s' % (P, name, R(ins >> 8), R(f1)))
            elif name in ('move/16', 'move-wide/16', 'move-object/16'):
                lines.append('%s%s %s, %s' % (P, name, R(f1), R(f2)))
            elif name == 'move-result-object':
                nm2 = 'move-exception' if pc in handler_starts else 'move-result-object'
                lines.append('%s%s %s' % (P, nm2, R(ins >> 8)))
            elif name == 'move-exception':
                lines.append('%smove-exception %s' % (P, R(ins >> 8)))
            elif name in ('move-result', 'move-result-wide'):
                lines.append('%s%s %s' % (P, name, R(ins >> 8)))
            elif name == 'return-void':
                lines.append('%sreturn-void' % P)
            elif name in ('return', 'return-object', 'return-wide'):
                v = ins >> 8
                want = shorty[0] if shorty else 'V'
                if want == 'V':
                    lines.append('%sreturn-void' % P)
                elif want in 'JD':
                    lines.append('%sreturn-wide %s' % (P, R(v)))
                elif want == 'L':
                    lines.append('%sreturn-object %s' % (P, R(v)))
                else:
                    lines.append('%sreturn %s' % (P, R(v)))
            elif name == 'const/16':
                lines.append('%sconst/16 %s, %#x' % (P, R(ins >> 8), s16(f1)))
            elif name == 'const':
                lines.append('%sconst %s, %#x' % (P, R(ins >> 8), s32(f1 | (f2 << 16))))
            elif name == 'const/high16':
                lines.append('%sconst/high16 %s, %#x' % (P, R(ins >> 8), f1 << 16))
            elif name == 'const-wide/16':
                lines.append('%sconst-wide/16 %s, %#x' % (P, R(ins >> 8), s16(f1)))
            elif name == 'const-wide/32':
                lines.append('%sconst-wide/32 %s, %#x' % (P, R(ins >> 8), s32(f1 | (f2 << 16))))
            elif name == 'const-wide':
                val = f1 | (f2 << 16) | (f3 << 32) | (f4 << 48)
                if val >= 1 << 63:
                    val -= 1 << 64
                lines.append('%sconst-wide %s, %#xL' % (P, R(ins >> 8), val))
            elif name == 'const-wide/high16':
                lines.append('%sconst-wide/high16 %s, %#xL' % (P, R(ins >> 8), f1 << 48))
            elif name == 'const-string':
                lines.append('%sconst-string %s, "%s"' % (
                    P, R(ins >> 8), unescape(pools.const_strings[f1])))
            elif name == 'const-string/jumbo':
                idx = f1 | (f2 << 16)
                lines.append('%sconst-string/jumbo %s, "%s"' % (
                    P, R(ins >> 8), unescape(pools.const_strings[idx])))
            elif name == 'const-class':
                lines.append('%sconst-class %s, %s' % (P, R(ins >> 8), pools.types[f1]))
            elif name == 'check-cast':
                lines.append('%scheck-cast %s, %s' % (P, R(ins >> 8), pools.types[f1]))
            elif name == 'instance-of':
                lines.append('%sinstance-of %s, %s, %s' % (
                    P, R((ins >> 8) & 0xf), R((ins >> 12) & 0xf), pools.types[f1]))
            elif name == 'array-length':
                lines.append('%sarray-length %s, %s' % (P, R((ins >> 8) & 0xf), R((ins >> 12) & 0xf)))
            elif name == 'new-instance':
                lines.append('%snew-instance %s, %s' % (P, R(ins >> 8), pools.types[f1]))
            elif name == 'new-array':
                lines.append('%snew-array %s, %s, %s' % (
                    P, R((ins >> 8) & 0xf), R((ins >> 12) & 0xf), pools.types[f1]))
            elif name == 'filled-new-array':
                cnt = (ins >> 12) & 0xf
                g = (ins >> 8) & 0xf
                nib = [f2 & 0xf, (f2 >> 4) & 0xf, (f2 >> 8) & 0xf, (f2 >> 12) & 0xf, g]
                args = nib[:cnt]
                lines.append('%sfilled-new-array {%s}, %s' % (
                    P, ', '.join(R(a) for a in args), pools.types[f1]))
            elif name == 'filled-new-array/range':
                cnt = (ins >> 8) & 0xff
                if cnt == 0:
                    lines.append('%sfilled-new-array/range {}, %s' % (P, pools.types[f1]))
                else:
                    R(f2); R(f2 + cnt - 1)
                    lines.append('%sfilled-new-array/range {v%d .. v%d}, %s' % (
                        P, f2, f2 + cnt - 1, pools.types[f1]))
            elif name.startswith('invoke'):
                lines.append(P + fmt_invoke('/range' in name, f1, ins, f2, name))
            elif name == 'fill-array-data':
                lines.append('%sfill-array-data %s, %s' % (P, R(ins >> 8), lab(pc + s32(f1 | (f2 << 16)))))
            elif name == 'packed-switch':
                lines.append('%spacked-switch %s, %s' % (P, R(ins >> 8), lab(pc + s32(f1 | (f2 << 16)))))
            elif name == 'sparse-switch':
                lines.append('%ssparse-switch %s, %s' % (P, R(ins >> 8), lab(pc + s32(f1 | (f2 << 16)))))
            elif name == 'goto':
                dd = ins >> 8
                dd = dd - 256 if dd > 127 else dd
                lines.append('%sgoto %s' % (P, lab(pc + dd)))
            elif name == 'goto/16':
                lines.append('%sgoto/16 %s' % (P, lab(pc + s16(f1))))
            elif name == 'goto/32':
                lines.append('%sgoto/32 %s' % (P, lab(pc + s32(f1 | (f2 << 16)))))
            elif name.startswith('if-') and name.endswith('z'):
                lines.append('%s%s %s, %s' % (P, name, R(ins >> 8), lab(pc + s16(f1))))
            elif name.startswith('if-'):
                lines.append('%s%s %s, %s, %s' % (P, name, R((ins >> 8) & 0xf),
                                                  R((ins >> 12) & 0xf), lab(pc + s16(f1))))
            elif name in ('cmp-long', 'cmpl-float', 'cmpg-float', 'cmpl-double', 'cmpg-double'):
                lines.append('%s%s %s, %s, %s' % (P, name, R(ins >> 8), R(f1 & 0xff), R(f1 >> 8)))
            elif name == 'cmp-long/2addr':
                lines.append('%scmp-long %s, %s, %s' % (
                    P, R((ins >> 8) & 0xf), R((ins >> 8) & 0xf), R((ins >> 12) & 0xf)))
            elif name.startswith('aget') or name.startswith('aput'):
                lines.append('%s%s %s, %s, %s' % (P, name, R(ins >> 8), R(f1 & 0xff), R(f1 >> 8)))
            elif name.startswith('iget') or name.startswith('iput'):
                base = name.split('-')[0]
                fld = pools.fields[f1]
                v = field_variant(fld['type'], base)
                lines.append('%s%s %s, %s, %s->%s:%s' % (
                    P, v, R((ins >> 8) & 0xf), R((ins >> 12) & 0xf),
                    fld['cls'], fld['name'], fld['type']))
            elif name.startswith('sget') or name.startswith('sput'):
                base = name.split('-')[0]
                fld = pools.fields[f1]
                v = field_variant(fld['type'], base)
                lines.append('%s%s %s, %s->%s:%s' % (
                    P, v, R(ins >> 8), fld['cls'], fld['name'], fld['type']))
            elif name.startswith('monitor'):
                lines.append('%s%s %s' % (P, name, R(ins >> 8)))
            elif name == 'throw':
                lines.append('%sthrow %s' % (P, R(ins >> 8)))
            elif name in ('neg-int', 'not-int', 'neg-long', 'not-long', 'neg-float', 'neg-double'):
                lines.append('%s%s %s, %s' % (P, name, R((ins >> 8) & 0xf), R((ins >> 12) & 0xf)))
            elif name.endswith('/2addr') or '-to-' in name:
                lines.append('%s%s %s, %s' % (P, name, R((ins >> 8) & 0xf), R((ins >> 12) & 0xf)))
            elif name.endswith('-int/lit16') or name == 'rsub-int':
                lines.append('%s%s %s, %s, %#x' % (P, name, R((ins >> 8) & 0xf),
                                                   R((ins >> 12) & 0xf), s16(f1)))
            elif name.endswith('-int/lit8'):
                lit = f1 >> 8
                lit = lit - 256 if lit > 127 else lit
                lines.append('%s%s %s, %s, %#x' % (P, name, R(ins >> 8), R(f1 & 0xff), lit))
            else:
                lines.append('%s%s %s, %s, %s' % (P, name, R(ins >> 8), R(f1 & 0xff), R(f1 >> 8)))
            if name in ('packed-switch', 'sparse-switch', 'fill-array-data'):
                tgt = pc + s32(f1 | (f2 << 16))
                hi = insns[tgt] >> 8
                pl = [lab(tgt)]
                if hi == 1:
                    n = insns[tgt + 1]
                    first = s32(insns[tgt + 2] | (insns[tgt + 3] << 16))
                    pl.append('%s.packed-switch %#x' % (P, first))
                    for i in range(n):
                        t = s32(insns[tgt + 4 + 2 * i] | (insns[tgt + 5 + 2 * i] << 16))
                        pl.append('    :L%04x' % (pc + t))
                    pl.append('%s.end packed-switch' % P)
                elif hi == 2:
                    n = insns[tgt + 1]
                    pl.append('%s.sparse-switch' % P)
                    for i in range(n):
                        k = s32(insns[tgt + 2 + 2 * i] | (insns[tgt + 3 + 2 * i] << 16))
                        t = s32(insns[tgt + 2 + 2 * n + 2 * i] |
                                (insns[tgt + 3 + 2 * n + 2 * i] << 16))
                        pl.append('    %#x -> :L%04x' % (k, pc + t))
                    pl.append('%s.end sparse-switch' % P)
                elif hi == 3:
                    w = insns[tgt + 1] & 0xff
                    cnt = insns[tgt + 2] | (insns[tgt + 3] << 16)
                    data = insns[tgt + 4: tgt + 4 + (w * cnt + 1) // 2]
                    pl.append('%s.array-data %d' % (P, w))
                    if w == 1:
                        bs = b''.join(struct.pack('<H', x) for x in data)[:cnt]
                        for b in bs:
                            pl.append('    %#x' % b)
                    elif w == 2:
                        for x in data[:cnt]:
                            pl.append('    %#x' % (x & 0xffff))
                    elif w == 4:
                        for i in range(cnt):
                            pl.append('    %#x' % ((data[i * 2] | (data[i * 2 + 1] << 16)) & 0xffffffff))
                    elif w == 8:
                        for i in range(cnt):
                            value = sum(data[i * 4 + j] << (16 * j) for j in range(4))
                            pl.append('    %#xL' % value)
                    pl.append('%s.end array-data' % P)
                payload_blocks.extend(pl)
        # Place payload directives after executable instructions.
        lines.extend(payload_blocks)
        for (s, e, hs) in try_ranges:
            for (t, a) in hs:
                tref = 'all' if t is None else pools.types[t] if t < len(pools.types) else 'all'
                if t is None:
                    lines.append('    .catchall {:L%04x .. :L%04x} %s' % (s, e, lab(a)))
                else:
                    lines.append('    .catch %s {:L%04x .. :L%04x} %s' % (tref, s, e, lab(a)))
        if size in catch_pcs:
            lines.append(lab(size))
        # sanity: every referenced label must have a definition line, else drop
        blob_txt = '\n'.join(lines)
        defined = set(ln.strip() for ln in lines if ln.strip().startswith(':L'))
        ok_labels = True
        for m0 in re.finditer(r':L[0-9a-f]{4,}', blob_txt):
            if m0.group(0) not in defined:
                ok_labels = False
                break
        if not ok_labels:
            return None, 0, 0
        return '\n'.join(lines), maxreg[0], size
