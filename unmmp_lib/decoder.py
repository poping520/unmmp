# -*- coding: utf-8 -*-
"""VM blob decoder + validator (dalvik-semantic instruction walker)."""

RET_KIND = {'return-void': 'V', 'return': 'I', 'return-wide': 'J', 'return-object': 'L'}

BINOPS = ['add', 'sub', 'mul', 'div', 'rem', 'and', 'or', 'xor', 'shl', 'shr', 'ushr']

FMT = {
 'nop': (1, '10x'), 'move': (1, '12x'), 'move/from16': (2, '22x'), 'move/16': (3, '32x'),
 'move-wide': (1, '12x'), 'move-wide/from16': (2, '22x'), 'move-wide/16': (3, '32x'),
 'move-object': (1, '12x'), 'move-object/from16': (2, '22x'), 'move-object/16': (3, '32x'),
 'move-result': (1, '11x'), 'move-result-wide': (1, '11x'), 'move-result-object': (1, '11x'),
 'move-exception': (1, '11x'), 'return-void': (1, '10x'), 'return': (1, '11x'),
 'return-wide': (1, '11x'), 'return-object': (1, '11x'),
 'const/4': (1, '11n'), 'const/16': (2, '21s'), 'const': (3, '31i'), 'const/high16': (2, '21h'),
 'const-wide/16': (2, '21s'), 'const-wide/32': (3, '31i'), 'const-wide': (5, '51i'),
 'const-wide/high16': (2, '21h'), 'const-string': (2, '21c'), 'const-string/jumbo': (3, '31c'),
 'const-class': (2, '21c'), 'monitor-enter': (1, '11x'), 'monitor-exit': (1, '11x'),
 'check-cast': (2, '21c'), 'instance-of': (2, '22c'), 'array-length': (1, '12x'),
 'new-instance': (2, '21c'), 'new-array': (2, '22c'), 'filled-new-array': (3, '35c'),
 'filled-new-array/range': (3, '3rc'), 'fill-array-data': (3, '31t'), 'throw': (1, '11x'),
 'goto': (1, '10t'), 'goto/16': (2, '20t'), 'goto/32': (3, '30t'),
 'packed-switch': (3, '31t'), 'sparse-switch': (3, '31t'),
 'cmpl-float': (2, '23x'), 'cmpg-float': (2, '23x'), 'cmpl-double': (2, '23x'),
 'cmpg-double': (2, '23x'), 'cmp-long': (2, '23x'),
 'if-eq': (2, '22t'), 'if-ne': (2, '22t'), 'if-lt': (2, '22t'), 'if-ge': (2, '22t'),
 'if-gt': (2, '22t'), 'if-le': (2, '22t'), 'if-eqz': (2, '21t'), 'if-nez': (2, '21t'),
 'if-ltz': (2, '21t'), 'if-gez': (2, '21t'), 'if-gtz': (2, '21t'), 'if-lez': (2, '21t'),
}
for nm_, sz, fm in [
        ('aget', 2, '23x'), ('aget-wide', 2, '23x'), ('aget-object', 2, '23x'),
        ('aget-boolean', 2, '23x'), ('aget-byte', 2, '23x'), ('aget-char', 2, '23x'),
        ('aget-short', 2, '23x'), ('aput', 2, '23x'), ('aput-wide', 2, '23x'),
        ('aput-object', 2, '23x'), ('aput-boolean', 2, '23x'), ('aput-byte', 2, '23x'),
        ('aput-char', 2, '23x'), ('aput-short', 2, '23x'),
        ('iget', 2, '22c'), ('iget-wide', 2, '22c'), ('iget-object', 2, '22c'),
        ('iget-boolean', 2, '22c'), ('iget-byte', 2, '22c'), ('iget-char', 2, '22c'),
        ('iget-short', 2, '22c'), ('iput', 2, '22c'), ('iput-wide', 2, '22c'),
        ('iput-object', 2, '22c'), ('iput-boolean', 2, '22c'), ('iput-byte', 2, '22c'),
        ('iput-char', 2, '22c'), ('iput-short', 2, '22c'),
        ('sget', 2, '21c'), ('sget-wide', 2, '21c'), ('sget-object', 2, '21c'),
        ('sget-boolean', 2, '21c'), ('sget-byte', 2, '21c'), ('sget-char', 2, '21c'),
        ('sget-short', 2, '21c'), ('sput', 2, '21c'), ('sput-wide', 2, '21c'),
        ('sput-object', 2, '21c'), ('sput-boolean', 2, '21c'), ('sput-byte', 2, '21c'),
        ('sput-char', 2, '21c'), ('sput-short', 2, '21c'),
        ('invoke-virtual', 3, '35c'), ('invoke-super', 3, '35c'), ('invoke-direct', 3, '35c'),
        ('invoke-static', 3, '35c'), ('invoke-interface', 3, '35c'),
        ('invoke-virtual/range', 3, '3rc'), ('invoke-super/range', 3, '3rc'),
        ('invoke-direct/range', 3, '3rc'), ('invoke-static/range', 3, '3rc'),
        ('invoke-interface/range', 3, '3rc')]:
    FMT[nm_] = (sz, fm)
for b in BINOPS:
    FMT['%s-int' % b] = (2, '23x'); FMT['%s-int/2addr' % b] = (1, '12x')
    FMT['%s-long' % b] = (2, '23x'); FMT['%s-long/2addr' % b] = (1, '12x')
for b in ('add', 'sub', 'mul', 'div', 'rem'):
    FMT['%s-float' % b] = (2, '23x'); FMT['%s-float/2addr' % b] = (1, '12x')
    FMT['%s-double' % b] = (2, '23x'); FMT['%s-double/2addr' % b] = (1, '12x')
    FMT['%s-int/lit16' % b] = (2, '22s'); FMT['%s-int/lit8' % b] = (2, '22b')
FMT['rsub-int'] = (2, '22s'); FMT['rsub-int/lit8'] = (2, '22b')
FMT['cmp-long/2addr'] = (1, '12x')  # nmmp-internal 2addr form of cmp-long
for b in ('and', 'or', 'xor'):
    FMT['%s-int/lit16' % b] = (2, '22s')
for b in ('and', 'or', 'xor'):
    FMT['%s-int/lit8' % b] = (2, '22b')
for b in ('shl', 'shr', 'ushr'):
    FMT['%s-int/lit8' % b] = (2, '22b')
for x in ('neg-float', 'neg-double'):
    FMT[x] = (1, '12x')
FMT['invoke-polymorphic'] = (4, '45cc'); FMT['invoke-polymorphic/range'] = (4, '4rcc')
FMT['invoke-custom'] = (3, '35c'); FMT['invoke-custom/range'] = (3, '3rc')
FMT['const-method-handle'] = (2, '21c'); FMT['const-method-type'] = (2, '21c')
for a, b in [('int', 'float'), ('int', 'double'), ('int', 'long'), ('int', 'byte'),
             ('int', 'char'), ('int', 'short'), ('long', 'int'), ('long', 'float'),
             ('long', 'double'), ('float', 'int'), ('float', 'long'), ('float', 'double'),
             ('double', 'int'), ('double', 'long'), ('double', 'float')]:
    FMT['%s-to-%s' % (a, b)] = (1, '12x')
for x in ('neg-int', 'not-int', 'neg-long', 'not-long'):
    FMT[x] = (1, '12x')


def shorty_of(sig):
    ret = sig[sig.rindex(')') + 1]
    args = sig[sig.index('(') + 1: sig.rindex(')')]

    def ch(c):
        return {'V': 'V', 'J': 'J', 'D': 'D', 'F': 'F', 'L': 'L', '[': 'L'}.get(c, 'I')
    s = ch(ret)
    i = 0
    while i < len(args):
        c = args[i]
        if c == 'L':
            s += 'L'; i = args.index(';', i) + 1; continue
        if c == '[':
            s += 'L'; j = i
            while args[j] == '[':
                j += 1
            i = args.index(';', j) + 1 if args[j] == 'L' else j + 1
            continue
        s += ch(c); i += 1
    return s



def payload_units(insns, pc):
    """Length in code units of a payload at pc, or None when the header does not fit."""
    size = len(insns)
    if pc >= size:
        return None
    inst = insns[pc]
    if inst not in (0x0100, 0x0200, 0x0300) or pc + 2 > size:
        return None
    if inst == 0x0300:
        if pc + 4 > size:
            return None
        w = insns[pc + 1]
        if w not in (1, 2, 4, 8):
            return None
        cnt = insns[pc + 2] | (insns[pc + 3] << 16)
        n = 4 + (w * cnt + 1) // 2
    elif inst == 0x0100:
        n = 4 + 2 * insns[pc + 1]
    else:
        n = 2 + 4 * insns[pc + 1]
    if n < 1 or pc + n > size:
        return None
    return n


def decode(insns, size, shorty, mapping):
    """Walk instructions; return (ok, err, ops). ops = [(pc, opcode_val, name, size)].

    Payload blocks (packed-switch 0x0100, sparse-switch 0x0200, array-data
    0x0300 headers) may sit anywhere in the stream (nmmp places them adjacent
    to the switch or at the end, dalvik-style). The walk advances linearly
    and skips any payload header encountered; switch/fill-array instructions
    validate their target payload then advance by their own size."""
    ops = []
    if size < 0 or size > len(insns):
        return False, 'LEN invalid size=%d' % size, ops
    pc = 0
    while pc < size:
        inst = insns[pc]
        # payload header encountered linearly: ident in high byte, low byte 0
        if inst in (0x0100, 0x0200, 0x0300):
            payload = payload_units(insns, pc)
            if payload is None or pc + payload > size:
                return False, 'PAYLOAD len at pc=%d' % pc, ops
            pc += payload
            continue
        opv = inst & 0xff
        name = mapping.get(opv)
        if name is None:
            return False, 'UNKNOWN op %#04x at pc=%d' % (opv, pc), ops
        if name in ('UNUSED', '?'):
            return False, '%s op %#04x at pc=%d' % (name, opv, pc), ops
        fmt = FMT.get(name)
        if fmt is None:
            return False, 'NOFORMAT %s at pc=%d' % (name, pc), ops
        sz, _kind = fmt
        if pc + sz > size:
            return False, 'LEN trunc %s at pc=%d' % (name, pc), ops
        ops.append((pc, opv, name, sz))
        if name in ('packed-switch', 'sparse-switch', 'fill-array-data'):
            if pc + 3 > size:
                return False, 'LEN trunc %s at pc=%d' % (name, pc), ops
            off32 = insns[pc + 1] | (insns[pc + 2] << 16)
            if off32 >= 0x80000000:
                off32 -= 0x100000000
            tgt = pc + off32
            if tgt < 0 or tgt >= size:
                return False, '%s target oob pc=%d' % (name, pc), ops
            hi = insns[tgt] >> 8
            want = {'packed-switch': 1, 'sparse-switch': 2, 'fill-array-data': 3}[name]
            if hi != want:
                return False, '%s ident %#x != %d pc=%d' % (name, hi, want, pc), ops
            payload = payload_units(insns, tgt)
            if payload is None or tgt + payload > size:
                return False, '%s payload truncated pc=%d' % (name, pc), ops
        pc += sz
    if pc != size:
        return False, 'LEN end=%d != %d' % (pc, size), ops
    if not ops:
        return False, 'EMPTY', ops
    # trailing nops (payload alignment padding after the final return) are legal
    idx = len(ops) - 1
    while idx >= 0 and ops[idx][2] == 'nop':
        idx -= 1
    last = ops[idx][2] if idx >= 0 else 'nop'
    if last.startswith('return'):
        want = shorty[0] if shorty else 'V'
        got = RET_KIND.get(last)
        if want == 'V' and got not in ('V', 'I', 'J'):
            # return/return-wide handlers double as no-store returns for void
            # methods in nmmp (retval already set by the last invoke)
            return False, 'RETMISMATCH shorty=%s last=%s' % (shorty, last), ops
        if want in ('J', 'D') and got not in ('J', 'I', 'V'):
            return False, 'RETWMISMATCH shorty=%s last=%s' % (shorty, last), ops
    elif last not in ('goto', 'goto/16', 'goto/32', 'throw'):
        return False, 'NORET last=%s' % last, ops
    return True, '', ops
