# -*- coding: utf-8 -*-
"""Dalvik effects used as the oracle for native single-instruction trials."""
import math
import struct

from .decoder import FMT
from .dalvik import NAMES
from .emulate import EmulationError
from unicorn import UC_MEM_READ, UC_MEM_WRITE


def signed(value, bits):
    value &= (1 << bits) - 1
    return value - (1 << bits) if value & (1 << (bits - 1)) else value


def float_of(value, wide):
    n = 8 if wide else 4
    return struct.unpack('<d' if wide else '<f', (value & ((1 << (8*n))-1)).to_bytes(n, 'little'))[0]


def float_bits(value, wide):
    try:
        return int.from_bytes(struct.pack('<d' if wide else '<f', value), 'little')
    except OverflowError:
        return int.from_bytes(struct.pack('<f', math.copysign(float('inf'), value)), 'little')


def trunc_div(a, b):
    if not b:
        raise ZeroDivisionError
    return (abs(a) // abs(b)) * (-1 if (a < 0) != (b < 0) else 1)


def numeric_effect(name, high, words, values):
    size, fmt = FMT[name]
    a, b = high & 15, high >> 4
    aa = high
    w1, w2, w3, w4 = (list(words) + [0]*4)[:4]
    if fmt == '12x':
        dst, s1, s2 = a, a, b
    elif fmt == '23x':
        dst, s1, s2 = aa, w1 & 255, w1 >> 8
    elif fmt in ('22s', '22b'):
        dst = a if fmt == '22s' else aa
        s1 = b if fmt == '22s' else w1 & 255
        s2 = None
    else:
        dst, s1, s2 = aa, 0, 0
    pc, writes = size, {}

    def put(reg, value, kind='int'):
        if kind == 'float':
            value = (values[reg] & 0xffffffff00000000) | (value & 0xffffffff)
        elif kind == 'int':
            value &= 0xffffffff
        else:
            value &= 0xffffffffffffffff
        if value != values[reg]:
            writes[reg] = value

    if name == 'nop':
        pass
    elif name.startswith('move') and not name.startswith(('move-result', 'move-exception', 'move-object')):
        if fmt == '12x':
            dst, source = a, b
        elif fmt == '22x':
            dst, source = aa, w1
        else:
            dst, source = w1, w2
        put(dst, values[source], 'long' if 'wide' in name else 'int')
    elif name.startswith('const') and name not in ('const-string', 'const-string/jumbo', 'const-class', 'const-method-handle', 'const-method-type'):
        wide = name.startswith('const-wide')
        if name == 'const/4':
            dst, value = a, signed(b, 4)
        elif name.endswith('/16'):
            value = signed(w1, 16)
        elif name.endswith('high16'):
            value = w1 << (48 if wide else 16)
        elif name == 'const-wide':
            value = w1 | w2 << 16 | w3 << 32 | w4 << 48
        else:
            value = signed(w1 | w2 << 16, 32)
        put(dst, value, 'long' if wide else 'int')
    elif name.startswith('goto'):
        pc = signed(high, 8) if name == 'goto' else signed(w1, 16) if name == 'goto/16' else signed(w1 | w2 << 16, 32)
    elif name.startswith('if-'):
        cond = name[3:]
        if cond.endswith('z'):
            lhs, rhs = signed(values[aa], 32), 0
            cond = cond[:-1]
        else:
            lhs, rhs = signed(values[a], 32), signed(values[b], 32)
        take = {'eq': lhs == rhs, 'ne': lhs != rhs, 'lt': lhs < rhs,
                'ge': lhs >= rhs, 'gt': lhs > rhs, 'le': lhs <= rhs}[cond]
        pc = signed(w1, 16) if take else 2
    elif name.startswith(('cmp-long', 'cmpl-', 'cmpg-')):
        if name.startswith('cmp-long'):
            lhs, rhs = signed(values[s1], 64), signed(values[s2], 64)
        else:
            wide = name.endswith('double')
            lhs, rhs = float_of(values[s1], wide), float_of(values[s2], wide)
        value = (-1 if name.startswith('cmpl') else 1) if isinstance(lhs, float) and (math.isnan(lhs) or math.isnan(rhs)) else (lhs > rhs) - (lhs < rhs)
        put(dst, value)
    elif '-to-' in name:
        source, target = name.split('-to-')
        v = values[b]
        if source in ('int', 'long'):
            v = signed(v, 64 if source == 'long' else 32)
        else:
            v = float_of(v, source == 'double')
        if target in ('float', 'double'):
            put(a, float_bits(float(v), target == 'double'), target)
        else:
            bits = {'long': 64, 'int': 32, 'byte': 8, 'char': 16, 'short': 16}[target]
            if isinstance(v, float):
                limit = 1 << (bits-1)
                v = 0 if math.isnan(v) else max(-limit, min(limit-1, int(v) if math.isfinite(v) else (limit if v > 0 else -limit)))
            if target == 'char':
                v &= 0xffff
            else:
                v = signed(v, bits)
            put(a, v, 'long' if target == 'long' else 'int')
    elif name.startswith(('neg-', 'not-')):
        op, kind = name.split('-')
        v = values[b]
        if kind in ('float', 'double'):
            v ^= 1 << (63 if kind == 'double' else 31)
        else:
            v = -v if op == 'neg' else ~v
        put(a, v, kind)
    elif name.split('-', 1)[0] in ('add', 'sub', 'rsub', 'mul', 'div', 'rem', 'and', 'or', 'xor', 'shl', 'shr', 'ushr'):
        op, tail = name.split('-', 1)
        kind = tail.split('/')[0]
        bits = 64 if kind == 'long' else 32
        lhs = values[s1]
        rhs = signed(w1, 16) if fmt == '22s' else signed(w1 >> 8, 8) if fmt == '22b' else values[s2]
        if kind in ('float', 'double'):
            wide = kind == 'double'
            lhs, rhs = float_of(lhs, wide), float_of(rhs, wide)
            if op == 'add': v = lhs + rhs
            elif op == 'sub': v = lhs - rhs
            elif op == 'mul': v = lhs * rhs
            elif op == 'div':
                v = lhs / rhs if rhs else float('nan') if not lhs else math.copysign(float('inf'), lhs * math.copysign(1.0, rhs))
            else:
                try: v = math.fmod(lhs, rhs)
                except ValueError: v = float('nan')
            put(dst, float_bits(v, wide), kind)
        else:
            lhs, rhs = signed(lhs, bits), signed(rhs, bits)
            if op == 'add': v = lhs + rhs
            elif op == 'sub': v = lhs - rhs
            elif op == 'rsub': v = rhs - lhs
            elif op == 'mul': v = lhs * rhs
            elif op == 'div': v = trunc_div(lhs, rhs)
            elif op == 'rem': v = lhs - trunc_div(lhs, rhs) * rhs
            elif op == 'and': v = lhs & rhs
            elif op == 'or': v = lhs | rhs
            elif op == 'xor': v = lhs ^ rhs
            elif op == 'shl': v = lhs << (rhs & (bits-1))
            elif op == 'shr': v = lhs >> (rhs & (bits-1))
            else: v = (lhs & ((1 << bits)-1)) >> (rhs & (bits-1))
            put(dst, v, kind)
    else:
        return None
    return pc, writes


NUMERIC = sorted({n for n in NAMES.values() if numeric_effect(n, 0x21, (0x0302, 0, 0, 0), [i*17+5 for i in range(65536)]) is not None})


def structural_name(trace, high):
    jni = [e[1] for e in trace['events'] if e[0] == 'jni']
    resolve = [e for e in trace['events'] if e[0] == 'resolve']
    js = set(jni)
    pc = trace['pc']
    if resolve and resolve[0][1] == 0:
        static = bool(resolve[0][3])
        get = bool(js & set(range(95, 104))) or bool(js & set(range(145, 154)))
        put = bool(js & set(range(104, 113))) or bool(js & set(range(154, 163)))
        # Float put handlers can inline the native call in unsupported trials.
        if not get and not put:
            return ('s' if static else 'i') + 'put-wide'
        return ('s' if static else 'i') + ('get' if get else 'put') + ('-wide' if js & {101, 103, 110, 112, 151, 153, 160, 162} else '')
    if resolve and resolve[0][1] == 1:
        static = bool(resolve[0][3])
        base = 'invoke-static' if static else 'invoke-virtual' if js & set(range(34, 64)) else 'invoke-nonvirtual'
        return base  # range and nonvirtual kind need dedicated trials/corpus
    if resolve and resolve[0][1] == 5:
        return 'const-string/jumbo' if pc == 3 else 'const-string'
    if 15 in js and 17 in js and trace['flags']:
        return 'move-exception'
    if 25 in js:
        if trace['return']:
            return 'return-object'
        return {1: 'move-object', 2: 'move-object/from16', 3: 'move-object/16'}.get(pc)
    if 27 in js:
        return 'new-instance'
    if 32 in js:
        return 'instance-of' if trace['delta'] else 'check-cast'
    if resolve and resolve[0][1] == 3 and trace['flags']:
        return 'const-class'
    if resolve and resolve[0][1] == 2 and 172 in js:
        if pc == 2:
            return 'new-array'
        return 'filled-new-array/range' if jni.count(174) == high else 'filled-new-array'
    for idx, name in {199:'aget-boolean',200:'aget-byte',201:'aget-char',202:'aget-short',173:'aget-object',
                      207:'aput-boolean',208:'aput-byte',209:'aput-char',210:'aput-short',174:'aput-object'}.items():
        if idx in js:
            return name
    if 222 in js:
        reads = [e for e in trace['array'] if e[0] == UC_MEM_READ]
        writes = [e for e in trace['array'] if e[0] == UC_MEM_WRITE]
        accesses = reads or writes
        wide = sum(e[2] for e in accesses) >= 8
        return ('aget' if reads else 'aput') + ('-wide' if wide else '')
    if 217 in js: return 'monitor-enter'
    if 218 in js: return 'monitor-exit'
    if 171 in js and trace['delta']: return 'array-length'
    if 13 in js and 14 not in js and not resolve: return 'throw'
    return None


def effect_matches(name, high, words, values, trace):
    if trace['error'] or trace['events'] or trace['return']:
        return False
    try:
        effect = numeric_effect(name, high, words, values)
    except (ZeroDivisionError, OverflowError, ValueError):
        return False
    if effect is None or effect[0] != trace['pc']:
        return False
    tail = name.split('/')[0]
    float_output = tail.endswith(('-float', '-to-float')) and not name.startswith(('cmpl','cmpg'))
    actual_writes = dict(trace['delta'])
    if float_output:
        for reg,value in list(actual_writes.items()):
            value = (values[reg]&0xffffffff00000000) | (value&0xffffffff)
            if value == values[reg]:
                del actual_writes[reg]
            else:
                actual_writes[reg] = value
    for reg in effect[1].keys() | actual_writes.keys():
        value = effect[1].get(reg, values[reg])
        actual = actual_writes.get(reg, values[reg])
        if value == actual:
            continue
        # NaN payload propagation differs between hardware and Python. Its
        # sign/payload is not used to decide the operation's Dalvik identity.
        tail = name.split('/')[0]
        kind = 'double' if tail.endswith(('-double', '-to-double')) else 'float' if tail.endswith(('-float', '-to-float')) else None
        if kind and math.isnan(float_of(value, kind == 'double')) and math.isnan(float_of(actual, kind == 'double')):
            continue
        return False
    return True


def derive_semantic(probe, log=print):
    """Recover mapping from concrete effects, preserving unresolved failures."""
    from .handlers import find_handler_table
    _, table = find_handler_table(probe.r.images[1][0])
    normal = [i*17+5 for i in range(65536)]
    bank = [0x0123456787654321, 0xfedcba9876543210,
            0x00000000fffffffd, 0x7ffffffeffffffff,
            0x4008000040e00000, 0xc0140000c0300000,
            0x3ff000003f800000, 0x000000003f000000]
    mixed = [bank[i % len(bank)] for i in range(65536)]
    reverse = [bank[(i+3) % len(bank)] for i in range(65536)]
    zeros = [(0, 1, 0xffffffff, 0x7fffffff, 0x80000000, 3, 7, 19)[i % 8] for i in range(65536)]
    trials = [(0x21, (0x0302,0,0,0), normal),
              (0x32, (0x0504,0,0,0), mixed),
              (0x12, (0x0302,0,0,0), reverse),
              (0x21, (0x0302,0,0,0), zeros),
              (0x32, (0x0504,1,0x2345,0x6789), normal)]
    mapping, candidates, traces, cache = {}, {}, {}, {}
    probe.aliases = {}
    for op in range(256):
        key = table[op]
        if key not in cache:
            cache[key] = probe.run(op, values=normal)
        trace = cache[key]
        traces[op] = trace
        name = structural_name(trace, 0x21)
        if trace['return'] and not trace['events']:
            name = 'return-void' if not trace['vreg_reads'] else 'return'
            if name == 'return':
                vals = list(normal)
                vals[33] = 0x1122334455667788
                returned = probe.run(op,values=vals)
                if returned['error'] or not returned['return']:
                    raise EmulationError('return probe unresolved for opcode %#x'%op)
                if returned['result'] == vals[33]:
                    name = 'return-wide'
                elif returned['result'] != (vals[33]&0xffffffff):
                    raise EmulationError('return value unresolved for opcode %#x'%op)
                probe.aliases[op] = [name,'return-object']
        if name:
            mapping[op] = name
        else:
            candidates[op] = [n for n in NUMERIC if effect_matches(n, *trials[0], trace)]
    log('[*] semantic probes: %d initial names, %d numerical/special cases' %
        (len(mapping), len(candidates)))
    for op, names in candidates.items():
        if names:
            for high, words, vals in trials[1:]:
                t = probe.run(op, high=high, words=words, values=vals)
                names = [n for n in names if effect_matches(n, high, words, vals, t)]
                if not names:
                    break
            if len(names) > 1 and all(n.startswith('const') for n in names):
                words = (0xff81, 0xffff, 0, 0)
                t = probe.run(op, words=words, values=normal)
                names = [n for n in names if effect_matches(n, 0x21, words, normal, t)]
            if len(names) > 1 and any(n.startswith(('cmpl-', 'cmpg-')) for n in names):
                vals = list(normal)
                vals[2] = vals[3] = 0x7ff800007fc00000
                t = probe.run(op, values=vals)
                names = [n for n in names if effect_matches(n, 0x21, trials[0][1], vals, t)]
            if len(names) > 1:
                extra = []
                if all(n.startswith(('if-', 'goto')) for n in names):
                    extra = [[v] * 65536 for v in (0, 7)]
                elif any(n.startswith(('cmpl-', 'cmpg-')) for n in names):
                    vals = list(normal)
                    vals[2], vals[3] = 0x402200003f800000, 0x3ff0000041100000
                    extra = [vals]
                else:
                    extra = [[v] * 65536 for v in
                             (0xffffffffffffffff, 0x80001234, 0xc01c0000c0e00000)]
                for vals in extra:
                    t = probe.run(op, values=vals)
                    names = [n for n in names if effect_matches(n, 0x21, trials[0][1], vals, t)]
                    if len(names) <= 1:
                        break
            if set(names) == {'long-to-int', 'move'}:
                # Native optimization erases this distinction. The lifter
                # chooses the legal Dalvik form using the source vreg type.
                mapping[op] = 'move'
                probe.aliases[op] = ['move', 'long-to-int']
                continue
            if len(names) == 1:
                mapping[op] = names[0]
                continue
        candidates[op] = names
    # Payload handlers are identified by executing valid payloads of each kind.
    for op in candidates:
        if op in mapping:
            continue
        t = traces[op]
        if t['pc'] in (3, 770) and not t['delta'] and not any(e[0]=='resolve' for e in t['events']):
            for ident, name in ((0x100,'packed-switch'),(0x200,'sparse-switch'),(0x300,'fill-array-data')):
                vals = list(normal)
                vals[33] = 5
                trial = probe.run(op, values=vals, payload=ident)
                if not trial['error'] and not any(e[0]=='throw' for e in trial['events']) and trial['pc'] == (3 if ident==0x300 else 7):
                    mapping[op] = name
                    break
    # Measure range argument selection; direct and super have identical call
    # effects in some official builds and are resolved from method metadata.
    invokes = [op for op, n in mapping.items() if n.startswith('invoke-')]
    for op in invokes:
        t = probe.run(op, words=(0x0302,0x4321,0,0), values=normal)
        calls = [e for e in t['events'] if e[0]=='call']
        if not calls:
            raise EmulationError('invoke probe did not call JNI for opcode %#x' % op)
        base = mapping[op]
        static = base == 'invoke-static'
        observed = calls[0][3] if static else calls[0][2]
        ranged = observed == normal[0x4321]
        if observed not in (normal[0x4321], normal[1]):
            raise EmulationError('invoke register selection unresolved for opcode %#x' % op)
        if base == 'invoke-nonvirtual':
            base = 'invoke-direct'
        mapping[op] = base + ('/range' if ranged else '')
    # move-result must be probed after an invoke in the same interpreter frame.
    virtual = next((op for op in invokes if mapping[op] == 'invoke-virtual'), None)
    if virtual is not None:
        probe.uc.mem_write(probe.shorty, b'J\0')
        for op in candidates:
            if op in mapping:
                continue
            t = probe.run(op, values=normal, prefix=(virtual,0,0))
            if t['pc'] == 4 and 33 in t['delta']:
                value = t['delta'][33]
                if value in (0x1122334455667788, 0x55667788):
                    mapping[op] = ('move-result-object' if t['flags'] else
                                   'move-result-wide' if value > 0xffffffff else 'move-result')
        probe.uc.mem_write(probe.shorty, b'II\0')
    unknown = {op: {'candidates': candidates.get(op), 'trace': traces[op]}
               for op in range(256) if op not in mapping}
    if unknown:
        exc = EmulationError('semantic opcode ambiguity (%d): %s' %
                             (len(unknown), ', '.join('%#x' % op for op in unknown)))
        exc.diagnostics = unknown
        raise exc
    log('[*] semantic opcode map: 256 values / %d names' % len(set(mapping.values())))
    return mapping
