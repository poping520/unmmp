# -*- coding: utf-8 -*-
"""Resolve optimized native aliases using Dalvik register widths at each use."""
import collections

from .decoder import FMT


def width_of(desc):
    return 'W' if desc[0] in 'JD' else 'O' if desc[0] in '[L' else 'S'


def aliases_by_type(ins, ops, pools, method, th, aliases, tries):
    if not aliases:
        return {}
    nregs = th.get('nregs')
    if nregs is None:
        return {}
    params = method['sig'][1:method['sig'].index(')')]
    tags = []
    if not method.get('static'):
        tags.append('O')
    i = 0
    while i < len(params):
        first = params[i]
        if first == '[':
            i += 1
            while params[i] == '[':
                i += 1
            if params[i] == 'L':
                i = params.index(';', i)
            tags.append('O')
        elif first == 'L':
            i = params.index(';', i)
            tags.append('O')
        elif first in 'JD':
            tags.extend(('W','H'))
        else:
            tags.append('S')
        i += 1
    initial = {nregs-len(tags)+i: frozenset((tag,)) for i, tag in enumerate(tags)}
    bypc = {pc:(op,name,size) for pc,op,name,size in ops}
    states = {ops[0][0]:initial}
    todo = collections.deque((ops[0][0],))
    overrides = {}

    def add_state(pc, state):
        if pc not in bypc:
            return
        old = states.get(pc)
        if old is None:
            states[pc] = dict(state)
            todo.append(pc)
            return
        merged = {r:old.get(r,frozenset(('?',))) | state.get(r,frozenset(('?',)))
                  for r in old.keys() | state.keys()}
        if merged != old:
            states[pc] = merged
            todo.append(pc)

    def s16(v): return v-65536 if v&0x8000 else v
    def s32(v): return v-(1<<32) if v&(1<<31) else v

    while todo:
        pc = todo.popleft()
        op, name, size = bypc[pc]
        state = states[pc]
        out = dict(state)
        word = ins[pc]
        aa, a, b = word>>8, (word>>8)&15, word>>12
        w1 = ins[pc+1] if pc+1<len(ins) else 0
        w2 = ins[pc+2] if pc+2<len(ins) else 0

        def put(reg, tag):
            out[reg] = frozenset((tag,))
            if tag == 'W':
                out[reg+1] = frozenset(('H',))

        if op in aliases and 'move' in aliases[op]:
            source = state.get(b, frozenset(('?',)))
            if source == frozenset(('W',)):
                overrides[pc] = 'long-to-int'
            elif 'W' not in source:
                overrides[pc] = 'move'
            else:
                raise RuntimeError('ambiguous register width at native alias pc=%d' % pc)
        if name.startswith('move') and not name.startswith(('move-result','move-exception')):
            fmt = FMT[name][1]
            dst, src = (a,b) if fmt=='12x' else (aa,w1) if fmt=='22x' else (w1,w2)
            if overrides.get(pc) == 'long-to-int':
                put(dst,'S')
            elif 'wide' in name:
                put(dst,'W')
            else:
                out[dst] = state.get(src, frozenset(('O' if 'object' in name else 'S',)))
        elif name.startswith('const-wide'):
            put(aa,'W')
        elif name.startswith('const'):
            put(a if name=='const/4' else aa, 'O' if name in ('const-class','const-string','const-string/jumbo') else 'S')
        elif name.startswith(('iget','sget')):
            put(a if name.startswith('iget') else aa, width_of(pools.fields[w1]['type']))
        elif name.startswith('aget'):
            put(aa, 'W' if 'wide' in name else 'O' if 'object' in name else 'S')
        elif name.startswith('invoke-'):
            put(-1,width_of(pools.methods[w1]['proto'].split(')')[1]))
        elif name.startswith('filled-new-array'):
            put(-1,'O')
        elif name.startswith('move-result'):
            kind = state.get(-1, frozenset(('W' if 'wide' in name else 'O' if 'object' in name else 'S',)))
            out[aa] = kind
            if kind == frozenset(('W',)):
                put(aa,'W')
        elif name in ('move-exception','new-instance','new-array'):
            put(a if name=='new-array' else aa,'O')
        elif '-to-' in name:
            put(a, width_of({'long':'J','double':'D','float':'F'}.get(name.split('-to-')[1],'I')))
        elif name.startswith(('neg-','not-')):
            put(a,'W' if name.endswith(('long','double')) else 'S')
        elif name.startswith(('cmp','instance-of','array-length')):
            put(a if name in ('array-length','instance-of') else aa,'S')
        elif name.split('-')[0] in ('add','sub','mul','div','rem','and','or','xor','shl','shr','ushr','rsub'):
            put(a if FMT[name][1] in ('12x','22s') else aa,
                'W' if name.split('/')[0].endswith(('long','double')) else 'S')
        # Catch edges use the state before an instruction that can throw.
        for start,end,handlers in tries:
            if start<=pc<end:
                for _,target in handlers:
                    add_state(target,state)
        if name.startswith('return') or name=='throw':
            continue
        if name.startswith('goto'):
            target = ((aa-256 if aa&128 else aa) if name=='goto' else
                      s16(w1) if name=='goto/16' else s32(w1 | w2<<16))
            add_state(pc+target,out)
            continue
        if name.startswith('if-'):
            add_state(pc+s16(w1),out)
        if name in ('packed-switch','sparse-switch'):
            payload = pc+s32(w1 | w2<<16)
            count = ins[payload+1]
            offset = payload+4 if name=='packed-switch' else payload+2+2*count
            for j in range(count):
                target = s32(ins[offset+2*j] | ins[offset+2*j+1]<<16)
                add_state(pc+target,out)
        add_state(pc+size,out)
    return overrides
