# -*- coding: utf-8 -*-
"""Small dex reader used to validate native bindings and drive registration."""
import struct


class Dex:
    def __init__(self, data):
        self.data = data
        if data[:4] != b'dex\n':
            raise ValueError('not a dex image')
        self.strings = []
        ns, off = self.u32(56), self.u32(60)
        for i in range(ns):
            p = self.uleb(self.u32(off + 4 * i))[1]
            end = data.index(b'\0', p)
            text = data[p:end].replace(b'\xc0\x80', b'\0').decode('utf-8', 'surrogatepass')
            self.strings.append(text.encode('utf-16', 'surrogatepass').decode('utf-16', 'surrogatepass'))
        self.types = [self.strings[self.u32(self.u32(68) + 4 * i)] for i in range(self.u32(64))]
        self.protos = []
        for i in range(self.u32(72)):
            p = self.u32(76) + 12 * i
            params = self.u32(p + 8)
            args = '' if not params else ''.join(self.types[self.u16(params + 4 + 2 * j)]
                                                 for j in range(self.u32(params)))
            self.protos.append('(' + args + ')' + self.types[self.u32(p + 4)])
        self.methods = []
        for i in range(self.u32(88)):
            cls, proto, name = struct.unpack_from('<HHI', data, self.u32(92) + 8 * i)
            self.methods.append((self.types[cls][1:-1], self.strings[name], self.protos[proto]))
        self.definitions = {}
        self.class_flags = {}
        for i in range(self.u32(96)):
            base = self.u32(100) + 32 * i
            self.class_flags[self.types[self.u32(base)]] = self.u32(base + 4)
            off = self.u32(base + 24)
            if not off:
                continue
            counts = []
            for _ in range(4):
                count, off = self.uleb(off)
                counts.append(count)
            for _ in range(counts[0] + counts[1]):
                _, off = self.uleb(off)
                _, off = self.uleb(off)
            for count in counts[2:]:
                mid = 0
                for _ in range(count):
                    diff, off = self.uleb(off)
                    flags, off = self.uleb(off)
                    code, off = self.uleb(off)
                    mid += diff
                    self.definitions[self.methods[mid]] = (flags, code)

    def u16(self, off):
        return struct.unpack_from('<H', self.data, off)[0]

    def u32(self, off):
        return struct.unpack_from('<I', self.data, off)[0]

    def uleb(self, off):
        value = shift = 0
        while True:
            b = self.data[off]
            off += 1
            value |= (b & 127) << shift
            if b < 128:
                return value, off
            shift += 7
            if shift > 35:
                raise ValueError('invalid dex uleb128')

    def registration_calls(self, target):
        """Constant integer arguments at invoke-static calls to the JNI registrar.

        nmmp injects a const followed by invoke-static at class initialization.
        Decode instruction widths so operand words are never treated as calls.
        """
        from .dalvik import WIDTHS
        target_ids = {i for i, m in enumerate(self.methods) if m == target}
        out = set()
        for flags, off in self.definitions.values():
            if not off:
                continue
            n = self.u32(off + 12)
            ins = struct.unpack_from('<%dH' % n, self.data, off + 16)
            pc, values = 0, {}
            while pc < n:
                word = ins[pc]
                op = word & 255
                if word in (0x100, 0x200, 0x300):
                    from .decoder import payload_units
                    span = payload_units(ins, pc)
                    if span is None:
                        break
                else:
                    span = WIDTHS[op]
                if pc + span > n:
                    break
                if op == 0x12:
                    v = word >> 12
                    values[(word >> 8) & 15] = v - 16 if v & 8 else v
                elif op in (0x13, 0x14, 0x15):
                    v = ins[pc + 1]
                    if op == 0x13:
                        v = v - 65536 if v & 0x8000 else v
                    elif op == 0x14:
                        v |= ins[pc + 2] << 16
                    else:
                        v <<= 16
                    values[word >> 8] = v & 0xffffffff
                elif op in (0x71, 0x77) and ins[pc + 1] in target_ids:
                    reg = (ins[pc + 2] & 15) if op == 0x71 else ins[pc + 2]
                    if reg not in values:
                        raise ValueError('nonconstant nmmp registration argument')
                    out.add(values[reg])
                else:
                    # The injected const/invoke pair is adjacent. Avoid retaining
                    # stale constants through register writes or control flow.
                    values.clear()
                pc += span
        return sorted(out)

    def referenced_interfaces(self):
        """Interface owners identified by surviving original dex invokes."""
        from .dalvik import WIDTHS
        from .decoder import payload_units
        result = {cls:bool(flags&0x200) for cls,flags in self.class_flags.items()}
        for flags,off in self.definitions.values():
            if not off:
                continue
            n = self.u32(off+12)
            ins = struct.unpack_from('<%dH'%n,self.data,off+16)
            pc = 0
            while pc<n:
                word = ins[pc]
                op = word&255
                span = payload_units(ins,pc) if word in (0x100,0x200,0x300) else WIDTHS[op]
                if span is None or pc+span>n:
                    break
                if op in (0x72,0x78):
                    cls = 'L'+self.methods[ins[pc+1]][0]+';'
                    result[cls] = True
                pc+=span
        return result
