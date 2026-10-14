# -*- coding: utf-8 -*-
"""Bounded native execution for nmmp's JNI and interpreter boundaries.

This is a CPU sandbox, not an Android process. Unimplemented external calls
fail explicitly; the APK's application methods are stopped at the VM entry.
"""
import struct
import math

from unicorn import (Uc, UcError, UC_ARCH_ARM, UC_ARCH_ARM64, UC_ARCH_X86,
                     UC_MODE_ARM, UC_MODE_32, UC_MODE_64, UC_HOOK_CODE)
from unicorn import arm_const as ar, arm64_const as aa, x86_const as xx


class EmulationError(RuntimeError):
    pass


class NativeRuntime:
    STACK = 0x20000000
    STUBS = 0x30000000
    HEAP = 0x10000000
    BASES = (0x01000000, 0x04000000)

    def __init__(self, nm, vm):
        self.machine, self.ptr = nm.machine, nm.ptr
        if vm.machine != self.machine or vm.ptr != self.ptr:
            raise EmulationError('native and VM libraries must use the same ABI')
        if self.machine not in (40, 183, 3, 62):
            raise EmulationError('unsupported ELF machine %d' % self.machine)
        arch, mode = {40: (UC_ARCH_ARM, UC_MODE_ARM),
                      183: (UC_ARCH_ARM64, UC_MODE_ARM),
                      3: (UC_ARCH_X86, UC_MODE_32),
                      62: (UC_ARCH_X86, UC_MODE_64)}[self.machine]
        self.uc = Uc(arch, mode)
        self.uc.mem_map(self.STACK, 0x200000)
        self.uc.mem_map(self.STUBS, 0x100000)
        self.uc.mem_map(self.HEAP, 0x4000000)
        self.uc.mem_map(0, 0x1000)  # compiler TLS stack canary slot
        if self.machine == 40:
            self.uc.reg_write(ar.UC_ARM_REG_C1_C0_2, 0xf << 20)
            self.uc.reg_write(ar.UC_ARM_REG_FPEXC, 1 << 30)
        elif self.machine == 183:
            self.uc.reg_write(aa.UC_ARM64_REG_CPACR_EL1, 3 << 20)
        self.heap_next = self.HEAP
        self.stub_next = self.STUBS + 16
        self.callbacks = {}
        self.symbols = {}
        self.stop_reason = None
        self.callback_error = None
        self.events = []
        self.classes = {}
        self.handles = {}
        self.registrations = []
        self.exception = 0
        self.probing = False
        self.capture_vm = False
        self.vm_call = None
        self.boundary = None
        self.images = [(nm, self.BASES[0]), (vm, self.BASES[1])]
        self.uc.mem_write(self.STUBS, self._ret_code())
        for elf, base in self.images:
            alloc = [s for s in elf.sections if s['flags'] & 2 and s['size']]
            size = max(s['addr'] + s['size'] for s in alloc)
            self.uc.mem_map(base, (size + 4095) & ~4095)
            for s in alloc:
                if s['typ'] != 8:
                    self.uc.mem_write(base + s['addr'],
                                      elf.data[s['offset']:s['offset'] + s['size']])
            for sym in elf.exported_symbols():
                self.symbols[sym['name']] = base + sym['value']
        self.vm_entry = self.symbols.get('vmInterpret')
        if not self.vm_entry:
            raise EmulationError('exported vmInterpret entry not found')
        for elf, base in self.images:
            for off, typ, si, add in elf.relocs:
                if not typ:
                    continue
                slot = base + off
                old = self.read_ptr(slot) if add is None else add
                if typ == elf.relative_reloc_type():
                    self.write_ptr(slot, base + old)
                    continue
                sym = elf.dynsyms[si]
                name = sym['name']
                target = base + sym['value'] if sym['value'] else self.symbols.get(name)
                if target is None:
                    if name in ('__stack_chk_guard', '__sF'):
                        target = self.alloc(256)
                    else:
                        target = self.stub(lambda n=name: self.libc(n))
                    self.symbols[name] = target
                abs_type, slot_types = {40: (2, (21, 22)), 183: (257, (1025, 1026)),
                                        3: (1, (6, 7)), 62: (1, (6, 7))}[self.machine]
                if typ == abs_type:
                    target += old
                elif typ not in slot_types:
                    raise EmulationError('unsupported ELF relocation %d for %s' % (typ, name))
                self.write_ptr(slot, target)
        self.env = self.alloc(self.ptr)
        self.env_table = self.alloc(240 * self.ptr)
        self.write_ptr(self.env, self.env_table)
        for idx in range(240):
            self.write_ptr(self.env_table + idx * self.ptr,
                           self.stub(lambda i=idx: self.jni(i)))
        self.jvm = self.alloc(self.ptr)
        table = self.alloc(8 * self.ptr)
        self.write_ptr(self.jvm, table)
        self.write_ptr(table + 6 * self.ptr, self.stub(self.get_env))
        self.uc.hook_add(UC_HOOK_CODE, self._on_code)

    def _ret_code(self):
        return {40: b'\x1e\xff\x2f\xe1', 183: b'\xc0\x03\x5f\xd6',
                3: b'\xc3', 62: b'\xc3'}[self.machine]

    def alloc(self, size, data=None):
        addr = self.heap_next
        self.heap_next += (max(size, 16) + 15) & ~15
        if self.heap_next > self.HEAP + 0x4000000:
            raise EmulationError('native scratch memory exhausted')
        if data is not None:
            self.uc.mem_write(addr, bytes(data))
        return addr

    def stub(self, fn):
        addr = self.stub_next
        self.stub_next += 16
        self.uc.mem_write(addr, self._ret_code())
        self.callbacks[addr] = fn
        return addr

    def read_ptr(self, addr):
        return int.from_bytes(self.uc.mem_read(addr, self.ptr), 'little')

    def write_ptr(self, addr, value):
        self.uc.mem_write(addr, (value & ((1 << (8 * self.ptr)) - 1)).to_bytes(self.ptr, 'little'))

    def cbytes(self, addr, limit=65536):
        out = bytearray()
        while len(out) < limit:
            block = bytes(self.uc.mem_read(addr + len(out), min(128, limit - len(out))))
            end = block.find(b'\0')
            if end >= 0:
                out.extend(block[:end])
                return bytes(out)
            out.extend(block)
        raise EmulationError('unterminated native string at %#x' % addr)

    def cstring(self, addr, limit=65536):
        # JNI uses modified UTF-8, including encoded NUL and surrogate pairs.
        value = self.cbytes(addr, limit).replace(b'\xc0\x80', b'\0').decode('utf-8', 'surrogatepass')
        return value.encode('utf-16', 'surrogatepass').decode('utf-16', 'surrogatepass')

    def args(self, count):
        if self.machine == 40:
            regs = [ar.UC_ARM_REG_R0, ar.UC_ARM_REG_R1, ar.UC_ARM_REG_R2, ar.UC_ARM_REG_R3]
            sp = self.uc.reg_read(ar.UC_ARM_REG_SP)
        elif self.machine == 183:
            regs = [getattr(aa, 'UC_ARM64_REG_X%d' % i) for i in range(8)]
            sp = self.uc.reg_read(aa.UC_ARM64_REG_SP)
        elif self.machine == 62:
            regs = [xx.UC_X86_REG_RDI, xx.UC_X86_REG_RSI, xx.UC_X86_REG_RDX,
                    xx.UC_X86_REG_RCX, xx.UC_X86_REG_R8, xx.UC_X86_REG_R9]
            sp = self.uc.reg_read(xx.UC_X86_REG_RSP) + 8
        else:
            regs = []
            sp = self.uc.reg_read(xx.UC_X86_REG_ESP) + 4
        return [self.uc.reg_read(regs[i]) if i < len(regs)
                else self.read_ptr(sp + (i - len(regs)) * self.ptr) for i in range(count)]

    def _return(self, value=0):
        if self.machine == 40:
            self.uc.reg_write(ar.UC_ARM_REG_R0, value & 0xffffffff)
            self.uc.reg_write(ar.UC_ARM_REG_R1, (value >> 32) & 0xffffffff)
            self.uc.reg_write(ar.UC_ARM_REG_PC, self.uc.reg_read(ar.UC_ARM_REG_LR))
        elif self.machine == 183:
            self.uc.reg_write(aa.UC_ARM64_REG_X0, value & 0xffffffffffffffff)
            self.uc.reg_write(aa.UC_ARM64_REG_PC, self.uc.reg_read(aa.UC_ARM64_REG_LR))
        else:
            wide = self.machine == 62
            spreg = xx.UC_X86_REG_RSP if wide else xx.UC_X86_REG_ESP
            pcreg = xx.UC_X86_REG_RIP if wide else xx.UC_X86_REG_EIP
            sp = self.uc.reg_read(spreg)
            self.uc.reg_write(xx.UC_X86_REG_RAX if wide else xx.UC_X86_REG_EAX, value)
            if not wide:
                self.uc.reg_write(xx.UC_X86_REG_EDX, value >> 32)
            self.uc.reg_write(pcreg, self.read_ptr(sp))
            self.uc.reg_write(spreg, sp + self.ptr)

    def _on_code(self, uc, addr, size, _):
        try:
            if addr == self.STUBS:
                self.stop_reason = 'return'
                uc.emu_stop()
            elif self.capture_vm and addr == (self.vm_entry & ~1 if self.machine == 40 else self.vm_entry):
                self.vm_call = self.args(4 if self.ptr == 4 else 3)
                self.stop_reason = 'vm-entry'
                uc.emu_stop()
            elif self.boundary is not None and self.boundary(addr):
                self.stop_reason = 'instruction'
                uc.emu_stop()
            elif addr in self.callbacks:
                result = self.callbacks[addr]()
                if self.stop_reason is None:
                    self._return(result or 0)
        except Exception as exc:
            self.callback_error = exc
            uc.emu_stop()

    def call(self, addr, args, count=200000):
        self.stop_reason = self.callback_error = None
        self.events = []
        top = self.STACK + 0x1f0000
        if self.machine == 40:
            self.uc.reg_write(ar.UC_ARM_REG_SP, top)
            self.uc.reg_write(ar.UC_ARM_REG_LR, self.STUBS)
            for i, arg in enumerate(args):
                if i < 4:
                    self.uc.reg_write(getattr(ar, 'UC_ARM_REG_R%d' % i), arg)
                else:
                    self.write_ptr(top + (i - 4) * 4, arg)
        elif self.machine == 183:
            self.uc.reg_write(aa.UC_ARM64_REG_SP, top)
            self.uc.reg_write(aa.UC_ARM64_REG_LR, self.STUBS)
            for i, arg in enumerate(args):
                if i < 8:
                    self.uc.reg_write(getattr(aa, 'UC_ARM64_REG_X%d' % i), arg)
                else:
                    self.write_ptr(top + (i - 8) * 8, arg)
        else:
            wide = self.machine == 62
            regs = [xx.UC_X86_REG_RDI, xx.UC_X86_REG_RSI, xx.UC_X86_REG_RDX,
                    xx.UC_X86_REG_RCX, xx.UC_X86_REG_R8, xx.UC_X86_REG_R9] if wide else []
            top -= self.ptr
            self.uc.reg_write(xx.UC_X86_REG_RSP if wide else xx.UC_X86_REG_ESP, top)
            self.write_ptr(top, self.STUBS)
            for i, arg in enumerate(args):
                if i < len(regs):
                    self.uc.reg_write(regs[i], arg)
                else:
                    self.write_ptr(top + self.ptr * (1 + i - len(regs)), arg)
        try:
            self.uc.emu_start(addr, 0xffffffffffffffff if self.ptr == 8 else 0xffffffff, count=count)
        except UcError as exc:
            pc = self.uc.reg_read({40: ar.UC_ARM_REG_PC, 183: aa.UC_ARM64_REG_PC,
                                   3: xx.UC_X86_REG_EIP, 62: xx.UC_X86_REG_RIP}[self.machine])
            raise EmulationError('native execution at %#x: %s' % (pc, exc)) from exc
        if self.callback_error:
            raise EmulationError(str(self.callback_error)) from self.callback_error
        if self.stop_reason is None:
            raise EmulationError('native instruction budget exhausted at %#x' % addr)
        return self.uc.reg_read({40: ar.UC_ARM_REG_R0, 183: aa.UC_ARM64_REG_X0,
                                 3: xx.UC_X86_REG_EAX, 62: xx.UC_X86_REG_RAX}[self.machine])

    def handle(self, kind, value):
        key = (kind, value)
        if key not in self.handles:
            addr = self.alloc(16)
            self.handles[key] = addr
            self.classes[addr] = value
        return self.handles[key]

    def get_env(self):
        _, dst, _ = self.args(3)
        self.write_ptr(dst, self.env)
        return 0

    def jni(self, idx):
        a = self.args(5)
        if self.probing:
            self.events.append(('jni', idx))
        if idx == 6:  # FindClass
            name = self.cstring(a[1])
            self.events.append(('class', name))
            return self.handle('class', name)
        if idx == 215:  # RegisterNatives
            cls = self.classes[a[1]]
            if a[3] > 100000:
                raise EmulationError('invalid RegisterNatives count')
            for i in range(a[3]):
                p = a[2] + i * self.ptr * 3
                self.registrations.append({'class': cls, 'name': self.cstring(self.read_ptr(p)),
                                           'sig': self.cstring(self.read_ptr(p + self.ptr)),
                                           'entry': self.read_ptr(p + 2 * self.ptr)})
            return 0
        if idx in (33, 113, 94, 144):
            cls, name, sig = self.classes[a[1]], self.cstring(a[2]), self.cstring(a[3])
            kind = 'method' if idx in (33, 113) else 'field'
            self.events.append((kind, cls, name, sig, idx in (113, 144)))
            return self.handle(kind, (cls, name, sig))
        if idx in (21, 22, 25):
            return a[1]
        if idx in (23, 17):
            if idx == 17:
                self.exception = 0
            return 0
        if idx in (15, 228):
            return self.exception
        if idx in (13, 14):
            self.exception = self.handle('exception', 'probe')
            self.events.append(('throw', idx))
            return 0
        if idx == 167:
            value = self.cstring(a[1])
            self.events.append(('string', value))
            return self.handle('string', value)
        if idx == 31:
            return self.handle('class', 'java/lang/Object')
        if idx == 145:
            if self.probing:
                return 0x13579
            cls, name, sig = self.classes[a[2]]
            if name == 'TYPE':
                return self.handle('class', cls)
            raise EmulationError('unsupported initialization field %s.%s' % (cls, name))
        if self.probing:
            if idx == 24:
                return int(a[1] == a[2])
            if idx == 32:
                return 1
            if idx in (217, 218):
                return 0
            if idx == 27:
                return self.handle('object', 'new')
            if idx == 171:
                return 65536
            if idx == 172 or idx in range(175, 183):
                return self.handle('array', idx)
            if idx == 173:
                return 0x123456
            if idx == 174 or idx in range(207, 215):
                return 0
            if idx in range(199, 207):
                self.uc.mem_write(a[4], bytes.fromhex('81ff341278563412'))
                return 0
            if idx == 222:
                return self.array_data
            if idx == 223:
                return 0
            if idx in range(95, 104) or idx in range(146, 154):
                return 0x13579
            if idx in range(104, 113) or idx in range(154, 163):
                return 0
            if idx in range(34, 94) or idx in range(114, 144):
                vp = a[4] if idx in range(64, 94) else a[3]
                self.events.append(('call', idx, a[1], (self.read_ptr(vp) & 0xffffffff) if vp else 0))
                return 0x1122334455667788
        raise EmulationError('unsupported JNI call %d' % idx)

    def libc(self, name):
        a = self.args(4)
        if name in ('fmod', 'fmodf'):
            fmt = '<d' if name == 'fmod' else '<f'
            width = 8 if name == 'fmod' else 4
            if self.machine == 62:
                raw = [self.uc.reg_read(getattr(xx, 'UC_X86_REG_XMM%d' % i)) for i in range(2)]
            elif self.machine == 183:
                raw = [self.uc.reg_read(getattr(aa, 'UC_ARM64_REG_D%d' % i)) for i in range(2)]
            else:
                raw = [a[0] | (a[1] << 32), a[2] | (a[3] << 32)] if width == 8 else a[:2]
            vals = [struct.unpack(fmt, int(v & ((1 << (8*width))-1)).to_bytes(width, 'little'))[0] for v in raw]
            try:
                value = math.fmod(*vals)
            except ValueError:
                value = float('nan')
            packed = struct.pack(fmt, value)
            bits = int.from_bytes(packed, 'little')
            if self.machine == 62:
                self.uc.reg_write(xx.UC_X86_REG_XMM0, bits)
            elif self.machine == 3:
                # x86 cdecl floating results live on the x87 stack.
                ext_sign = 0x8000 if math.copysign(1, value) < 0 else 0
                if math.isnan(value):
                    ext_man,ext_exp,tag = 0xc000000000000000,0x7fff,2
                elif math.isinf(value):
                    ext_man,ext_exp,tag = 0x8000000000000000,0x7fff,2
                elif not value:
                    ext_man,ext_exp,tag = 0,0,1
                else:
                    mantissa,exponent = math.frexp(value)
                    ext_man,ext_exp,tag = int(abs(mantissa)*(1<<64)),exponent-1+16383,0
                status = self.uc.reg_read(xx.UC_X86_REG_FPSW)
                top = (((status>>11)&7)-1)&7
                tags = self.uc.reg_read(xx.UC_X86_REG_FPTAG)
                self.uc.reg_write(xx.UC_X86_REG_FPSW,(status&~(7<<11)) | top<<11)
                self.uc.reg_write(xx.UC_X86_REG_FPTAG,(tags&~(3<<(top*2))) | tag<<(top*2))
                self.uc.reg_write(getattr(xx,'UC_X86_REG_FP%d'%top),(ext_man,ext_exp|ext_sign))
            elif self.machine == 183:
                self.uc.reg_write(aa.UC_ARM64_REG_D0, bits)
            return bits
        if name in ('vsnprintf', '__vsnprintf_chk'):
            if a[0] and a[1]:
                self.uc.mem_write(a[0], b'\0')
            return 0
        if name.startswith('__aeabi_memclr'):
            self.uc.mem_write(a[0], bytes(a[1]))
            return a[0]
        if name.startswith('__aeabi_memset'):
            self.uc.mem_write(a[0], bytes([a[2] & 255]) * a[1])
            return a[0]
        if name.startswith('__aeabi_memcpy') or name.startswith('__aeabi_memmove'):
            self.uc.mem_write(a[0], bytes(self.uc.mem_read(a[1], a[2])))
            return a[0]
        if name in ('malloc', 'calloc'):
            return self.alloc(a[0] if name == 'malloc' else a[0] * a[1])
        if name == 'free':
            return 0
        if name in ('memset', '__memset_chk'):
            self.uc.mem_write(a[0], bytes([a[1] & 255]) * a[2])
            return a[0]
        if name in ('memcpy', 'memmove', '__memcpy_chk', '__memmove_chk'):
            self.uc.mem_write(a[0], bytes(self.uc.mem_read(a[1], a[2])))
            return a[0]
        if name in ('strlen', '__strlen_chk'):
            return len(self.cbytes(a[0]))
        if name in ('strncpy', '__strncpy_chk'):
            value = self.cbytes(a[1])[:a[2]]
            self.uc.mem_write(a[0], value.ljust(a[2], b'\0'))
            return a[0]
        if name in ('pthread_mutex_lock', 'pthread_mutex_unlock', '__cxa_atexit', '__cxa_finalize'):
            return 0
        raise EmulationError('unsupported external call %s' % name)
