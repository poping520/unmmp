# -*- coding: utf-8 -*-
"""Minimal ELF32/ELF64 reader: sections, symbols, relocations, vaddr<->offset.

Pointer-sized values in RELA images (arm64, x86_64) live in the relocation
addend, not in the file bytes. pointer() applies R_*_RELATIVE for those slots.
"""
import struct

EM_386 = 3
EM_ARM = 40
EM_X86_64 = 62
EM_AARCH64 = 183

# R_*_RELATIVE
_RELATIVE = {
    EM_386: 8,
    EM_ARM: 23,
    EM_X86_64: 8,
    EM_AARCH64: 1027,
}


class Elf:
    def __init__(self, data: bytes):
        self.data = data
        if data[:4] != b'\x7fELF':
            raise ValueError('not an ELF file')
        self.ei_class = data[4]
        self.ei_data = data[5]
        if self.ei_class not in (1, 2):
            raise ValueError('unknown ELF class %s' % self.ei_class)
        if self.ei_data != 1:
            raise ValueError('big-endian ELF is not supported')
        self.is64 = self.ei_class == 2
        self.ptr = 8 if self.is64 else 4
        self.end = '<'
        e = self.end
        if self.is64:
            (self.e_type, self.machine, _, self.e_entry, self.e_phoff, self.e_shoff,
             _, _, self.e_phentsize, self.e_phnum, self.e_shentsize, self.e_shnum,
             self.e_shstrndx) = struct.unpack_from(e + 'HHIQQQIHHHHHH', data, 0x10)
        else:
            (self.e_type, self.machine, _, self.e_entry, self.e_phoff, self.e_shoff,
             _, _, self.e_phentsize, self.e_phnum, self.e_shentsize, self.e_shnum,
             self.e_shstrndx) = struct.unpack_from(e + 'HHIIIIIHHHHHH', data, 0x10)
        self.sections = self._parse_sections()
        self.relocs = self._parse_relocs()
        self._rel_ptr = {}
        rel_t = _RELATIVE.get(self.machine)
        for off, typ, _sym, addend in self.relocs:
            if rel_t is not None and typ == rel_t and addend is not None:
                self._rel_ptr[off] = addend & ((1 << (self.ptr * 8)) - 1)
        self.dynsyms = self._parse_dynsym()

    def _parse_sections(self):
        e = self.end
        secs = []
        if self.e_shoff == 0 or self.e_shnum == 0:
            return secs
        for i in range(self.e_shnum):
            off = self.e_shoff + i * self.e_shentsize
            if self.is64:
                (name, typ, flags, addr, offset, size, link, info, align,
                 entsize) = struct.unpack_from(e + 'IIQQQQIIQQ', self.data, off)
            else:
                (name, typ, flags, addr, offset, size, link, info, align,
                 entsize) = struct.unpack_from(e + 'IIIIIIIIII', self.data, off)
            secs.append(dict(name_off=name, typ=typ, flags=flags, addr=addr,
                             offset=offset, size=size, link=link, info=info,
                             entsize=entsize))
        shstr = secs[self.e_shstrndx]
        for s in secs:
            e2 = self.data.index(b'\0', shstr['offset'] + s['name_off'])
            s['name'] = self.data[shstr['offset'] + s['name_off']:e2].decode('utf8', 'replace')
        return secs

    def section(self, name):
        for s in self.sections:
            if s['name'] == name:
                return s
        return None

    def vaddr_to_off(self, va):
        for s in self.sections:
            if s['typ'] != 8 and s['size'] and s['addr'] <= va < s['addr'] + s['size']:
                return s['offset'] + (va - s['addr'])
        raise ValueError('va %#x not mapped' % va)

    def _parse_relocs(self):
        """List of (offset, type, sym, addend). addend is None for REL (stored in place)."""
        out = []
        e = self.end
        for s in self.sections:
            # SHT_RELA=4, SHT_REL=9
            if s['typ'] not in (4, 9):
                continue
            rela = s['typ'] == 4
            if self.is64:
                ent = 24 if rela else 16
                n = s['size'] // ent
                for i in range(n):
                    base = s['offset'] + ent * i
                    if rela:
                        off, info, addend = struct.unpack_from(e + 'QQq', self.data, base)
                    else:
                        off, info = struct.unpack_from(e + 'QQ', self.data, base)
                        addend = None
                    out.append((off, info & 0xffffffff, info >> 32, addend))
            else:
                ent = 12 if rela else 8
                n = s['size'] // ent
                for i in range(n):
                    base = s['offset'] + ent * i
                    if rela:
                        off, info, addend = struct.unpack_from(e + 'IIi', self.data, base)
                    else:
                        off, info = struct.unpack_from(e + 'II', self.data, base)
                        addend = None
                    out.append((off, info & 0xff, info >> 8, addend))
        return out

    def _parse_dynsym(self):
        s = self.section('.dynsym')
        d = self.section('.dynstr')
        if not s or not d:
            return []
        syms = []
        if self.is64:
            ent = 24
            n = s['size'] // ent
            for i in range(n):
                nameoff, info, other, shndx, value, size = struct.unpack_from(
                    self.end + 'IBBHQQ', self.data, s['offset'] + ent * i)
                e = self.data.index(b'\0', d['offset'] + nameoff)
                nm = self.data[d['offset'] + nameoff:e].decode('utf8', 'replace')
                syms.append({'name': nm, 'value': value, 'size': size, 'info': info})
        else:
            ent = 16
            n = s['size'] // ent
            for i in range(n):
                nameoff, value, size, info, other, shndx = struct.unpack_from(
                    self.end + 'IIIBBH', self.data, s['offset'] + ent * i)
                e = self.data.index(b'\0', d['offset'] + nameoff)
                nm = self.data[d['offset'] + nameoff:e].decode('utf8', 'replace')
                syms.append({'name': nm, 'value': value, 'size': size, 'info': info})
        return syms

    def exported_symbols(self):
        return [s for s in self.dynsyms if s['name'] and s['value'] and (s['info'] >> 4) == 1]

    def text_range(self):
        s = self.section('.text')
        return s['addr'], s['addr'] + s['size']

    def pointer(self, va):
        """Pointer-sized value at va, with RELA R_*_RELATIVE applied."""
        if va in self._rel_ptr:
            return self._rel_ptr[va]
        off = self.vaddr_to_off(va)
        if self.ptr == 8:
            return struct.unpack_from('<Q', self.data, off)[0]
        return struct.unpack_from('<I', self.data, off)[0]

    def code_addr(self, va):
        """Clear the Thumb bit. Data addresses are never passed here."""
        if self.machine == EM_ARM:
            return va & ~1
        return va

    def in_text(self, va):
        if not va:
            return False
        tlo, thi = self.text_range()
        code = va & ~1 if self.machine == EM_ARM else va
        return tlo <= code < thi

    def relative_reloc_type(self):
        t = _RELATIVE.get(self.machine)
        if t is None:
            raise RuntimeError('no RELATIVE reloc type for machine %s' % self.machine)
        return t
