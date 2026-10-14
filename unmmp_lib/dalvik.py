# -*- coding: utf-8 -*-
"""Standard Dalvik opcode names (not an APK-specific shuffled mapping)."""
from .decoder import FMT

NAMES = {
    0x00: 'nop', 0x01: 'move', 0x02: 'move/from16', 0x03: 'move/16',
    0x04: 'move-wide', 0x05: 'move-wide/from16', 0x06: 'move-wide/16',
    0x07: 'move-object', 0x08: 'move-object/from16', 0x09: 'move-object/16',
    0x0a: 'move-result', 0x0b: 'move-result-wide', 0x0c: 'move-result-object',
    0x0d: 'move-exception', 0x0e: 'return-void', 0x0f: 'return',
    0x10: 'return-wide', 0x11: 'return-object', 0x12: 'const/4',
    0x13: 'const/16', 0x14: 'const', 0x15: 'const/high16',
    0x16: 'const-wide/16', 0x17: 'const-wide/32', 0x18: 'const-wide',
    0x19: 'const-wide/high16', 0x1a: 'const-string', 0x1b: 'const-string/jumbo',
    0x1c: 'const-class', 0x1d: 'monitor-enter', 0x1e: 'monitor-exit',
    0x1f: 'check-cast', 0x20: 'instance-of', 0x21: 'array-length',
    0x22: 'new-instance', 0x23: 'new-array', 0x24: 'filled-new-array',
    0x25: 'filled-new-array/range', 0x26: 'fill-array-data', 0x27: 'throw',
    0x28: 'goto', 0x29: 'goto/16', 0x2a: 'goto/32', 0x2b: 'packed-switch',
    0x2c: 'sparse-switch', 0x2d: 'cmpl-float', 0x2e: 'cmpg-float',
    0x2f: 'cmpl-double', 0x30: 'cmpg-double', 0x31: 'cmp-long',
}
for start, names in [
    (0x32, ['if-eq', 'if-ne', 'if-lt', 'if-ge', 'if-gt', 'if-le']),
    (0x38, ['if-eqz', 'if-nez', 'if-ltz', 'if-gez', 'if-gtz', 'if-lez']),
    (0x44, ['aget', 'aget-wide', 'aget-object', 'aget-boolean', 'aget-byte', 'aget-char', 'aget-short']),
    (0x4b, ['aput', 'aput-wide', 'aput-object', 'aput-boolean', 'aput-byte', 'aput-char', 'aput-short']),
    (0x52, ['iget', 'iget-wide', 'iget-object', 'iget-boolean', 'iget-byte', 'iget-char', 'iget-short']),
    (0x59, ['iput', 'iput-wide', 'iput-object', 'iput-boolean', 'iput-byte', 'iput-char', 'iput-short']),
    (0x60, ['sget', 'sget-wide', 'sget-object', 'sget-boolean', 'sget-byte', 'sget-char', 'sget-short']),
    (0x67, ['sput', 'sput-wide', 'sput-object', 'sput-boolean', 'sput-byte', 'sput-char', 'sput-short']),
    (0x6e, ['invoke-virtual', 'invoke-super', 'invoke-direct', 'invoke-static', 'invoke-interface']),
    (0x74, ['invoke-virtual/range', 'invoke-super/range', 'invoke-direct/range', 'invoke-static/range', 'invoke-interface/range']),
    (0x7b, ['neg-int', 'not-int', 'neg-long', 'not-long', 'neg-float', 'neg-double',
            'int-to-long', 'int-to-float', 'int-to-double', 'long-to-int', 'long-to-float',
            'long-to-double', 'float-to-int', 'float-to-long', 'float-to-double',
            'double-to-int', 'double-to-long', 'double-to-float', 'int-to-byte', 'int-to-char', 'int-to-short']),
    (0xd0, ['add-int/lit16', 'rsub-int', 'mul-int/lit16', 'div-int/lit16', 'rem-int/lit16',
            'and-int/lit16', 'or-int/lit16', 'xor-int/lit16']),
    (0xd8, ['add-int/lit8', 'rsub-int/lit8', 'mul-int/lit8', 'div-int/lit8', 'rem-int/lit8',
            'and-int/lit8', 'or-int/lit8', 'xor-int/lit8', 'shl-int/lit8', 'shr-int/lit8', 'ushr-int/lit8']),
    (0xfa, ['invoke-polymorphic', 'invoke-polymorphic/range', 'invoke-custom',
            'invoke-custom/range', 'const-method-handle', 'const-method-type']),
]:
    NAMES.update({start + i: name for i, name in enumerate(names)})
binary = []
for kind in ('int', 'long', 'float', 'double'):
    for op in ('add', 'sub', 'mul', 'div', 'rem', 'and', 'or', 'xor', 'shl', 'shr', 'ushr'):
        if kind in ('float', 'double') and op in ('and', 'or', 'xor', 'shl', 'shr', 'ushr'):
            continue
        binary.append(op + '-' + kind)
NAMES.update({0x90 + i: name for i, name in enumerate(binary)})
NAMES.update({0xb0 + i: name + '/2addr' for i, name in enumerate(binary)})
WIDTHS = [FMT.get(NAMES.get(i), (1,))[0] for i in range(256)]
