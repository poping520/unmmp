# -*- coding: utf-8 -*-
"""Semantic recovery and rebuilding of every protected dex in an APK."""
import json
import os
import re
import shutil
import hashlib
import struct
import zlib
from collections import Counter

from .recover import Recovery
from .probe import InstructionProbe
from .semantic import derive_semantic
from .lifter import Lifter, type_words
from . import build
from .assemble import assemble_tree


def write_json(path, value):
    with open(path, 'w', encoding='utf-8') as handle:
        json.dump(value, handle, ensure_ascii=True, indent=2)


def method_info(definitions, interfaces):
    """Keep the complete descriptor used by resolved method references."""
    return {('L'+cls+';', name, sig):
            (bool(flags & 8), bool(interfaces.get('L'+cls+';', False)), bool(flags & 2))
            for (cls, name, sig), (flags, _) in definitions.items()}


def clear_results(out):
    """Only remove filenames owned by the recovery pipeline."""
    names = {'opcode_mapping.json','opcode_aliases.json','native_methods.json',
             'lifted_bodies.json','recovery_summary.json','semantic_failures.json',
             'decode_failures.json'}
    for name in os.listdir(out):
        if name in names or re.fullmatch(r'classes\d*_restored\.dex',name):
            path = os.path.join(out,name)
            if os.path.isfile(path):
                os.remove(path)
        elif is_output_directory(name):
            path = os.path.join(out, name)
            if os.path.islink(path):
                os.unlink(path)
            elif os.path.isdir(path):
                shutil.rmtree(path)


def is_output_directory(name):
    """Reserved generated directory names."""
    return name == 'work' or bool(
        re.fullmatch(r'(?:smali|patched_smali)(?:_.+)?', name, re.I))


def discard_dex_results(out):
    """A failed restoration must not leave partial dex files or a success summary."""
    for name in os.listdir(out):
        if name == 'recovery_summary.json' or re.fullmatch(r'classes\d*_restored\.dex', name):
            path = os.path.join(out, name)
            if os.path.isfile(path):
                os.remove(path)


def restore(nm, vm, dex_inputs, out, tools, skip_dex=False, log=print):
    os.makedirs(out, exist_ok=True)
    clear_results(out)
    os.makedirs(os.path.join(out, 'work'))
    try:
        return _restore(nm, vm, dex_inputs, out, tools, skip_dex, log)
    except Exception:
        discard_dex_results(out)
        raise


def _restore(nm, vm, dex_inputs, out, tools, skip_dex, log):
    if not dex_inputs:
        raise RuntimeError('no dex inputs')
    if not skip_dex:
        jars = build.require_jars(tools)
        build.find_java()
    recovery = Recovery(nm, vm, [raw for _,raw in dex_inputs], log).extract()
    probe = InstructionProbe(recovery.runtime)
    try:
        mapping = derive_semantic(probe, log)
    except RuntimeError as exc:
        if hasattr(exc, 'diagnostics'):
            write_json(os.path.join(out, 'semantic_failures.json'), exc.diagnostics)
        raise
    write_json(os.path.join(out, 'opcode_mapping.json'), {str(k):v for k,v in sorted(mapping.items())})
    write_json(os.path.join(out, 'opcode_aliases.json'), probe.aliases)
    failures = recovery.resolve_references(mapping)
    if failures:
        write_json(os.path.join(out, 'decode_failures.json'), failures)
        raise RuntimeError('decode failed for %d/%d methods; see decode_failures.json' %
                           (len(failures),len(recovery.methods)))
    kinds = recovery.refine_invokes(mapping)
    recovery.refine_returns(mapping)
    write_json(os.path.join(out, 'opcode_mapping.json'), {str(k):v for k,v in sorted(mapping.items())})
    info = method_info(recovery.definitions, kinds)
    lifted = {}
    for m in recovery.methods:
        m['static'] = bool(recovery.definitions[(m['class'],m['name'],m['sig'])][0]&8)
        pool = recovery.sessions[m['resolver']]
        pool.semantic_aliases = probe.aliases
        th = recovery.blobs[m['thunk']]
        body,maxreg,_ = Lifter(pool,mapping,nm.data,nm.vaddr_to_off,info).lift(m,th)
        if body is None:
            raise RuntimeError('lift failed: %s.%s%s' % (m['class'],m['name'],m['sig']))
        regs = th['nregs']
        if regs is None:
            # No parameters: spare wide halves do not shift incoming registers.
            regs = max(maxreg+2, type_words(m['sig'][1:m['sig'].index(')')]))
        if regs<=maxreg or regs>65535:
            raise RuntimeError('invalid recovered register count for %s.%s' % (m['class'],m['name']))
        lifted.setdefault(m['class'],[]).append({'name':m['name'],'sig':m['sig'],
                                               'static':m['static'],'regs':regs,'body':body})
    write_json(os.path.join(out,'lifted_bodies.json'),lifted)
    write_json(os.path.join(out,'native_methods.json'),recovery.methods)
    log('[*] decoded/lifted: %d/%d' % (len(recovery.methods),len(recovery.methods)))
    summary = {'backend':'emulate','machine':nm.machine,'methods':len(recovery.methods),
               'blobs':len(recovery.blobs),'decoded':len(recovery.methods),
               'resolvers':len(recovery.sessions),'patched':0,'dex_files':[]}
    if skip_dex:
        write_json(os.path.join(out,'recovery_summary.json'),summary)
        return summary
    expected = Counter((m['class'],m['name'],m['sig']) for m in recovery.methods)
    next_dex = 1
    summary['dex_sources'] = {}
    for (dex_name,raw),dex in zip(dex_inputs,recovery.dexes):
        stem = os.path.splitext(os.path.basename(dex_name))[0]
        output = os.path.join(out,('classes' if next_dex==1 else 'classes%d'%next_dex)+'_restored.dex')
        wanted = {key for key in dex.definitions if key in expected}
        if not wanted:
            with open(output,'wb') as handle:
                handle.write(raw)
            summary['dex_files'].append(output)
            summary['dex_sources'][dex_name] = [output]
            next_dex+=1
            continue
        work = os.path.join(out,'work',stem+'.dex')
        with open(work,'wb') as handle:
            handle.write(raw)
        suffix = '' if stem=='classes' else '_'+stem
        bak = os.path.join(out,'smali'+suffix)
        patched = os.path.join(out,'patched_smali'+suffix)
        for directory in (bak,patched):
            if os.path.isdir(directory):
                shutil.rmtree(directory)
        rc,_ = build.baksmali(jars['baksmali'],work,bak,log)
        if rc:
            raise RuntimeError('baksmali failed for %s' % dex_name)
        shutil.copytree(bak,patched)
        count = 0
        for cls,methods in lifted.items():
            selected = [m for m in methods if (cls,m['name'],m['sig']) in wanted]
            if not selected:
                continue
            path = os.path.join(patched,cls.replace('/',os.sep)+'.smali')
            with open(path,encoding='utf-8') as handle:
                text = handle.read()
            for m in selected:
                pattern = re.compile(r'^(\.method[^\n]*?[ \t]'+re.escape(m['name']+m['sig'])+
                                     r'[ \t]*)\r?\n(.*?)^\.end method\b',re.M|re.S)
                matches = list(pattern.finditer(text))
                if len(matches)!=1 or not re.search(r'\bnative\b',matches[0].group(1)):
                    raise RuntimeError('native declaration mismatch: %s.%s%s' % (cls,m['name'],m['sig']))
                match = matches[0]
                head = re.sub(r'\bnative\b[ \t]*','',match.group(1)).rstrip()
                metadata = match.group(2)
                body = head+'\n    .registers %d\n' % m['regs']+metadata+'\n'+m['body']+'\n.end method'
                text = text[:match.start()]+body+text[match.end():]
                count+=1
                expected[(cls,m['name'],m['sig'])]-=1
            with open(path,'w',encoding='utf-8') as handle:
                handle.write(text)
        log('[*] %s patched methods: %d' % (dex_name,count))
        summary['patched']+=count
        api = {'035':15,'037':24,'038':26,'039':28}.get(raw[4:7].decode('ascii'))
        if api is None:
            raise RuntimeError('unsupported original dex version: %r'%raw[4:7])
        outputs = assemble_tree(patched,out,stem,jars['smali'],next_dex,log,api=api)
        next_dex+=len(outputs)
        summary['dex_files'].extend(outputs)
        summary['dex_sources'][dex_name] = outputs
    if any(expected.values()):
        raise RuntimeError('not all captured native methods were patched')
    from .dex import Dex
    restored = {}
    for path in summary['dex_files']:
        with open(path,'rb') as handle:
            data = handle.read()
        if data[12:32]!=hashlib.sha1(data[32:]).digest() or struct.unpack_from('<I',data,8)[0]!=(zlib.adler32(data[12:])&0xffffffff):
            raise RuntimeError('restored dex checksum invalid: %s'%path)
        for key,value in Dex(data).definitions.items():
            if key in restored:
                raise RuntimeError('duplicate restored method: %s'%(key,))
            restored[key] = value
    for m in recovery.methods:
        key = (m['class'],m['name'],m['sig'])
        flags,code = restored.get(key,(0,0))
        if flags&0x100 or not code:
            raise RuntimeError('restored native body missing: %s'%(key,))
    summary['verified_bodies'] = len(recovery.methods)
    write_json(os.path.join(out,'recovery_summary.json'),summary)
    log('[*] restored dex files: %d; patched: %d' % (len(summary['dex_files']),summary['patched']))
    return summary
