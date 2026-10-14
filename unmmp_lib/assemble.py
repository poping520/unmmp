# -*- coding: utf-8 -*-
"""Promote string instructions and partition restored classes for dex limits."""
import os
import re
import shutil

from . import build


METHOD_REF = re.compile(r'(L[^\s;]+;|\[[^\s,]+)->([^\s(]+\([^)]*\)[^\s,}]+)')
FIELD_REF = re.compile(r'(L[^\s;]+;)->([^\s:]+:[^\s,}]+)')
TYPE_REF = re.compile(r'\[*L[\w/$\-]+;|\[+[ZBCSIJFD]')


def references(text):
    match = re.search(r'^\.class[^\n]*\s(L[^\s;]+;)\s*$',text,re.M)
    if not match:
        raise RuntimeError('smali class declaration missing')
    cls = match.group(1)
    methods = {owner+'->'+sig for owner,sig in METHOD_REF.findall(text)}
    fields = {owner+'->'+sig for owner,sig in FIELD_REF.findall(text)}
    for line in re.findall(r'^\.method\s+([^\n]+)',text,re.M):
        methods.add(cls+'->'+line.split()[-1])
    for line in re.findall(r'^\.field\s+([^\n]+)',text,re.M):
        fields.add(cls+'->'+line.split(' = ',1)[0].split()[-1])
    types = set(TYPE_REF.findall(text))
    return methods,fields,types


def promote_strings(text):
    text = re.sub(r'^(\s*)const-string(\s+v\d+,)',r'\1const-string/jumbo\2',text,flags=re.M)
    # Wider strings can push previously short gotos beyond their encoding.
    return re.sub(r'^(\s*)goto(?:/16|/32)?(\s+:)',r'\1goto/32\2',text,flags=re.M)


def assemble_tree(smali_dir, out, stem, jar, start_index, log=print, limit=65000, api=None):
    files = sorted(os.path.join(root,name) for root,dirs,names in os.walk(smali_dir)
                   for name in names if name.endswith('.smali'))
    groups,group = [],[]
    totals = [set(),set(),set()]
    for path in files:
        with open(path,encoding='utf-8') as handle:
            text = promote_strings(handle.read())
        with open(path,'w',encoding='utf-8') as handle:
            handle.write(text)
        refs = references(text)
        if any(len(s)>limit for s in refs):
            raise RuntimeError('one class exceeds dex index capacity: %s' % path)
        merged = [a|b for a,b in zip(totals,refs)]
        if group and any(len(s)>limit for s in merged):
            groups.append(group)
            group,totals = [],[set(),set(),set()]
            merged = [a|b for a,b in zip(totals,refs)]
        group.append(path)
        totals = merged
    if group:
        groups.append(group)
    outputs = []
    for index,group in enumerate(groups):
        number = start_index+index
        output = os.path.join(out,('classes' if number==1 else 'classes%d'%number)+'_restored.dex')
        directory = smali_dir
        if len(groups)>1:
            directory = os.path.join(out,'work',stem+'_part%d'%(index+1))
            if os.path.isdir(directory):
                if os.path.commonpath((os.path.abspath(directory),os.path.abspath(out)))!=os.path.abspath(out):
                    raise RuntimeError('assembly directory outside output')
                shutil.rmtree(directory)
            os.makedirs(directory)
            for path in group:
                target = os.path.join(directory,os.path.relpath(path,smali_dir))
                os.makedirs(os.path.dirname(target),exist_ok=True)
                shutil.copyfile(path,target)
        if os.path.isfile(output):
            os.remove(output)
        rc,details = build.smali(jar,directory,output,log,api=api)
        if rc or not os.path.isfile(output) or 'Exception in thread' in details or re.search(r'\.smali\[\d+',details):
            if os.path.isfile(output):
                os.remove(output)
            raise RuntimeError('smali failed for %s part %d:\n%s'%(stem,index+1,details[-4000:]))
        outputs.append(output)
    log('[*] %s assembled into %d dex file(s)'%(stem,len(outputs)))
    return outputs
