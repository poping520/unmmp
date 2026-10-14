# -*- coding: utf-8 -*-
"""Invoke the baksmali/smali jars shipped in the project tools directory."""
import glob
import hashlib
import os
import shutil
import subprocess

# Release v2.5.2, https://github.com/baksmali/smali/releases?page=2#release-v2.5.2
# These are the standalone jars (dependencies are inside the jar).
JARS = {
    'baksmali': (
        'baksmali-2.5.2.jar',
        'd3116248cce4f82ec5a31eb7f95ee75daff42ddf6eed0ab573973dc53fbad2e5',
    ),
    'smali': (
        'smali-2.5.2.jar',
        '9544299578b16f771d8aa8eaefe0d3718ca03478c16f3c356f2fcf1366bfb116',
    ),
}


def _sha256(path):
    digest = hashlib.sha256()
    with open(path, 'rb') as handle:
        for chunk in iter(lambda: handle.read(1 << 20), b''):
            digest.update(chunk)
    return digest.hexdigest()


def require_jars(tools_dir):
    """Return {'baksmali': path, 'smali': path} after checking the pinned hashes."""
    found = {}
    for key, (name, expect) in JARS.items():
        path = os.path.join(tools_dir, name)
        if not os.path.isfile(path):
            raise RuntimeError('missing %s (expected in %s)' % (name, tools_dir))
        got = _sha256(path)
        if got != expect:
            raise RuntimeError('%s sha256 %s != %s' % (name, got, expect))
        found[key] = path
    return found


def _java_filename():
    return 'java.exe' if os.name == 'nt' else 'java'


def _java_candidates():
    """Ordered places a java launcher may live. First hit that exists is used."""
    name = _java_filename()
    home = os.environ.get('JAVA_HOME')
    if home:
        yield os.path.join(home, 'bin', name)
        yield os.path.join(home, name)
    found = shutil.which('java')
    if found:
        yield found
    if os.name != 'nt':
        return
    bases = [os.environ.get(key) for key in ('ProgramFiles', 'ProgramFiles(x86)', 'LocalAppData')]
    patterns = (
        os.path.join('Java', '*', 'bin', name),
        os.path.join('Eclipse Adoptium', '*', 'bin', name),
        os.path.join('Microsoft', 'jdk*', 'bin', name),
        os.path.join('Android', 'Android Studio', 'jbr', 'bin', name),
    )
    hits = []
    for base in bases:
        if not base:
            continue
        for pattern in patterns:
            hits.extend(glob.glob(os.path.join(base, pattern)))
    for path in sorted(hits, reverse=True):
        yield path


def find_java():
    """Return a java launcher, or raise RuntimeError listing where we looked."""
    tried = []
    for path in _java_candidates():
        if path and os.path.isfile(path):
            return path
        if path:
            tried.append(path)
    lines = 'java not found. Set JAVA_HOME, or put java on PATH.'
    if tried:
        lines += ' Looked for: ' + '; '.join(tried)
    raise RuntimeError(lines)


def run_jar(jar, args, log=print):
    cmd = [find_java(), '-jar', jar] + args
    result = subprocess.run(cmd, capture_output=True)
    out = ((result.stdout or b'') + (result.stderr or b'')).decode('utf-8', 'replace')
    if result.returncode != 0:
        log(out[-4000:])
    return result.returncode, out


def baksmali(jar, dex_path, outdir, log=print):
    return run_jar(jar, ['disassemble', '-o', outdir, dex_path], log)


def smali(jar, smali_dir, out_dex, log=print, api=None):
    args = ['assemble', '-o', out_dex]
    if api is not None:
        args += ['--api', str(api)]
    return run_jar(jar, args + [smali_dir], log)
