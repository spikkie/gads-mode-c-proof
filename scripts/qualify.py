#!/usr/bin/env python3
"""Synthetic evidence validation; stdlib only; never accesses GitHub or secrets."""
import argparse
import hashlib
import json
import re
import subprocess
from pathlib import Path

PROOF = 'docs/c05-proof.txt'
STAGED = frozenset((PROOF, 'SHA256SUMS', 'evidence.json'))
SOURCE = b'def is_even(n):\n    return n % 2 == 0\n'
LINE = re.compile(r'^([0-9a-f]{64})  ([A-Za-z0-9_./-]+)$')
SHA = re.compile(r'^[0-9a-f]{40}$')


class Rejected(ValueError):
    pass


def digest(data):
    return hashlib.sha256(data).hexdigest()


def tracked(checkout):
    # The git index, not untracked job artifacts, defines the trusted source file set.
    if (checkout / '.git').exists():
        p = subprocess.run(['git', '-C', str(checkout), 'ls-files', '-z'],
                           capture_output=True, check=True)
        result = {x.decode('utf-8') for x in p.stdout.split(b'\0') if x}
    else:
        result = {p.relative_to(checkout).as_posix() for p in checkout.rglob('*')
                  if p.is_file() and '.git' not in p.parts and not any(
                      x in p.relative_to(checkout).parts for x in
                      ('__pycache__', '.venv', '.ci-venv', 'staged', 'evidence', '.pytest_cache'))}
        result = {x for x in result if not x.endswith('.pyc')}
    result.discard('SHA256SUMS')
    return result


def valid_path(name):
    return not (name.startswith('/') or '\\' in name or
                any(part in ('', '.', '..') for part in name.split('/')))


def parse_manifest(data):
    try:
        s = data.decode('ascii')
    except UnicodeError as exc:
        raise Rejected('MANIFEST_ENCODING') from exc
    if not s.endswith('\n') or '\r' in s:
        raise Rejected('MANIFEST_LINE_ENDING')
    result = {}
    for line in s.splitlines():
        m = LINE.fullmatch(line)
        if not m or not valid_path(m[2]) or m[2] in result:
            raise Rejected('MANIFEST_FORMAT_OR_DUPLICATE')
        result[m[2]] = m[1]
    if list(result) != sorted(result):
        raise Rejected('MANIFEST_ORDER')
    return result


def verify_manifest(checkout):
    manifest = parse_manifest((checkout / 'SHA256SUMS').read_bytes())
    if set(manifest) != tracked(checkout):
        raise Rejected('MANIFEST_FILESET')
    for rel, value in manifest.items():
        path = checkout / rel
        if path.is_symlink() or not path.is_file() or digest(path.read_bytes()) != value:
            raise Rejected('MANIFEST_DIGEST:' + rel)
    return manifest


def stage(checkout, worker, e1, reviewer, base_sha, out):
    if not SHA.fullmatch(base_sha):
        raise Rejected('BASE_SHA')
    source = worker.read_bytes()
    if source != SOURCE:
        raise Rejected('WORKER_OUTPUT_NOT_QUALIFIED')
    worker_sha = digest(source)
    if e1.read_text('ascii') != f'{worker_sha}  worker.py\n':
        raise Rejected('E1_NOT_BOUND')
    if reviewer.read_text('ascii').strip() != f'GADS_J01_APPROVE_{worker_sha}':
        raise Rejected('J01_REJECT_OR_UNBOUND')
    baseline = verify_manifest(checkout)
    if PROOF in baseline:
        raise Rejected('PROOF_ALREADY_ON_BASE')
    if out.exists() or out.is_symlink():
        raise Rejected('STAGE_EXISTS')
    proof = (f'GADS_SYNTHETIC_C05_PROOF\nbase_sha={base_sha}\n'
             f'worker_sha256={worker_sha}\ne1_sha256={worker_sha}\n'
             f'j01=GADS_J01_APPROVE_{worker_sha}\n').encode('ascii')
    entries = {**baseline, PROOF: digest(proof)}
    output_manifest = ''.join(f'{entries[k]}  {k}\n' for k in sorted(entries)).encode('ascii')
    out.mkdir(mode=0o700)
    (out / 'docs').mkdir()
    (out / PROOF).write_bytes(proof)
    (out / 'SHA256SUMS').write_bytes(output_manifest)
    report = dict(schema='gads.c05.synthetic.v1', status='STAGED_ONLY',
                  base_sha=base_sha, worker_sha256=worker_sha,
                  proof_sha256=digest(proof), manifest_sha256=digest(output_manifest),
                  allowed_files=['SHA256SUMS', PROOF])
    (out / 'evidence.json').write_text(json.dumps(report, sort_keys=True) + '\n')
    return preflight(checkout, out, base_sha)


def preflight(checkout, out, base_sha):
    baseline = verify_manifest(checkout)
    if not SHA.fullmatch(base_sha):
        raise Rejected('BASE_SHA')
    files = set()
    for path in out.rglob('*'):
        if path.is_symlink():
            raise Rejected('STAGE_SYMLINK')
        if path.is_file():
            files.add(path.relative_to(out).as_posix())
    if files != STAGED:
        raise Rejected('STAGE_FILESET')
    proof = (out / PROOF).read_bytes()
    new_manifest = (out / 'SHA256SUMS').read_bytes()
    if len(proof) > 4096:
        raise Rejected('PROOF_SIZE')
    manifest = parse_manifest(new_manifest)
    if set(manifest) != set(baseline) | {PROOF}:
        raise Rejected('NEW_MANIFEST_FILESET')
    if any(manifest[k] != v for k, v in baseline.items()):
        raise Rejected('CHANGED_BASE_MANIFEST')
    if manifest[PROOF] != digest(proof):
        raise Rejected('PROOF_HASH')
    try:
        report = json.loads((out / 'evidence.json').read_text('utf-8'))
    except (ValueError, UnicodeError) as exc:
        raise Rejected('BAD_EVIDENCE_JSON') from exc
    wh = report.get('worker_sha256')
    if not isinstance(wh, str) or not re.fullmatch('[0-9a-f]{64}', wh):
        raise Rejected('BAD_WORKER_SHA')
    exact = (f'GADS_SYNTHETIC_C05_PROOF\nbase_sha={base_sha}\n'
             f'worker_sha256={wh}\ne1_sha256={wh}\n'
             f'j01=GADS_J01_APPROVE_{wh}\n').encode('ascii')
    if proof != exact:
        raise Rejected('PROOF_UNBOUND')
    if report != dict(schema='gads.c05.synthetic.v1', status='STAGED_ONLY',
                      base_sha=base_sha, worker_sha256=wh,
                      proof_sha256=digest(proof), manifest_sha256=digest(new_manifest),
                      allowed_files=['SHA256SUMS', PROOF]):
        raise Rejected('EVIDENCE_REPORT')
    return {'status': 'PREFLIGHT_PASS_NOT_PUBLISHED',
            'base_sha': base_sha, 'worker_sha256': wh,
            'proof_sha256': digest(proof), 'manifest_sha256': digest(new_manifest)}


def main():
    a = argparse.ArgumentParser()
    s = a.add_subparsers(dest='command', required=True)
    p = s.add_parser('manifest'); p.add_argument('--checkout', type=Path, required=True)
    p = s.add_parser('stage')
    for key in ('checkout', 'worker', 'e1', 'reviewer', 'out'):
        p.add_argument('--' + key, required=True, type=Path)
    p.add_argument('--base-sha', required=True)
    p = s.add_parser('preflight')
    p.add_argument('--checkout', required=True, type=Path)
    p.add_argument('--out', required=True, type=Path)
    p.add_argument('--base-sha', required=True)
    args = a.parse_args()
    try:
        if args.command == 'manifest':
            verify_manifest(args.checkout); print('MANIFEST_PASS')
        elif args.command == 'stage':
            print(json.dumps(stage(args.checkout, args.worker, args.e1,
                                   args.reviewer, args.base_sha, args.out), sort_keys=True))
        else:
            print(json.dumps(preflight(args.checkout, args.out, args.base_sha), sort_keys=True))
    except (Rejected, OSError, subprocess.CalledProcessError) as exc:
        raise SystemExit(f'BLOCKED: {exc}') from exc


if __name__ == '__main__':
    main()
