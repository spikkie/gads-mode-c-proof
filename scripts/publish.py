#!/usr/bin/env python3
"""Publish only a SHA-bound synthetic draft PR from a protected public main.

Only the publisher GitHub Actions job should invoke this with an ephemeral token.
"""
import argparse
import base64
import hashlib
import json
import os
import sys
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path

try:
    from scripts.qualify import PROOF, Rejected, preflight
except ModuleNotFoundError:
    from qualify import PROOF, Rejected, preflight


class API:
    def __init__(self, repo, token):
        if not token:
            raise Rejected('NO_TOKEN')
        self.url = 'https://api.github.com/repos/' + repo
        self.token = token

    def call(self, method, path, body=None):
        request = urllib.request.Request(
            self.url + path, method=method,
            headers={'Authorization': 'Bearer ' + self.token,
                     'Accept': 'application/vnd.github+json',
                     'X-GitHub-Api-Version': '2022-11-28',
                     'User-Agent': 'gads-public-c05-proof',
                     'Content-Type': 'application/json'},
            data=json.dumps(body).encode('utf-8') if body is not None else None)
        try:
            with urllib.request.urlopen(request, timeout=30) as response:
                b = response.read()
                return json.loads(b) if b else {}
        except urllib.error.HTTPError as exc:
            # Never expose auth headers, token, request body, or opaque GitHub payloads.
            raise Rejected(f'GITHUB_HTTP_{exc.code}:{method}:{path.split("?")[0]}') from exc


def blob_sha(data):
    return hashlib.sha1(b'blob ' + str(len(data)).encode() + b'\0' + data).hexdigest()


def verify_diff(diff, expected):
    files = diff.get('files') or []
    if diff.get('total_commits') != 1 or len(files) != 2:
        raise Rejected('DIFF_SIZE_OR_COMMITS')
    for file in files:
        if file.get('filename') not in expected or file.get('sha') != expected[file['filename']]:
            raise Rejected('DIFF_PATH_OR_BLOB')
        if file.get('status') not in ('added', 'modified'):
            raise Rejected('DIFF_STATUS')


def run(api, checkout, staged, source_sha, github_ref, repo):
    if not repo.endswith('/gads-mode-c-proof') or repo.count('/') != 1:
        raise Rejected('WRONG_SYNTHETIC_REPOSITORY')
    if github_ref != 'refs/heads/main':
        raise Rejected('UNTRUSTED_BASE_REF')
    result = preflight(checkout, staged, source_sha)
    metadata = api.call('GET', '')
    if metadata.get('private') is not False:
        raise Rejected('PUBLIC_SYNTHETIC_ONLY')
    protected = api.call('GET', '/branches/main')
    if protected.get('protected') is not True:
        raise Rejected('MAIN_NOT_PROTECTED')
    latest = api.call('GET', '/git/ref/heads/main')
    if latest.get('object', {}).get('sha') != source_sha:
        raise Rejected('BASE_MOVED')

    head_branch = 'autonomy/c05-proof-' + source_sha[:20]
    proof = (staged / PROOF).read_bytes()
    manifest = (staged / 'SHA256SUMS').read_bytes()
    expected = {PROOF: blob_sha(proof), 'SHA256SUMS': blob_sha(manifest)}
    owner = repo.split('/')[0]
    query = urllib.parse.urlencode({'state': 'all', 'head': owner + ':' + head_branch, 'per_page': 100})
    prs = api.call('GET', '/pulls?' + query)
    if len(prs) > 1:
        raise Rejected('DUPLICATE_PRS')
    if prs:
        pr = prs[0]
    else:
        ref_path = '/git/ref/heads/' + head_branch
        try:
            head = api.call('GET', ref_path).get('object', {}).get('sha')
        except Rejected as exc:
            if 'GITHUB_HTTP_404' not in str(exc):
                raise
            head = None
        if head is None:
            base_commit = api.call('GET', '/git/commits/' + source_sha)
            blobs = {}
            for filename, data in ((PROOF, proof), ('SHA256SUMS', manifest)):
                info = api.call('POST', '/git/blobs', {
                    'content': base64.b64encode(data).decode('ascii'), 'encoding': 'base64'})
                if info.get('sha') != expected[filename]:
                    raise Rejected('GIT_BLOB_HASH')
                blobs[filename] = info['sha']
            tree = api.call('POST', '/git/trees', {
                'base_tree': base_commit['tree']['sha'],
                'tree': [{'path': p, 'mode': '100644', 'type': 'blob', 'sha': v}
                         for p, v in blobs.items()]})
            commit = api.call('POST', '/git/commits', {
                'message': 'test: bounded synthetic C-05 candidate',
                'tree': tree['sha'], 'parents': [source_sha]})
            if api.call('GET', '/git/ref/heads/main')['object']['sha'] != source_sha:
                raise Rejected('BASE_MOVED_BEFORE_REF')
            api.call('POST', '/git/refs', {'ref': 'refs/heads/' + head_branch,
                                           'sha': commit['sha']})
            head = commit['sha']
        compare = api.call('GET', '/compare/' + source_sha + '...' + head)
        verify_diff(compare, expected)
        try:
            pr = api.call('POST', '/pulls', {
                'title': 'Synthetic C-05 bounded autonomous publisher',
                'body': ('Public synthetic proof on exact protected-main SHA ' + source_sha +
                         '. Two files only. Draft; no merge or approval.'),
                'head': head_branch, 'base': 'main', 'draft': True,
                'maintainer_can_modify': False})
        except Rejected:
            # Reconcile write uncertainty instead of blindly reissuing the mutation.
            matches = api.call('GET', '/pulls?' + query)
            if len(matches) != 1:
                raise Rejected('PR_CREATE_UNCONFIRMED')
            pr = matches[0]

    detail = api.call('GET', '/pulls/' + str(pr['number']))
    if detail.get('draft') is not True or detail.get('merged') is True:
        raise Rejected('PR_NOT_DRAFT')
    if detail.get('base', {}).get('ref') != 'main' or detail.get('head', {}).get('ref') != head_branch:
        raise Rejected('PR_WRONG_REFS')
    if detail.get('head', {}).get('repo', {}).get('full_name') != repo:
        raise Rejected('PR_WRONG_REPOSITORY')
    compare = api.call('GET', '/compare/' + source_sha + '...' + detail['head']['sha'])
    verify_diff(compare, expected)
    files = api.call('GET', '/pulls/' + str(pr['number']) + '/files?per_page=100')
    if len(files) != 2 or any(f.get('filename') not in expected or
                              f.get('sha') != expected[f['filename']] for f in files):
        raise Rejected('PR_FILES_NOT_VERIFIED')
    return {'status': 'C05_DRAFT_PR_VERIFIED_NOT_MERGED',
            'number': pr['number'], 'base_sha': source_sha,
            'head_sha': detail['head']['sha'], 'proof_sha256': result['proof_sha256']}


def main():
    p = argparse.ArgumentParser()
    p.add_argument('--checkout', required=True, type=Path)
    p.add_argument('--staged', required=True, type=Path)
    a = p.parse_args()
    try:
        result = run(API(os.environ.get('GITHUB_REPOSITORY', ''), os.environ.get('GITHUB_TOKEN')),
                     a.checkout, a.staged, os.environ.get('GITHUB_SHA', ''),
                     os.environ.get('GITHUB_REF', ''), os.environ.get('GITHUB_REPOSITORY', ''))
        print(json.dumps(result, sort_keys=True))
    except (Rejected, OSError, KeyError) as exc:
        raise SystemExit(f'BLOCKED: {exc}') from exc


if __name__ == '__main__':
    main()
