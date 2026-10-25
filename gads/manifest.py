"""Strict complete SHA256 git-tracked tree check; standard library only."""
import argparse
import hashlib
from pathlib import Path
import re
import subprocess

LINE=re.compile(r"^([0-9a-f]{64})  ([A-Za-z0-9_./-]+)$")
class InvalidManifest(ValueError): pass

def parse(body):
    if not isinstance(body,str) or not body.endswith("\n") or "\r" in body:
        raise InvalidManifest("LINE_ENDINGS")
    result={}
    for text in body.splitlines():
        match=LINE.fullmatch(text)
        if not match: raise InvalidManifest("BAD_LINE")
        digest,path=match.groups()
        if (path.startswith("/") or any(p in ("","..",".") for p in path.split("/"))
                or path in result): raise InvalidManifest("INVALID_PATH")
        result[path]=digest
    if list(result)!=sorted(result): raise InvalidManifest("NOT_SORTED")
    return result

def verify(directory):
    root=Path(directory).resolve()
    hashes=parse((root/"SHA256SUMS").read_text("ascii"))
    git=subprocess.run(["git","-C",str(root),"ls-files","-z"],
                       capture_output=True,check=True)
    tracked={x.decode("utf-8") for x in git.stdout.split(b"\x00") if x}
    tracked.discard("SHA256SUMS")
    if tracked!=set(hashes): raise InvalidManifest("FILESET")
    for path,wanted in hashes.items():
        p=root/path
        if p.is_symlink() or not p.is_file(): raise InvalidManifest("NONREGULAR:"+path)
        if hashlib.sha256(p.read_bytes()).hexdigest()!=wanted:
            raise InvalidManifest("DIGEST:"+path)
    return len(hashes)

def main():
    cli=argparse.ArgumentParser()
    cli.add_argument("command",choices=("verify",))
    cli.add_argument("--root",default=".")
    args=cli.parse_args()
    print("MANIFEST_PASS files="+str(verify(args.root)))

if __name__=="__main__":main()
