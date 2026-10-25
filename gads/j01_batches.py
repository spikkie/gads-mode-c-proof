"""Deterministic complete-file J-01 review batches; bounded no silent truncation."""
import hashlib
from gads import j01_runtime as r

MAX_TOTAL_BYTES = 65536
MAX_BATCH_BYTES = 16000
MAX_BATCHES = 8


def partition(full, max_batch_bytes=MAX_BATCH_BYTES):
    if not isinstance(full, dict) or full.get("schema") != "gads.j01-diff.v1":
        raise r.ReviewBlocked("INVALID_REVIEW_SNAPSHOT")
    if type(max_batch_bytes) is not int or not 1024 <= max_batch_bytes <= MAX_BATCH_BYTES:
        raise r.ReviewBlocked("INVALID_BATCH_BUDGET")
    files = full.get("files")
    if not isinstance(files, list) or not files or len(r.canonical(full)) > MAX_TOTAL_BYTES:
        raise r.ReviewBlocked("UNREVIEWABLE_TOTAL_INPUT")
    metadata = {key: value for key, value in full.items() if key != "files"}

    def candidate(group, index, count):
        return {**metadata, "batch_index": index, "batch_count": count,
                "files": group}

    groups = []
    current = []
    # Use the largest possible batch index/count digit lengths during sizing.
    for file in files:
        if not isinstance(file, dict):
            raise r.ReviewBlocked("INVALID_BATCH_FILE")
        proposal = current + [file]
        if len(r.canonical(candidate(proposal, MAX_BATCHES, MAX_BATCHES))) > max_batch_bytes:
            if not current:
                raise r.ReviewBlocked("SINGLE_FILE_EXCEEDS_BATCH_BUDGET")
            groups.append(current)
            current = [file]
            if len(r.canonical(candidate(current, MAX_BATCHES, MAX_BATCHES))) > max_batch_bytes:
                raise r.ReviewBlocked("SINGLE_FILE_EXCEEDS_BATCH_BUDGET")
        else:
            current = proposal
    if current:
        groups.append(current)
    if len(groups) > MAX_BATCHES:
        raise r.ReviewBlocked("TOO_MANY_REVIEW_BATCHES")
    result = [candidate(group, i + 1, len(groups)) for i, group in enumerate(groups)]
    if any(len(r.canonical(batch)) > max_batch_bytes for batch in result):
        raise r.ReviewBlocked("BATCH_SIZE_MISMATCH")
    if [file for batch in result for file in batch["files"]] != files:
        raise r.ReviewBlocked("BATCH_COVERAGE_MISMATCH")
    return result


def batch_digest(batch):
    return hashlib.sha256(r.canonical(batch)).hexdigest()
