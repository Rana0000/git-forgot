#!/usr/bin/env python3
# git_forgot.py - find secrets that are still recoverable in a git repo
#
# Idea: git almost never deletes objects. amend / rebase / branch -D / stash drop
# only move refs, the old commits and blobs stay in .git/objects (or in a pack).
# So I read ALL objects, scan the blobs, and then figure out where each blob
# came from (which commit, file, author, date) and how "hidden" it is.
#
# Output is JSON lines on stdout (one finding per line), summary on stderr.
# Only stdlib + the git command.
#
# usage: python git_forgot.py <repo> [--show-secrets]

import argparse
import hashlib
import json
import re
import subprocess
import sys
from datetime import datetime, timedelta, timezone

# regexes run on bytes because blobs can be anything (binary, utf-16...)
# if a regex has a group, the group is the secret
DETECTORS = {
    # AKIA = normal IAM key, ASIA = temporary (STS) key, always 20 chars
    "aws_access_key_id": re.compile(rb"\b(?:AKIA|ASIA)[A-Z0-9]{16}\b"),
    # the secret key has no prefix so I only match it next to its variable name
    "aws_secret_access_key": re.compile(
        rb"(?i)aws_?secret(?:_access)?(?:_key)?[\"']?\s*[=:]\s*[\"']?([A-Za-z0-9/+=]{40})(?![A-Za-z0-9/+=])"),
    # ghp_ / gho_ / ghu_ / ghs_ / ghr_ + exactly 36 chars
    "github_token": re.compile(rb"\bgh[pousr]_[A-Za-z0-9]{36}\b"),
    "github_fine_grained_pat": re.compile(rb"\bgithub_pat_[A-Za-z0-9_]{82}\b"),
    # hf_ + 34 letters (see TOKEN_ANALYSIS.md)
    "huggingface_token": re.compile(rb"\bhf_[A-Za-z]{34}\b"),
    # matches RSA, EC, OPENSSH, ENCRYPTED, plain PKCS8...
    "private_key": re.compile(rb"-----BEGIN (?:[A-Z0-9]+ )*PRIVATE KEY-----"),
}

# refs that rebase/merge/fetch leave behind, they also keep old commits alive
PSEUDO_REFS = ["ORIG_HEAD", "FETCH_HEAD", "MERGE_HEAD", "CHERRY_PICK_HEAD", "REVERT_HEAD"]


def git(repo, *args, check=True):
    # list of args, no shell=True -> file names can't inject commands
    res = subprocess.run(["git", "-C", repo, *args], capture_output=True, check=check)
    return res.stdout


def list_objects(repo):
    # --batch-all-objects sees loose objects AND packs (also cruft packs after gc),
    # reachable or not. "find .git/objects" would miss everything after a gc.
    out = git(repo, "cat-file", "--batch-all-objects", "--batch-check", "--unordered")
    objects = {}
    for line in out.decode().splitlines():
        oid, obj_type, size = line.split()
        objects[oid] = (obj_type, int(size))
    return objects


def read_objects(repo, oids):
    # one "cat-file --batch" process for everything instead of one process per object
    # for each oid git prints: "<oid> <type> <size>\n" + content + "\n"
    request = "".join(oid + "\n" for oid in oids).encode()
    out = subprocess.run(["git", "-C", repo, "cat-file", "--batch"],
                         input=request, capture_output=True, check=True).stdout

    result = {}
    pos = 0
    while pos < len(out):
        nl = out.index(b"\n", pos)
        oid, _, size = out[pos:nl].decode().split()
        size = int(size)
        # cut by size, not by "\n", because the content itself has newlines
        result[oid] = out[nl + 1:nl + 1 + size]
        pos = nl + 1 + size + 1
    return result


def rev_list(repo, *args):
    return set(git(repo, "rev-list", *args, check=False).decode().split())


def mask(secret):
    # don't leak the secret again in the report
    if secret.startswith("-----BEGIN"):
        return secret  # the pem header is not secret
    if len(secret) <= 12:
        return secret[:4] + "..."
    return secret[:8] + "..." + secret[-4:]


def fingerprint(secret):
    # same secret -> same id, so you can tell masked secrets apart
    return hashlib.sha256(secret.encode()).hexdigest()[:12]


def scan_blob(content):
    found = []
    for name, regex in DETECTORS.items():
        for m in regex.finditer(content):
            g = 1 if regex.groups else 0
            line = content.count(b"\n", 0, m.start(g)) + 1
            found.append((name, m.group(g).decode(), line))
    return found


def parse_commit(raw):
    # a commit object looks like:
    #   tree <oid>
    #   parent <oid>        (0, 1 or more, stash commits have 2)
    #   author Name <mail> 1767600000 +0100
    #   committer ...
    #
    #   message
    header, _, message = raw.decode(errors="replace").partition("\n\n")
    msg_lines = message.strip().splitlines()
    commit = {"parents": [], "message": msg_lines[0] if msg_lines else ""}

    for line in header.splitlines():
        key, _, value = line.partition(" ")
        if key == "parent":
            commit["parents"].append(value)
        elif key == "author":
            who, ts, tz = value.rsplit(" ", 2)
            name, _, email = who.partition(" <")
            # tz is like +0100
            offset = timedelta(hours=int(tz[1:3]), minutes=int(tz[3:5]))
            if tz[0] == "-":
                offset = -offset
            commit["author"] = name
            commit["email"] = email.rstrip(">")
            commit["date"] = datetime.fromtimestamp(int(ts), timezone(offset)).isoformat()
    return commit


def files_in_commit(repo, oid):
    # every (path, blob) in the commit snapshot
    # -r = go into sub folders, -z = NUL separated so weird file names are ok
    files = set()
    for entry in git(repo, "ls-tree", "-r", "-z", oid).split(b"\0"):
        if not entry:
            continue
        meta, path = entry.split(b"\t", 1)      # "<mode> <type> <oid>\t<path>"
        _, obj_type, blob = meta.decode().split()
        if obj_type == "blob":                  # skip submodules
            files.add((path.decode(errors="replace"), blob))
    return files


def staged_files(repo):
    # files in the index right now (git add but not committed yet)
    files = set()
    for entry in git(repo, "ls-files", "--stage", "-z").split(b"\0"):
        if entry:
            meta, path = entry.split(b"\t", 1)  # "<mode> <oid> <stage>\t<path>"
            files.add((path.decode(errors="replace"), meta.decode().split()[1]))
    return files


def classify_commits(repo, commit_oids):
    # reachable       -> from a branch / tag / stash, gets cloned and pushed
    # reflog_only     -> only the reflog (or ORIG_HEAD etc.) still points to it,
    #                    local only, expires after 90 days (30 if unreachable)
    # dangling_commit -> nothing points to it, next gc --prune can delete it
    reachable = rev_list(repo, "--all")

    pseudo = []
    for ref in PSEUDO_REFS:
        if git(repo, "rev-parse", "-q", "--verify", ref + "^{commit}", check=False):
            pseudo.append(ref)
    in_reflog = rev_list(repo, "--reflog", *pseudo) - reachable

    status = {}
    for oid in commit_oids:
        if oid in reachable:
            status[oid] = "reachable"
        elif oid in in_reflog:
            status[oid] = "reflog_only"
        else:
            status[oid] = "dangling_commit"
    return status


def locate_blobs(repo, objects):
    # blob -> list of places where it was INTRODUCED.
    # "introduced" = (path, blob) is in this commit but in none of its parents.
    # so if a key stays in 50 commits I only report the one that added it.
    commit_oids = [oid for oid, (t, _) in objects.items() if t == "commit"]
    raw_commits = read_objects(repo, commit_oids)
    commits = {oid: parse_commit(raw) for oid, raw in raw_commits.items()}
    snapshot = {oid: files_in_commit(repo, oid) for oid in commits}
    status = classify_commits(repo, commits)

    locations = {}
    for oid, c in commits.items():
        in_parents = set()
        for p in c["parents"]:
            in_parents |= snapshot.get(p, set())   # parent can be missing (shallow clone)

        for path, blob in snapshot[oid] - in_parents:
            locations.setdefault(blob, []).append({
                "status": status[oid],
                "commit": oid,
                "path": path,
                "author": c["author"],
                "author_email": c["email"],
                "date": c["date"],
                "commit_message": c["message"],
                "recover": f"git show {oid}:{path}",
            })

    for path, blob in staged_files(repo):
        locations.setdefault(blob, []).append({
            "status": "staged",
            "path": path,
            "recover": f"git show :{path}",
        })
    return locations


def scan(repo, show_secrets=False, max_size=10 * 1024 * 1024):
    objects = list_objects(repo)
    locations = locate_blobs(repo, objects)

    # skip huge blobs (videos, datasets...)
    blobs = [oid for oid, (t, size) in objects.items() if t == "blob" and size <= max_size]
    contents = read_objects(repo, blobs)

    findings = []
    for blob, content in contents.items():
        for secret_type, secret, line in scan_blob(content):
            # not in any commit and not staged -> only a loose/packed blob is left
            places = locations.get(blob) or [{
                "status": "dangling_blob",
                "recover": f"git cat-file -p {blob}",
            }]
            for loc in places:
                findings.append({
                    "type": secret_type,
                    "secret": secret if show_secrets else mask(secret),
                    "fingerprint": fingerprint(secret),
                    "status": loc["status"],
                    "path": loc.get("path"),
                    "line": line,
                    "blob": blob,
                    "commit": loc.get("commit"),
                    "author": loc.get("author"),
                    "author_email": loc.get("author_email"),
                    "date": loc.get("date"),
                    "commit_message": loc.get("commit_message"),
                    "recover": loc["recover"],
                })
    return findings


def main():
    parser = argparse.ArgumentParser(description="find recoverable secrets in a git repo")
    parser.add_argument("repo", help="path to a local git repo")
    parser.add_argument("--show-secrets", action="store_true", help="don't mask secrets")
    args = parser.parse_args()

    try:
        git(args.repo, "rev-parse", "--git-dir")
    except subprocess.CalledProcessError:
        sys.exit(f"error: {args.repo} is not a git repo")

    findings = scan(args.repo, args.show_secrets)
    for f in findings:
        print(json.dumps(f))

    counts = {}
    for f in findings:
        counts[f["status"]] = counts.get(f["status"], 0) + 1
    print(f"{len(findings)} findings: {counts}", file=sys.stderr)


if __name__ == "__main__":
    main()
