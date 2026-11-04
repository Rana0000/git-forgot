# git-forgot

Find what Git forgot to forget.

Deleting a secret from a repository rarely removes it. `git rm`, `commit --amend`,
`rebase`, `branch -D` and `stash drop` only move references. The old commits and
blobs stay in `.git/objects` (or in a pack) until the reflog expires and `git gc`
prunes them, and once something has been pushed it may never really go away.

`git_forgot.py` reads **every** object in a local repository, searches the blobs for
secrets, and reports for each one where it is, who introduced it, when, and how
hidden it is.

## Files

| File | What it is |
|---|---|
| `setup_test_repo.sh` | builds a test repo with fake secrets hidden in 6 different ways |
| `git_forgot.py` | the scanner (Python 3, stdlib only + `git`) |
| `test_git_forgot.py` | end-to-end tests |
| `TOKEN_ANALYSIS.md` | part 3: Hugging Face tokens |

## Usage

```bash
./setup_test_repo.sh test-repo            # or: ./setup_test_repo.sh test-repo --gc
python git_forgot.py test-repo            # JSON lines on stdout, summary on stderr
python git_forgot.py test-repo --show-secrets
python -m unittest test_git_forgot -v
```

Example finding (one line per finding, formatted here for reading):

```json
{"type": "github_token", "secret": "ghp_FAKE...0000", "fingerprint": "af15298ae4d0",
 "status": "reflog_only", "path": ".env", "line": 1,
 "blob": "4c7451c5...", "commit": "92d1b872...",
 "author": "Bob Builder", "author_email": "bob@example.com",
 "date": "2026-01-15T11:00:00+01:00", "commit_message": "Read token from env",
 "recover": "git show 92d1b872...:.env"}
```

It works well with `jq`, for example to list only secrets that were pushed:

```bash
python git_forgot.py repo | jq 'select(.status == "reachable")'
```

## The test repository

| # | How the secret was hidden | Secret | Status found |
|---|---|---|---|
| 1 | file deleted in a later commit | AWS key + secret | `reachable` |
| 2 | `commit --amend` | GitHub token | `reflog_only` |
| 3 | `rebase` dropping the commit | RSA private key | `reflog_only` |
| 4 | `branch -D` | GitHub token | `reflog_only` |
| 5 | `stash drop` | AWS key + secret | `dangling_commit` |
| 6 | `git add` then unstaged, never committed | GitHub token | `dangling_blob` |

All secrets are fake, and each value contains the name of the technique so results are
easy to check. Commits use fixed authors and dates, so hashes are the same on every
machine (except the private key, which is generated each time).

## How it works

1. **List all objects** with `git cat-file --batch-all-objects --batch-check`.
   This includes loose objects, packs and cruft packs, reachable or not. Just
   listing `.git/objects/??/*` would find nothing after a `git gc`.
2. **Read objects** with a single `git cat-file --batch` process, not one process per object.
3. **Scan blobs** with regexes on raw bytes (AWS access key ID and secret key,
   GitHub classic and fine-grained tokens, Hugging Face tokens, PEM private keys).
   A blob is identified by its content hash, so a file that stays the same in
   50 commits is scanned once.
4. **Find where each blob came from.** For each commit, `git ls-tree -r` gives the
   set of `(path, blob)` pairs. A blob was *introduced* by a commit if the pair is
   there and in none of its parents. That commit gives the author, date and path.
   Files in the index come from `git ls-files --stage`.
5. **Classify** each commit:

| Status | Meaning | Risk |
|---|---|---|
| `reachable` | ancestor of a branch, tag or stash (`git rev-list --all`) | cloned and pushed with the repo |
| `reflog_only` | only the reflog or `ORIG_HEAD`-like refs point to it | local, kept 90 days (30 if unreachable) |
| `dangling_commit` | nothing points to it | deleted by the next `gc --prune` (default 2 weeks) |
| `staged` | blob in the index, not committed | goes into the next commit |
| `dangling_blob` | blob in no commit and not in the index | no author or date available |

## Choices

- **Masking + fingerprint.** The report shouldn't become a new leak, so secrets are
  masked by default. A short SHA-256 fingerprint shows whether two masked secrets are
  the same or different.
- **Report the origin, not every copy.** One finding per place a secret was added,
  instead of one per commit that contains it.
- **Strict regexes.** For example a GitHub token is exactly 36 characters after the
  prefix. Being looser finds more junk (false positives) and nothing useful, because
  a token with the wrong length isn't a valid token.
- **No shell.** git is called with an argument list, so file names can't inject commands.

## Something I learned while testing

After `git gc`, the amend and rebase secrets moved from `reflog_only` to
`dangling_commit`. `gc` first runs `git reflog expire`, which drops entries
older than 30 days that point to unreachable commits, and the test commits are
dated January 2026. The objects were still there, in a cruft pack. The deleted
branch stayed `reflog_only` because it is the *old* value of a recent
`checkout: moving from feature/ci to main` entry.

## Limitations / ideas

- No validation of the tokens (no network calls). See `TOKEN_ANALYSIS.md` for how
  to validate one type safely.
- GitHub tokens have a CRC32 checksum in the last 6 characters, which could be
  checked offline to drop fake ones.
- Commit messages, tag messages, notes and compressed files are not scanned.
- Everything is loaded in memory and `ls-tree` runs once per commit. That's fine for
  normal repos but would be slow on huge ones (could stream, or cache trees).
- Only the local repo is scanned. Pushed secrets can also live on in forks,
  `refs/pull/*` on GitHub, CI logs and other people's clones.

## Removing a secret for real

1. **Revoke / rotate the secret.** This is the only real fix once it was pushed.
2. Rewrite history: `git filter-repo --path <file> --invert-paths` (or `--replace-text`).
3. Drop local leftovers: `git reflog expire --expire=now --all && git gc --prune=now`.
4. Force-push, and ask the host to purge cached views and PR refs.
