#!/usr/bin/env bash
# Build a Git repository where fake secrets were committed and then "hidden".
# Every secret is FAKE and self-labelled with the technique used to hide it,
# so the scanner's output can be checked against this list:
#
#   #  technique          secret type     value contains          how it survives
#   1  deleted file       AWS key pair    AKIAFAKEDELETEDFILE1    still in history (reachable)
#   2  amended commit     GitHub token    FAKEamendedCommit       old commit only in reflog
#   3  rebase (drop)      private key     (generated RSA key)     old commit only in reflog
#   4  deleted branch     GitHub token    FAKEdeletedBranch       commit only in HEAD reflog
#   5  dropped stash      AWS key pair    AKIAFAKEDROPPEDSTASH    dangling commit, no ref, no reflog
#   6  staged, unstaged   GitHub token    FAKEstagedNotCommitted  dangling blob, never committed
#
# Usage: ./setup_test_repo.sh [target_dir] [--gc]
#   --gc  also run `git gc`: objects move into packfiles and unreachable ones
#         into a cruft pack, so the scanner can't rely on loose objects only.

set -euo pipefail

REPO="${1:-test-repo}"
DO_GC="${2:-}"

rm -rf "$REPO"
git init -q -b main "$REPO"
cd "$REPO"

# Isolate from the user's global config (no signing, no hooks, fixed identity).
git config user.name  "Alice Admin"
git config user.email "alice@example.com"
git config commit.gpgsign false
git config core.autocrlf false   # store files byte-for-byte, also on Windows

# pad PREFIX LENGTH: PREFIX followed by '0's up to LENGTH characters.
# Lets us build tokens with exactly the right length but a readable label.
pad() { local s="$1"; while [ "${#s}" -lt "$2" ]; do s="${s}0"; done; printf '%s' "$s"; }

# commit_as NAME EMAIL DATE MESSAGE: commit with a chosen author AND committer
# identity and date, so the scanner has distinct, known metadata to report.
commit_as() {
  GIT_AUTHOR_NAME="$1" GIT_AUTHOR_EMAIL="$2" GIT_AUTHOR_DATE="$3" \
  GIT_COMMITTER_NAME="$1" GIT_COMMITTER_EMAIL="$2" GIT_COMMITTER_DATE="$3" \
    git commit -q -m "$4"
}

# --- Base commit -------------------------------------------------------------
printf '# Demo app\n' > README.md
printf 'print("hello")\n' > app.py
git add README.md app.py
commit_as "Alice Admin" alice@example.com "2026-01-05T10:00:00+01:00" "Initial commit"

# --- 1. Deleted file ---------------------------------------------------------
# The file is removed in a later commit, but the commit that added it is still
# part of main's history: the blob is reachable from a branch.
mkdir -p config
cat > config/aws_credentials <<EOF
[default]
aws_access_key_id = AKIAFAKEDELETEDFILE1
aws_secret_access_key = $(pad "fakeSecretDeletedFile" 40)
EOF
git add config/aws_credentials
commit_as "Alice Admin" alice@example.com "2026-01-10T09:30:00+01:00" "Add AWS config"
git rm -q config/aws_credentials
commit_as "Alice Admin" alice@example.com "2026-01-11T14:00:00+01:00" "Remove credentials"

# --- 2. Amended commit -------------------------------------------------------
# --amend creates a NEW commit; the original (with .env) is no longer on any
# branch but is still referenced by the HEAD and main reflogs.
echo "GITHUB_TOKEN=ghp_$(pad FAKEamendedCommit 36)" > .env
printf 'import os\nTOKEN = os.environ["GITHUB_TOKEN"]\n' >> app.py
git add .env app.py
commit_as "Bob Builder" bob@example.com "2026-01-15T11:00:00+01:00" "Read token from env"
git rm -q --cached .env && rm .env
GIT_COMMITTER_DATE="2026-01-15T11:05:00+01:00" git commit -q --amend --no-edit

# --- 3. Rebase that drops a commit -------------------------------------------
# Commit A adds a private key, commit B adds docs. Rebasing B onto A's parent
# drops A from main, but A stays in the reflog (and ORIG_HEAD).
openssl genrsa -traditional -out deploy_key.pem 2048 2>/dev/null
git add deploy_key.pem
commit_as "Carol Ops" carol@example.com "2026-01-20T16:00:00+01:00" "Add deploy key"
printf 'Deploy with ./deploy.sh\n' > DEPLOY.md
git add DEPLOY.md
commit_as "Carol Ops" carol@example.com "2026-01-21T08:45:00+01:00" "Add deploy docs"
# Equivalent to `git rebase -i HEAD~2` and deleting the "Add deploy key" line.
GIT_COMMITTER_DATE="2026-01-21T09:00:00+01:00" git rebase -q --onto HEAD~2 HEAD~1 main
rm -f deploy_key.pem   # rebase already removed it from the worktree; be safe

# --- 4. Deleted branch -------------------------------------------------------
# `branch -D` deletes the ref AND its own reflog, but the commit is still
# mentioned in HEAD's reflog because we had it checked out.
git switch -q -c feature/ci
mkdir -p .github/workflows
cat > .github/workflows/ci.yml <<EOF
name: ci
on: push
env:
  GH_TOKEN: ghp_$(pad FAKEdeletedBranch 36)
jobs:
  test: { runs-on: ubuntu-latest, steps: [ { run: echo ok } ] }
EOF
git add .github
commit_as "Dave Dev" dave@example.com "2026-01-25T13:20:00+01:00" "Add CI workflow"
git switch -q main
git branch -q -D feature/ci

# --- 5. Dropped stash --------------------------------------------------------
# A stash is a commit stored under refs/stash. `stash drop` removes that ref
# entry, leaving a dangling commit that only `git fsck` can find.
printf 'AWS_ACCESS_KEY_ID = "AKIAFAKEDROPPEDSTASH"\nAWS_SECRET = "%s"\n' \
  "$(pad fakeSecretDroppedStash 40)" >> app.py
GIT_AUTHOR_NAME="Erin Eng" GIT_AUTHOR_EMAIL=erin@example.com \
GIT_COMMITTER_NAME="Erin Eng" GIT_COMMITTER_EMAIL=erin@example.com \
GIT_AUTHOR_DATE="2026-02-01T10:00:00+01:00" GIT_COMMITTER_DATE="2026-02-01T10:00:00+01:00" \
  git stash push -q -m "wip aws"
git stash drop -q

# --- 6. Staged then unstaged (never committed) -------------------------------
# `git add` writes the blob into .git/objects immediately. Unstaging removes
# it from the index but not from the object store: a dangling blob with no
# author or date attached.
echo "token: ghp_$(pad FAKEstagedNotCommitted 36)" > notes.txt
git add notes.txt
git reset -q notes.txt
rm notes.txt

if [ "$DO_GC" = "--gc" ]; then
  git gc -q   # packs everything; unreachable objects go to a cruft pack
fi

echo "Created $(pwd)"
git log --oneline --all
