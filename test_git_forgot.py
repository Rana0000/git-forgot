# End to end test: build the test repo with setup_test_repo.sh, scan it,
# and check that every hidden secret is found with the right status.
#
# run: python -m unittest test_git_forgot -v
# needs bash, git and openssl (git bash on windows has all of them)

import os
import subprocess
import tempfile
import unittest

import git_forgot

HERE = os.path.dirname(os.path.abspath(__file__))

# text inside the secret -> (type, status we expect)
EXPECTED = {
    "AKIAFAKEDELETEDFILE1":   ("aws_access_key_id", "reachable"),
    "fakeSecretDeletedFile":  ("aws_secret_access_key", "reachable"),
    "FAKEamendedCommit":      ("github_token", "reflog_only"),
    "BEGIN RSA PRIVATE KEY":  ("private_key", "reflog_only"),
    "FAKEdeletedBranch":      ("github_token", "reflog_only"),
    "AKIAFAKEDROPPEDSTASH":   ("aws_access_key_id", "dangling_commit"),
    "fakeSecretDroppedStash": ("aws_secret_access_key", "dangling_commit"),
    "FAKEstagedNotCommitted": ("github_token", "dangling_blob"),
}

# gc runs "reflog expire" first: entries older than 30 days pointing to
# unreachable commits get dropped. My test commits are from january 2026, so
# the amend and rebase commits become dangling. The deleted branch commit is
# still in the reflog because it's the OLD value of the recent
# "checkout: moving from feature/ci to main" entry.
# The objects themselves stay in a cruft pack (pruned after 2 weeks).
EXPECTED_AFTER_GC = dict(EXPECTED)
EXPECTED_AFTER_GC["FAKEamendedCommit"] = ("github_token", "dangling_commit")
EXPECTED_AFTER_GC["BEGIN RSA PRIVATE KEY"] = ("private_key", "dangling_commit")


def build_repo(path, *flags):
    script = os.path.join(HERE, "setup_test_repo.sh")
    subprocess.run(["bash", script, path, *flags], check=True, capture_output=True)


class TestGitForgot(unittest.TestCase):

    def check(self, repo, expected):
        findings = git_forgot.scan(repo, show_secrets=True)
        for label, (secret_type, status) in expected.items():
            matches = [f for f in findings if label in f["secret"]]
            self.assertEqual(len(matches), 1, label)
            self.assertEqual(matches[0]["type"], secret_type, label)
            self.assertEqual(matches[0]["status"], status, label)
        self.assertEqual(len(findings), len(expected))

        # if it comes from a commit we must have author, date and path
        for f in findings:
            if f["commit"]:
                self.assertTrue(f["author"] and f["date"] and f["path"])

    def test_loose_objects(self):
        with tempfile.TemporaryDirectory() as tmp:
            repo = os.path.join(tmp, "repo")
            build_repo(repo)
            self.check(repo, EXPECTED)

    def test_after_gc(self):
        # after gc there are no loose objects, everything is in packs
        with tempfile.TemporaryDirectory() as tmp:
            repo = os.path.join(tmp, "repo")
            build_repo(repo, "--gc")
            self.check(repo, EXPECTED_AFTER_GC)

    def test_staged_file(self):
        with tempfile.TemporaryDirectory() as tmp:
            repo = os.path.join(tmp, "repo")
            build_repo(repo)
            token = "ghp_" + "S" * 36
            with open(os.path.join(repo, "keep.txt"), "w") as fh:
                fh.write(token + "\n")
            subprocess.run(["git", "-C", repo, "add", "keep.txt"], check=True)

            found = [f for f in git_forgot.scan(repo, show_secrets=True) if f["secret"] == token]
            self.assertEqual(len(found), 1)
            self.assertEqual(found[0]["status"], "staged")
            self.assertEqual(found[0]["path"], "keep.txt")

    def test_masking(self):
        with tempfile.TemporaryDirectory() as tmp:
            repo = os.path.join(tmp, "repo")
            build_repo(repo)
            for f in git_forgot.scan(repo):
                self.assertNotIn("FAKEamendedCommit000000", f["secret"])


if __name__ == "__main__":
    unittest.main()
