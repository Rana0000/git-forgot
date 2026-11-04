# Hugging Face User Access Tokens

**Recognize.** A user access token is `hf_` followed by 34 ASCII letters, e.g.
`hf_` + `[A-Za-z]{34}` (37 characters in total). There is no checksum, so the prefix,
the exact length and a letters-only alphabet are what separate it from noise. Leaks
usually sit next to telling names: `HF_TOKEN`, `HUGGING_FACE_HUB_TOKEN`,
`token=` in `from_pretrained(...)`, `huggingface-cli login`, or a cached
`~/.cache/huggingface/token` committed by mistake. Legacy organization tokens start
with `api_org_`.

**Validate safely.** One read-only call answers "is it live, and whose is it?":

```bash
curl -s https://huggingface.co/api/whoami-v2 -H "Authorization: Bearer $HF_TOKEN"
```

`200` means the token is live and `401` means it was revoked or never existed.
The call changes nothing: it doesn't list or download repositories or use paid
inference. Only test tokens you own, and never send a found token to a third-party
"checker". If a token turns out to be live and not yours, the safe action is
disclosure. Hugging Face also exposes a public `POST /api/credentials/revoke`
endpoint that lets whoever finds a leaked token revoke it.

**What it reveals.** The `whoami-v2` response describes the owner and the blast radius:

- **Owner:** username (`name`), display name, account `type` (user/org), and the
  email when the token's permissions allow it: everything needed to attribute
  and notify.
- **Organizations:** `orgs[]` with the user's role in each, which shows which
  companies' private models and datasets the token can reach.
- **Permissions:** `auth.accessToken.role` is `read`, `write` or `fineGrained`.
  `read`/`write` tokens act on every repository the user can access. For
  `fineGrained` tokens the `auth.accessToken.fineGrained.scoped` list shows each
  scoped resource (user, org, or a single repo) and its allowed actions
  (e.g. `repo.content.read`, `repo.write`, `inference.serverless.write`).
  `displayName` and `createdAt` often hint where the token was meant to be used
  ("colab", "ci").

**Impact.** A `write` token belonging to an organization member is a
supply-chain risk. The holder can push a backdoored model file (pickle weights
execute code when loaded) to repositories that downstream users trust. They can
also exfiltrate private and gated models or datasets and spend the owner's
inference credits.
