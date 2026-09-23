# Antigravity account-scoped print fetch proof

Covers #3662: when a Google account is selected or injected in Auto mode and the
ambient `agy` paths cannot prove that account, CodexBar runs `agy -p /usage`
scoped to the account's staged file-token credentials instead of substituting an
identity-free ambient report.

What the tests prove on macOS:

- `scoped print runs agy against the staged private home` spawns a real child
  process (a stub `agy` shell script) and asserts from inside the child that
  `HOME` is the staged private directory, the allowlist environment carries no
  `ANTIGRAVITY_OAUTH_CREDENTIALS_JSON` or unrelated parent secrets, `SSH_TTY` is
  set (file-token storage, no OS keyring access), and the staged token file at
  `.gemini/antigravity-cli/antigravity-oauth-token` contains the account token.
  After the run the staging directory is gone.
- `staging rejects a token whose identity does not match the account` and
  `staging rejects credentials without an identity claim` prove the fail-closed
  boundary: the staged `id_token` claim is re-read from disk and verified
  against the selected account before `agy` is ever launched.
- `scoped failure preserves the original error and never runs ambient print`
  proves the fallback contract: a scoped failure rethrows the original
  ambient-path error and never substitutes an identity-free report.
- `explicit cli mode never reaches the scoped fetch` and
  `unselected auto fetch still uses the ambient print report` pin the unchanged
  ambient behavior.

No real accounts, credentials, Keychain items, or provider requests are used;
the stub `agy` writes a marker file to prove whether it was spawned.

Reproduce from the repository root (macOS):

```sh
swift test --filter AntigravityScopedPrintFetchTests
```

Regression surface:

```sh
swift test --filter Antigravity
```
