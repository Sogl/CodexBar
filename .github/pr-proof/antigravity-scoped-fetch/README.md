# Antigravity account-scoped print fetch proof

Covers #3662: when a Google account is selected or injected in Auto mode and the
ambient `agy` paths cannot prove that account, CodexBar runs `agy -p /usage`
scoped to the account's staged file-token credentials instead of substituting an
identity-free ambient report.

`live-evidence.log` — macOS, agy 1.2.9, real accounts (emails redacted):

1. `CodexBarCLI usage --account A` runs the scoped `antigravity-cli-scoped-usage`
   subprocess and returns A's quota labeled A while ambient agy is logged in as
   a different account B.
2. Auto mode with the app-selected account takes the same scoped path.
3. A revoked-credential account preserves the original ambient-path error, falls
   back to the account-scoped OAuth strategy, and never displays B's quota.
4. Manually staged runs confirm the process boundary: agy authenticates as A in
   its own log, the ambient `~/.gemini` tree (614 files) is untouched, revoked
   staged credentials get UNAUTHENTICATED (401), and an expired staged grant
   refreshes in place.
5. Provenance: the saved grants carry the OAuth client ID that CodexBar's
   Add Account flow discovers from the installed Antigravity.app — they are
   CodexBar-minted under Antigravity's own client.
6. Production expired-grant run: with `expiry_date` forced to the past the
   scoped `agy` attempt fails closed (90s bound), the original ambient-path
   error is preserved, and the account-scoped OAuth strategy recovers with
   A's data labeled A.

Reproduce the scoped run from a shell (requires a real `agy` and a saved
Antigravity token account):

```sh
# Stage <home>/.gemini/antigravity-cli/antigravity-oauth-token in agy's
# file-token format, then:
env -i HOME=<staged-home> PWD=<staged-home> SSH_TTY=codexbar-scoped \
    PATH="$PATH" TMPDIR="$TMPDIR" LANG=en_US.UTF-8 \
    agy -p /usage --output-format json --print-timeout 90s
```

Automated coverage: `swift test --filter AntigravityScopedPrintFetchTests`
(staging format, env allowlist, identity verification, fail-closed wiring,
spawned stub-`agy` end-to-end) and `swift test --filter Antigravity` for the
regression surface.
