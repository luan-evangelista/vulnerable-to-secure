# vulnerable-to-secure

[![Security](https://github.com/luan-evangelista/vulnerable-to-secure/actions/workflows/security.yml/badge.svg)](https://github.com/luan-evangelista/vulnerable-to-secure/actions/workflows/security.yml)

**The same Go payments API twice: once with eight common vulnerabilities, once fixed.** The security pipeline runs on both, so you can see exactly what each layer catches, and what it misses.

> ⚠️ `before/` is intentionally vulnerable. Do not deploy it or copy from it.

## The vulnerabilities and the fixes

| # | Vulnerability in `before/` | Fix in `after/` | Caught by |
| --- | --- | --- | --- |
| 1 | JWT signing key hardcoded in source | Key from `JWT_SECRET`, startup fails if under 32 bytes | Semgrep (kit rule `jwt-hardcoded-secret-go`) |
| 2 | `InsecureSkipVerify: true` on outbound TLS | Verification on, TLS 1.2 minimum | Semgrep (kit rule `tls-verification-disabled-go`) |
| 3 | `err.Error()` returned to clients | Generic messages, details only in server logs | Code review, test `TestErrorsDoNotLeakInternals` |
| 4 | Unsalted MD5 password hashes | PBKDF2-SHA256, 600k iterations, random salt per user | Semgrep (kit rule `weak-password-hash-go`) |
| 5 | SQL built with `fmt.Sprintf` (login bypass) | Parameterized queries | Semgrep (kit rule `sql-string-building-go`), exploit test |
| 6 | Full card number written to logs | Only the last four digits logged | Semgrep (kit rule `pan-in-logs-go`), test |
| 7 | No HTTP server timeouts (slowloris) | Read, write, header and idle timeouts | Code review (none of the tools here flag it) |
| 8 | `golang:latest`, single stage, runs as root, no health check | Pinned multi-stage build, distroless, non-root, health check | Trivy config (DS-0001, DS-0002, DS-0026), Checkov |
| + | Unmaintained `dgrijalva/jwt-go` (CVE-2020-26160) | Maintained `golang-jwt/jwt/v5` | Trivy dependency scan (CI) |

## Scan results

Local run of the same tools the pipeline uses (Semgrep registry rulesets and the CVE database run only in CI):

| Tool | `before/` | `after/` |
| --- | --- | --- |
| Semgrep, kit rules | 7 findings | 0 |
| Trivy config (Dockerfile) | 3 (1 high, 1 medium, 1 low) | 0 |
| Checkov (Dockerfile) | 3 failed checks | 0 |
| Gitleaks | 0 | 0 |
| Go tests | exploit test **passes** (bypass works) | 5 security tests pass |

### What this shows

**Gitleaks did not catch the hardcoded JWT key.** `s3cr3t-signing-key-do-not-use` has too little entropy to look like a secret. The custom Semgrep rule caught it because it looks at *how* the value is used (signing a token), not at what it looks like. This is why a pipeline needs overlapping layers rather than one tool per category.

**Some issues need tests and review, not scanners.** Leaking `err.Error()` and missing server timeouts are not flagged by the tools run locally here. `after/` has tests that pin the fixed behavior so it cannot regress.

## Run it yourself

```bash
# proves the vulnerability: this test passes on the vulnerable code
cd before && go test -v ./...

# proves the fix: the same attack now fails, plus four more security tests
cd ../after && go test -v ./...

# the kit's rules
pip install semgrep
git clone https://github.com/luan-evangelista/pipeline-security-kit ../kit
semgrep scan --config ../kit/rules ../before
```

## The pipeline

[`.github/workflows/security.yml`](.github/workflows/security.yml) runs the same checks on both folders as a matrix. The `before` job is expected to fail and is marked `continue-on-error`, so the workflow stays green while the failed job shows what was caught.

Every action is pinned to a commit SHA, tokens are read-only, and Harden-Runner audits network egress. See [pipeline-security-kit](https://github.com/luan-evangelista/pipeline-security-kit) for the reusable version.

## AI-assisted review (optional)

Scanners match patterns; they miss logic flaws. For a deeper pass, an AI security review such as Cloudflare's open-source [security-audit skill](https://github.com/cloudflare/security-audit-skill) can be run on `before/` with a coding agent. Treat its findings like any other tool's: confirm each one before reporting it.

## License

MIT
