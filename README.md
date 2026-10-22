# CVE-2026-109618 / CVE-2026-109619 — php2shell: Analysis, Detector, DoS & In-Lab RCE Port

Security research on **php2shell** — the two critical PHP core vulnerabilities
disclosed on 2026-10-21 (both CVSS 4.0 **9.2 CRITICAL**, unauthenticated,
pre-application RCE + memory disclosure; found by Wiz Research, Calif and
OpenAI; fixed in PHP 8.5.12 / 8.4.27 / 8.3.36 / 8.2.35):

* **CVE-2026-109618** — *OOM corruption*: a fatal allocation failure
  `longjmp()`s out while request memory is half-initialized, and mod_php's
  request shutdown then consumes the invalid state (the counted-but-
  uninitialized `$_POST` bucket of `_zend_hash_str_add_or_update_i()`).
* **CVE-2026-109619** — *stale global state*: worker globals that point into
  request memory (`PS(id)`, `PS(http_session_vars)`,
  `EG(last_fatal_error_backtrace)`, OPcache pointer maps, the unserializer
  bookkeeping) survive a failed request and are trusted by operations that
  run before the next request's initialization.

**Results (this repo, all against the pinned lab):** a **safe differential
detector** (zero crashes on both builds), a **deterministic two-vector worker
DoS**, and an **in-lab RCE port of the hash-bucket arm** — `system()` as the
Apache worker user (`www-data`), **3/3 clean runs**, with the OOM fatal error
still served in the HTTP 200 response and the worker surviving.

## Verification matrix

| Claim | Evidence |
|---|---|
| Root cause derived from the vendor GHSAs + fix commit, not from blogs | [finding-sheet](docs/finding-sheet.md) (fix `31c0ea7d7ff1` analyzed: soft/hard OOM, fallible hash ops, state resets) |
| Differential pair boots: `php:8.5.11-apache` (vuln) vs `php:8.5.12-apache` (fixed), mod_php, single prefork worker | `lab/` + `lab/README.md` — `X-Worker-PID` proves same-worker pairing |
| Safe detector: **VULNERABLE** on 8.5.11 / **NOT-DETECTED** on 8.5.12, zero crashes on both | `poc/diagnose.py` — stale-state oracle: groom-survived consumer echoes the `H`-marker as an allocation size (`0x4848484848484840`) and suppresses `Set-Cookie`; patched build emits a fresh `PHPSESSID` and runs the script; 3/3 + 3/3 |
| Control: the same consumer **without** the producer's fatal emits the cookie on both builds (the divergence requires the vulnerability chain) | `poc/diagnose.py` control phase — 3/3 both hosts |
| Immediate-vs-deferred OOM accounting: identical request reports `tried to allocate 6296371` (vuln) vs `6299648` (fixed) | `poc/diagnose.py` accounting probe — deterministic per build, zero crashes |
| Deterministic worker DoS, vector 1 (bucket arm, CVE-2026-109618): urlencoded `=[276 B]&a=1&<3.5 MiB name>[x]=1` | `poc/crash.py --vector bucket` — 3/3 kills (empty reply, PID change, `AH00052` segfault); fixed 3/3 survives serving the OOM error |
| Deterministic worker DoS, vector 2 (session arm, CVE-2026-109619): OOM producer + no-file-part consumer | `poc/crash.py --vector session` — 3/3 kills (`AH00052` Abort — glibc heap-corruption detection); fixed 3/3 survives with `Set-Cookie` |
| **In-lab RCE: `system()` as `www-data` via the bucket arm, worker survives, HTTP 200 with OOM error served** | `exploit/rce.py` — 3/3 `RCE-RESULT: EXECUTED`, marker-based heap autodetection, `system()` resolved from the image libc's ELF dynsym |
| Session-id hygiene: a reused `PHPSESSID` accumulates upload-progress data that trips `php_check_cancel_upload()` and silently disables the chain | [research-writeup](docs/research-writeup.md) §3 — the debugging story, verified by clean-lab bisect |

## Quick start

```bash
# differential pair: PHP 8.5.11 (:29555) + 8.5.12 (:29556), mod_php, one worker
cd lab && docker compose up -d --build && cd ..

python3 poc/diagnose.py --port 29555          # safe oracle — VULNERABLE (exit 0)
python3 poc/diagnose.py --host 127.0.0.1 --port 29556   # NOT-DETECTED (exit 1)

python3 poc/crash.py --rounds 3 --check-fixed # both vectors: vuln 6/6 kills, fixed survives

# RCE (pinned lab on :29557, needs docker exec for calibration + proof)
docker compose -f lab/rce/docker-compose.yml up -d
python3 exploit/rce.py --cmd 'echo pwned-by-php2shell > /tmp/proof' --verify

docker compose -f lab/rce/docker-compose.yml exec apache cat /tmp/proof

# interactive console as the worker user (stages a PHP webshell served from
# inside the target; works even on rootless Docker with no callback path)
python3 exploit/rce.py --shell
```

Everything PHP-side runs inside Docker; the host only needs Python 3
(stdlib) and Docker.

## Documents

| Doc | What it is |
|---|---|
| [docs/finding-sheet.md](docs/finding-sheet.md) | One-page datasheet: versions, CVSS, the four bug instances, OOM strategies, detection signatures, lineage |
| [docs/report-ptes.md](docs/report-ptes.md) | Full PTES-structured report (7 phases) with lab evidence |
| [docs/research-writeup.md](docs/research-writeup.md) | The investigation narrative — the patch-first method, the session-file pollution trap, the calibration oracles, portable lessons |

## What is original here vs prior work

The vulnerabilities, their analysis and the exploitation designs are
**prior work by the credited reporters**: Wiz Research (AI-assisted
discovery, the four bug instances, WordPress/Drupal/Joomla RCE, the
`PHPSESSID` leak), Calif / Ryan Austin (independent discovery, the FPM
unserializer arm, the 2004→2026 lineage), OpenAI (co-discovery), and the
PHP security team (the fix). Datadog Security Labs published the
hash-bucket walkthrough this repo's RCE port follows (276-byte value in the
empty-name field, `a=1` arData reuse, oversized array-syntax name, fake
array with destructor callback = `system()`); JFrog published the flow
overview. See the [finding-sheet](docs/finding-sheet.md) references.

Original work in this repo: the **marker-based heap autodetection** (a
benign learning request + a read of the worker's own `/proc/<pid>/mem`
replaces hardcoded heap constants; ASLR stays on and every attempt re-reads
`/proc/<pid>/maps`), the **ELF-dynsym `system()` resolution** from the
image's own libc, the **crash/benign calibration oracle** that pinned the
stale-bucket geometry (val zval at value offset 72, key at 96 — including
the 24-byte `zend_string` header correction), the **safe differential
detector** (groom-survived consumer + in-band marker echo + cookie
suppression + the no-producer control), the **two-vector deterministic
DoS**, the **session-file-pollution finding** (a reused session id
silently disables the upload-progress chain via `cancel_upload`), and the
immediate-vs-deferred OOM **accounting fingerprint**. As with the
companion repos, no real-world target is ever touched — the lab images,
the SUID-free Debian base and the proof files are all purpose-built.

## Repository layout

```
docs/    finding-sheet · report-ptes · research-writeup
poc/     diagnose.py (safe oracle) · crash.py (deterministic DoS)
exploit/ rce.py (in-lab credited port, autodetecting)
lab/     differential compose pair + single-worker mod_php build
lab/rce/ pinned exploitation target (SYS_PTRACE for /proc calibration)
odd/     feature tracking document
```

## References

- Advisories: [GHSA-w8hw-w9fx-j79w](https://github.com/php/php-src/security/advisories/GHSA-w8hw-w9fx-j79w) · [GHSA-6wmf-4rv5-p3rp](https://github.com/php/php-src/security/advisories/GHSA-6wmf-4rv5-p3rp) · fix commit [`31c0ea7d7ff1`](https://github.com/php/php-src/commit/31c0ea7d7ff1d1fccb6492e52dab544011628065)
- Reporter writeups: [Wiz](https://www.wiz.io/blog/php2shell-php-rce) · [Calif](https://calif.io/php2shell/) · [Datadog](https://securitylabs.datadoghq.com/articles/php2shell-critical-vulnerabilities-in-php/) · [JFrog](https://research.jfrog.com/post/php2shell-all-you-need-to-know-about-cve-2026-109618-and-cve-2026-109619/) · [OpenAI](https://openai.com/index/coordinated-disclosure-of-critical-vulnerabilities)
- Coordination: [PHP release announcement](https://www.php.net/archive/2026.php#2026-10-21-1) · [CISA alert](https://www.cisa.gov/news-events/alerts/2026/10/21/critical-vulnerabilities-php-require-immediate-patching) · [NCSC-NL operational repo](https://github.com/NCSC-NL/php2shell)
