# Research Writeup — php2shell (CVE-2026-109618 / CVE-2026-109619)

> The investigation narrative. Datasheet: [finding-sheet.md](finding-sheet.md) ·
> PTES report: [report-ptes.md](report-ptes.md)

## 0. Method: the patch is the specification

Same method as the companion repos. php2shell was disclosed hours before
this investigation started, with unusually good public material: two vendor
GHSAs, four reporter writeups, and a same-day fix. So the working order was
inverted from a usual triage: **fix-commit archaeology first** — establish
what exactly changed between `php-8.5.11` and `php-8.5.12` — then build the
lab, then reproduce the *claims* rather than rediscover the bugs, and spend
the remaining budget on the things the publications do not spell out: which
behaviors are deterministic, which are heap-lottery, and what a *safe*
oracle for this bug class even looks like.

## 1. Fix archaeology

`git compare php-8.5.11...php-8.5.12` spans 319 commits. Grep for the
advisory keywords surfaces a dozen unrelated GHSA fixes plus the one that
matters: [`31c0ea7d7ff1`](https://github.com/php/php-src/commit/31c0ea7d7ff1d1fccb6492e52dab544011628065)
— *Avoid state corruption via bailout*, ~90 source files, fixing **both**
GHSAs. Reading the diff (not the blogs) settles the mechanics:

* `Zend/zend_alloc.c` (+527/−124): OOM no longer `longjmp()`s. A soft
  limit queues `EG(delayed_oom)` (message + file + line captured at queue
  time) and raises at the next VM safe point; a hard limit (default 200%
  of `memory_limit`, `ZEND_MM_LIMIT_MAX` above 1 GiB) calls `_exit(137)`
  outright.
* `Zend/zend_hash.c` (+259/−43): every fallible operation gained a
  `HASH_FALLIBLE` variant returning `HASH_NOMEM` — including
  `_zend_hash_str_add_or_update_i()`, whose pre-fix ordering
  (`idx = ht->nNumUsed++; ht->nNumOfElements++;` *before*
  `zend_string_init()` for the key) is exactly the counted-but-
  uninitialized-bucket bug. The fix even restores `nTableSize` on a failed
  packed→mixed conversion. Notably, the counters-before-allocation
  ordering itself is **still there** in 8.5.12 — the error handling around
  it changed, which matches Datadog's note that the deeper pattern remains.
* `ext/session/session.c`: `PS(in_rfc1867_update)` gating and
  `php_var_(un)serialize_set_incomplete_classes_only()` — upload-progress
  decode can no longer materialize live objects
  (`__PHP_Incomplete_Class`, no autoload, no destructors).
* Plus state resets across `Zend/zend_exceptions.c` (fatal backtrace),
  `ext/opcache/zend_persist.c` (the map-ptr frontier), `ext/standard/…`.

## 2. Building the differential lab

Two constraints drove everything: the confirmed-exploitable SAPI is
**mod_php**, and CVE-2026-109619 needs **same-worker** request pairing.
The stock `php:<ver>-apache` images ship Apache prefork with the
`apache2handler` SAPI; a `conf-enabled` snippet pins `MaxRequestWorkers 1`,
and a probe script returns `X-Worker-PID` — the lab equivalent of the
nginx lab's `X-Worker-PID` technique, and the evidence instrument for
every claim that follows. `php-override.ini` mirrors the Datadog profile
(`memory_limit=16M`, `post_max_size=64M`, `display_errors=On`) and leaves
every vulnerability-relevant default (`session.upload_progress.*`) alone.

## 3. The session-file pollution trap

The first big detour. The plan was the Wiz leak chain — producer (session
arming + OOM), consumer (no file part) → anomalous `PHPSESSID`. The first
clean run behaved exactly as published: vulnerable worker died on the
consumer, fixed build served a fresh cookie. Then the results **drifted**:
the producer stopped OOM-ing entirely, consumers stopped crashing, cookies
appeared and vanished, all with identical requests.

Bisecting on a freshly recreated lab (fresh `/tmp`, fresh workers) gave
the answer: everything was deterministic again — until session ids were
**reused**. Each producer/consumer cycle writes upload-progress data into
`/tmp/sess_<sid>`; on the next request with the same cookie,
`php_check_cancel_upload()` reads `$_SESSION[upload_progress_<key>]` from
that file, and the accumulated entries abort the multipart parse before
the OOM ever fires. The chain wasn't flaky — it was **poisoned by its own
session file**. Fix: a fresh random `PHPSESSID` per cycle. Every tool in
this repo generates its own sid per probe; that single change converted
all the oracles from lottery to clockwork. (Practical side note for
anyone reproducing public PoCs of this bug: if the trigger seems dead,
clear the session save path and change the sid before blaming the heap.)

## 4. What the consumption crash is — and isn't

With sids fresh, the consumer crash was 6/6 deterministic — but every
attempt to make the vulnerable side *survive* the stale-state consumption
with a groom field failed at small sizes, which seemed to contradict the
plan. It didn't: the earlier "no crash with groom" sweep had run on the
poisoned lab where **no stale state existed at all** (nothing had OOM-ed),
so those runs proved nothing. Lesson repeated: an oracle on a target that
never entered the vulnerable state is vacuous, whatever the sample size.

At a 16 KiB groom the vulnerable worker finally survived — because the
groom's parse-time allocations reclaim the freed session structures with
benign bytes — and the response became the oracle this repo ships: no
`Set-Cookie` (the stale `PS(send_cookie)=0` from the producer's
`FILE_START` suppresses emission) and an OOM fatal whose
`tried to allocate` figure is assembled from the groom marker itself
(`0x4848484848484840` ≈ `'H'` × 8). Attacker bytes consumed as live
internal state, echoed in-band — a miniature, observable instance of the
Wiz leak arm. The control (same consumer, no producer → cookie on both
builds) closes the loop: the divergence requires the fatal that leaves
stale state, i.e. the vulnerability itself.

## 5. Calibrating the bucket: crash as an instrument

The RCE needed the exact stale-bucket geometry inside the 276-byte value.
Analysis predicted the bucket at value offset 40 (value content sits at
`zend_string` block + 24; mixed-table arData puts bucket[1] at block + 64)
— and a benign-zero probe at that offset still crashed, disproving it. A
single-byte-pair calibration oracle found the truth: place an
`IS_ARRAY|refcounted` type_info + garbage pointer at candidate offset K
(zeros everywhere else) — crash ⇒ K is consumed. K=72 and K=96 crashed,
exactly 24 bytes apart: the val zval at **72**, the key at **96** (the
K=96 crash is `zend_string_release(garbage_key)`). That also retroactively
explained the earlier benign-groom failure: zeros at 32–63 leave the key
bytes at 64–71 as filler. Geometry is now measured, not assumed — and the
`crash/benign` oracle is a portable technique for any stale-bucket-style
bug in a respawnable worker.

## 6. The RCE port: kill the constants

`setarch -R` (ASLR off, the 42945 lab's trick) is blocked by Docker's
default seccomp policy — `personality(ADDR_NO_RANDOMIZE)` needs privileges
the container does not have. Instead of relaxing the sandbox, the exploit
goes the other way: **ASLR stays on, and every run re-derives the world**.

* `/proc/<pid>/maps` (via `docker exec`, `X-Worker-PID` = container-namespace
  pid) → the 2 MiB ZendMM chunk and the libc base.
* The image's libc is `docker cp`-ed once and `system()`'s offset parsed
  from its ELF dynsym in ~50 lines of stdlib — no host binutils, no
  hardcoded `0x53090`.
* The value block's address is learned per run: a benign marker request
  with the same shape plants `P2SMARK7f3a9c11ee` at value offset 200, and
  one `dd`-read of `/proc/<pid>/mem` over the chunk plus `grep -abo`
  returns the candidate bases. Two copies of the value exist (filter and
  parser); the attack tries both — the second hit every time.
* The fake structures live entirely inside the attacker's value bytes:
  val zval at 72 → fake packed `zend_array` at 112 (`nNumUsed=1`,
  `arPacked` → 176, `pDestructor = system`) → command string at 176,
  running until its NUL (so ~99 bytes fit, not 15).
* Result: 3/3 `EXECUTED` as `www-data`, HTTP 200 with the OOM error
  served, worker PID stable — no crash needed at all, exactly as Datadog
  described for their refined exploit.

The whole calibration is per-run and build-agnostic in its method: the
only lab-pinned constant that survives is the K geometry (72/96), which
the crash oracle can re-derive anywhere.

## 7. Portable lessons

1. **Fresh session id per probe.** Reused ids accumulate upload-progress
   state that silently disables the exact chain you are testing.
2. **A differential needs both sides vulnerable.** Runs on a target that
   never entered the vulnerable state are vacuous, regardless of n.
3. **Respawnable workers make crash a first-class measurement channel.**
   `X-Worker-PID` + a one-byte mutation localizes exactly which bytes are
   consumed as live state.
4. **Read the allocator, then measure anyway.** The `zend_string` header
   shifted our analytic offset by 32 bytes; the oracle found it in nine
   requests.
5. **When you cannot disable ASLR, autodetect harder.** `/proc/<pid>/mem`
   of the worker you are about to attack beats a table of frozen heap
   constants, and survives base re-randomization between attempts.
6. **The fix did not remove the pattern.** 8.5.12 still increments the
   counters before allocating the key — it made the failure non-fatal
   instead. Datadog flagged the same; anyone auditing PHP-style engines
   should grep for `publish → fallible work → commit` orderings.

## 8. What is original vs prior work

Everything about the bugs and their exploitation is prior work by Wiz
Research, Calif, OpenAI, the PHP security team, and the published
walkthroughs (Datadog's bucket-arm geometry in particular — the 276-byte
value, the `a=1` reuse, the 3.5 MiB array-syntax name, the fake-array
destructor callback). Original here: the session-file-pollution finding
and its fix discipline, the groom-survived consumer oracle with the
no-producer control, the accounting fingerprint (immediate vs deferred
OOM report), the crash/benign K-calibration oracle, the marker-based
`/proc/<pid>/mem` heap autodetection, the ELF-dynsym `system()` resolver,
and the packaging of all of it into the companion-repo portfolio format.

## References

Wiz — [PHP2Shell: AI uncovers critical RCE vulnerabilities](https://www.wiz.io/blog/php2shell-php-rce) ·
Calif (Ryan Austin) — [php2shell](https://calif.io/php2shell/) ·
Datadog Security Labs — [PHP2Shell: detection, analysis, remediation](https://securitylabs.datadoghq.com/articles/php2shell-critical-vulnerabilities-in-php/) ·
JFrog — [PHP2Shell: All You Need to Know](https://research.jfrog.com/post/php2shell-all-you-need-to-know-about-cve-2026-109618-and-cve-2026-109619/) ·
OpenAI — [Coordinated disclosure](https://openai.com/index/coordinated-disclosure-of-critical-vulnerabilities) ·
Advisories — [GHSA-w8hw-w9fx-j79w](https://github.com/php/php-src/security/advisories/GHSA-w8hw-w9fx-j79w), [GHSA-6wmf-4rv5-p3rp](https://github.com/php/php-src/security/advisories/GHSA-6wmf-4rv5-p3rp) ·
Fix — [php/php-src@31c0ea7d7ff1](https://github.com/php/php-src/commit/31c0ea7d7ff1d1fccb6492e52dab544011628065)
