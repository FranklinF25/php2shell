# PTES Report — php2shell (CVE-2026-109618 / CVE-2026-109619)

> Full PTES-structured report. Datasheet: [finding-sheet.md](finding-sheet.md) ·
> Investigation narrative: [research-writeup.md](research-writeup.md)

## 1. Pre-engagement Interactions

| | |
|---|---|
| **Scope** | PHP core CVE-2026-109618 + CVE-2026-109619 (php2shell) — analysis, safe detection, denial of service, and an in-lab RCE port of the published technique. |
| **Targets** | Purpose-built lab only: `php:8.5.11-apache` (vulnerable) and `php:8.5.12-apache` (fixed) behind a single-worker Apache prefork, plus the pinned `lab/rce/` target. No external or real-world host is ever contacted. |
| **Ground rules** | Same as the companion repos (`cve-2026-31431`, `cve-2026-42945`, `cve-2026-42533`): everything PHP-side inside Docker; host runs stdlib Python only; detector must be safe (zero crashes on any build); every claim carries a reproducible evidence line. |
| **Deliverables** | finding-sheet, this report, research writeup, safe detector, two-vector DoS PoC, credited RCE port, dockerized lab. |

## 2. Intelligence Gathering

* **Vendor advisories** (primary specification): GHSA-w8hw-w9fx-j79w (OOM
  corruption) and GHSA-6wmf-4rv5-p3rp (stale global state) — OOM strategies,
  SAPI susceptibility matrix, producer/consumer model, partial mitigations.
* **Fix archaeology**: `php-8.5.11...php-8.5.12` spans 319 commits; the
  php2shell fix is `31c0ea7d7ff1` (*Avoid state corruption via bailout*,
  ~90 source files): OOM `longjmp()` replaced by a deferred soft error
  (`EG(delayed_oom)` raised at the next VM safe point) plus a hard limit
  (`_exit(137)`, default 200% of `memory_limit`); fallible hash operations
  (`HASH_FALLIBLE`/`HASH_NOMEM` — an allocation failure inside
  `_zend_hash_str_add_or_update_i()` now returns instead of bailing out
  between counter-increment and bucket-init); long-lived state reset at
  shutdown (session, backtrace, OPcache persist frontier, error state);
  upload-progress decode restricted to `__PHP_Incomplete_Class`.
* **Reporter publications**: Wiz (four bug instances, WordPress/Drupal/
  Joomla RCE, `PHPSESSID` leak), Calif (hash-bucket and FPM unserializer
  arms, `post_max_size` bypass via chunked/lengthless bodies, empty-filename
  allocation multiplier, 2004→2026 lineage), Datadog (bucket-arm
  exploitation walkthrough with the exact request geometry), JFrog (flow
  overview), OpenAI (co-discovery).
* **Runtime ground truth**: `Zend/zend_hash.c` (`zend_array_destroy`,
  `zend_hash_destroy` — the `pDestructor != ZVAL_PTR_DTOR` path),
  `ext/session/session.c` (`php_session_rfc1867_callback`,
  `php_session_initialize`, `PS(send_cookie)`), `main/rfc1867.c`
  (`multipart_buffer_read_body` — non-file part values buffer in memory),
  `Zend/zend_alloc.h` (`ZEND_MM_BINS_INFO`, `HASH_FLAG_PACKED`).

## 3. Threat Modeling

* **Asset**: any PHP runtime serving HTTP — the vulnerable code runs during
  request initialization, before application code; authentication in the
  application cannot gate it.
* **Attacker**: unauthenticated network client. Needs (a) a request that
  reaches a fatal allocation failure at a chosen point, and (b) for
  CVE-2026-109619, that producer and consumer requests land on the same
  worker.
* **SAPI ranking** (vendor-confirmed): mod_php — application-independent
  RCE (request shutdown runs even after startup failure); PHP-FPM — session
  arms confirmed with an application-dependent post-startup producer;
  FrankenPHP likely; LSAPI conditional.
* **Entry surfaces used in this repo's PoCs**: urlencoded POST variable
  registration (bucket arm), RFC1867 multipart with
  `PHP_SESSION_UPLOAD_PROGRESS` + file part (session arm), plain multipart
  field value (safe OOM probe).

## 4. Vulnerability Analysis

### 4.1 Trigger anatomy (lab-verified)

**Bucket arm (CVE-2026-109618)** — one request:

```
POST /  application/x-www-form-urlencoded
  =<276 B>&a=1&<3.5 MiB name>[x]=1
```

1. The empty-name field's value copies land in the 320-byte size class and
   are freed (empty name ⇒ no variable registered).
2. `a=1` initializes `$_POST`; its arData allocation reuses the freed block,
   so the value's bytes survive as the (soon stale) bucket bytes.
3. The oversized `name[x]` insertion goes
   `php_std_post_handler()` → `php_register_variable_ex()` →
   `zend_symtable_str_update_ind()` → `_zend_hash_str_add_or_update_i()`;
   `nNumUsed`/`nNumOfElements` are incremented, then the 3.5 MiB key
   `zend_string_init()` exceeds `memory_limit` (16 MiB lab default profile)
   and 8.5.11 `longjmp()`s out — bucket counted, never initialized.
4. mod_php request shutdown destroys `$_POST`; the stale bucket's val zval
   and key are interpreted live.

Measured stale-bucket geometry (crash/benign oracle, `php:8.5.11-apache`):
val zval at value offset **72**, key at **96** (the 24-byte `zend_string`
header of the value copy shifts the mapping; see writeup §5).

**Session arm (CVE-2026-109619)** — two requests, same worker:

1. *Producer*: multipart with `PHP_SESSION_UPLOAD_PROGRESS`, a file part
   (`FILE_START` publishes `PS(id)`, `PS(http_session_vars)` before module
   activation; `PS(send_cookie)=0`) and a 17 MiB plain field value whose
   allocation OOMs the parse. The `END` callback never runs and
   `PG(modules_activated)==0` skips session RSHUTDOWN — the request heap is
   freed with the session globals still pointing into it.
2. *Consumer*: multipart **without** a file part;
   `MULTIPART_EVENT_FORMDATA` + the `PHPSESSID` cookie arm
   `progress->sid`/`key.s`, so `MULTIPART_EVENT_END` reaches
   `php_session_rfc1867_cleanup()` → `php_session_initialize()`, which
   consumes the dangling state.

### 4.2 Differential matrix (same request, both builds)

| Probe | 8.5.11 (vuln) | 8.5.12 (fixed) |
|---|---|---|
| 17 MiB plain multipart value (no session fields) | 200, `Fatal error: … tried to allocate 6296371 bytes … in Unknown on line 0`, worker stable — 3/3 | same, `6299648` bytes — 3/3 (immediate vs deferred OOM accounting) |
| Producer (session armed + OOM) | 200 + OOM, worker stable — 6/6 | identical — 6/6 |
| Consumer after producer, ungroomed | **worker killed** (`AH00052` Abort) — 6/6 | 200 + fresh `Set-Cookie: PHPSESSID` — 12/12 |
| Consumer after producer, 16 KiB groom first field | 200, **no Set-Cookie**, body echoes the groom marker as an allocation size (`0x4848484848484840`) — 3/3 | 200 + `Set-Cookie` + script output — 3/3 |
| Same consumer **without** producer | `Set-Cookie` emitted — 3/3 | `Set-Cookie` emitted — 3/3 |
| Bucket trigger | **worker killed** (empty reply, `AH00052` segfault) — 5/5 pre-probe + 3/3 PoC | 200 + served OOM error — 5/5 + 3/3 |

The 16 KiB groom's parse-time allocations reclaim the freed session
structures benignly, which is what turns the crash into a readable oracle —
the same "attacker reclaims the freed block" primitive the reporters use
for exploitation, pointed at observability instead of control flow.

## 5. Exploitation

### 5.1 Deterministic DoS — achieved (`poc/crash.py`)

Both vectors kill the vulnerable worker on every round (PID change via
`X-Worker-PID`, empty reply, `AH00052` in the Apache log — SIGSEGV for the
bucket arm, SIGABRT/glibc heap-corruption detection for the session arm);
the fixed build serves every round and keeps the same PID. Apache prefork
respawns the child within ~2 s, so the service stays up — this is worker
recycling, not a listener crash.

### 5.2 The detector is safe by construction (`poc/diagnose.py`)

The verdict never requires damage: the accounting probe OOMs a plain field
value (survived by both builds 3/3), the chain probe grooms the consumer to
survive on the vulnerable build, and the control proves the divergence
needs the producer's fatal. Zero crashes across all verdict runs on both
builds. If a different build's layout defeats the groom, the detector
degrades to the crash oracle and still reports VULNERABLE.

### 5.3 In-lab RCE — credited port, achieved (`exploit/rce.py`)

Port of Datadog's published bucket-arm chain against the pinned `lab/rce/`
target. One request; the fake `zend_array` (packed, `pDestructor=system`,
`arPacked` → command string) lives inside the attacker's 276-byte value;
`zend_array_destroy` → `zend_hash_destroy` → `system(zv)` with `zv` = the
command bytes. Heap placement is autodetected per run: a benign marker
learning request + a read of the worker's `/proc/<pid>/mem` yield the
value-base candidates; `/proc/<pid>/maps` yields the chunk and libc bases;
`system()`'s offset is resolved from the image libc's ELF dynsym. ASLR
stays on. **3/3 clean runs**: `RCE-RESULT: EXECUTED 'pwned-runN'` as
`uid=33(www-data)`, HTTP 200 with the OOM fatal error served, worker PID
stable — matching Datadog's observation that the refined exploit neither
crashes the worker nor needs an error status.

## 6. Post Exploitation

Not performed beyond proof-file creation (`id`/`echo` output in `/tmp`),
per scope. The reporters' publications document what full chains achieve
(credentials/tokens from memory disclosure, CMS RCE); nothing here extends
that. Cleanup: `docker compose down` in `lab/` and `lab/rce/` removes all
containers; no host state beyond the repository itself.

## 7. Reporting

* Fix: upgrade to PHP 8.5.12 / 8.4.27 / 8.3.36 / 8.2.35 (or vendor
  backports). Only patching is complete.
* Partial mitigations (vendor-documented, all verified against the
  advisories): `memory_limit=-1` (never `RLIMIT_AS`/`RLIMIT_DATA`),
  `session.upload_progress.enabled=0`, `fatal_error_backtraces=0` (8.5),
  `pm.max_requests=1`, frontend limits on decoded body size / multipart
  parts / headers / uploads.
* Detection: see the [finding-sheet](finding-sheet.md) signatures —
  `Unknown on line 0` OOM fatals, oversized/malformed `PHPSESSID`
  cookies, MiB-scale form field names, `AH00052` churn, worker-spawned
  shells. This repo adds two lab-verified oracles: the accounting
  fingerprint (immediate vs deferred OOM report) and the groom-survived
  consumer response (cookie suppression + in-band marker echo).
