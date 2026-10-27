# Finding Sheet — CVE-2026-109618 / CVE-2026-109619 (PHP2Shell)

> One-page datasheet. Full methodology: [report-ptes.md](report-ptes.md) ·
> Deep research narrative: [research-writeup.md](research-writeup.md)

| | |
|---|---|
| **CVEs** | **CVE-2026-109618** — *RCE via OOM corruption* ([GHSA-w8hw-w9fx-j79w](https://github.com/php/php-src/security/advisories/GHSA-w8hw-w9fx-j79w)) · **CVE-2026-109619** — *RCE via stale global state* ([GHSA-6wmf-4rv5-p3rp](https://github.com/php/php-src/security/advisories/GHSA-6wmf-4rv5-p3rp)) |
| **Weakness** | CWE-416 — Use After Free (both, per vendor advisories) |
| **CVSS 4.0** | **9.2 CRITICAL** each (`AV:N/AC:H/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H`), rated by the PHP security team |
| **Attacker** | Unauthenticated network client — reaches the bug **before any application code runs** |
| **Reporters** | Wiz Research (AI-assisted: Wiz Atlas / Gemini 4 Argon / GPT-5.6 Sol) · Calif (Ryan Austin) · OpenAI — coordinated under the *Patch the planet* initiative; public writeups: [Wiz](https://www.wiz.io/blog/php2shell-php-rce), [Calif](https://calif.io/php2shell/), [Datadog](https://securitylabs.datadoghq.com/articles/php2shell-critical-vulnerabilities-in-php/), [JFrog](https://research.jfrog.com/post/php2shell-all-you-need-to-know-about-cve-2026-109618-and-cve-2026-109619/) |
| **Fix** | Commit [`31c0ea7d7ff1`](https://github.com/php/php-src/commit/31c0ea7d7ff1d1fccb6492e52dab544011628065) — *Avoid state corruption via bailout* (Tovilo, Zelenka, Dossche, Grekas; fixes **both** GHSAs). ~90 source files: OOM no longer `longjmp()`s mid-operation (soft OOM deferred to the next VM safe point via `EG(delayed_oom)`; hard limit `_exit(137)`), fallible hash ops (`HASH_FALLIBLE`/`HASH_NOMEM` — allocation failure now returns instead of bailing out between count-increment and bucket-init), globals reset at shutdown, OPcache persist frontier fix, upload-progress decode restricted to `__PHP_Incomplete_Class` |
| **Exploitation** | **Active — in [CISA KEV](https://www.cisa.gov/news-events/alerts/2026/10/26/cisa-adds-two-known-exploited-vulnerabilities-catalog) since 2026-10-26** (FCEB remediation deadline 2026-10-29, BOD 26-04). First confirmed ITW shells 2026-10-24 (honeypots); millions of attempts since disclosure; still no confirmed real-world victim compromise |

## Root cause (the shared pattern)

PHP uses `longjmp()` (`zend_bailout()`) to abort a request on fatal errors,
including **out-of-memory**. Two bug families exploit contexts where that
non-local exit skips a paired cleanup:

1. **CVE-2026-109618 — shutdown consumes invalid state.** Request memory is
   temporarily reachable before it is fully initialized; an allocation
   failure mid-initialization bails out, and the SAPI shutdown path (mod_php
   runs `php_request_shutdown()` even after startup failure, because
   `PG(modules_activated)==0` skips module RSHUTDOWN while the request heap
   is still destroyed) then *interprets* the half-built state as live values.
2. **CVE-2026-109619 — next request consumes stale state.** Request-owned
   pointers published into worker globals (`PS(id)`,
   `PS(http_session_vars)`, `EG(last_fatal_error_backtrace)`,
   `BG(unserialize).data`, OPcache runtime-pointer slots) survive a failed
   request; an operation running **before normal initialization of the next
   request on the same worker** trusts them → cross-request UAF.

### The four demonstrated instances (Wiz/Calif)

| Instance | CVE | Mechanism | Demonstrated |
|---|---|---|---|
| Hash-bucket count-before-init | 109618 | `_zend_hash_str_add_or_update_i()` runs `ht->nNumUsed++; ht->nNumOfElements++;` **before** `zend_string_init()` for the key; OOM in the key alloc → bucket visible to `zend_array_destroy()` but uninitialized → teardown consumes stale heap bytes as a zval (groomed → fake array with dtor callback = `system()`) | RCE mod_php (Calif, Datadog walkthrough) |
| Upload-progress unserializer UAF + `PHPSESSID` leak | 109618 / 109619 | `php_session_rfc1867_callback()` FILE_START initializes session state before module activation; OOM skips the END cleanup; `PS(id)` dangles → next multipart request URL-encodes reclaimed heap into the `PHPSESSID` cookie (leak) / decoder `var_hash` consumed (corruption) | Application-agnostic memory disclosure + RCE (WordPress, Drupal, Joomla) |
| Fatal-error backtrace UAF (PHP 8.5) | 109619 | `EG(last_fatal_error_backtrace)` survives shutdown; an early next-request INI diagnostic (e.g. deprecated `auto_detect_line_endings=1` via `.htaccess`/`php_value`) reads it before executor init | Pre-auth RCE mod_php (Drupal) |
| OPcache type confusion | 109619 | `zend_accel_script_persist()` advances process-local `CG(map_ptr_last)` before publishing the shared frontier; allocation failure between the two leaves stale shared metadata → cross-worker type confusion | RCE (WordPress) |

Plus the **generic-unserializer FPM arm** (Calif): application-level
`unserialize()`/`session_start()` interrupted by OOM leaves
`BG(unserialize).data` dangling with nonzero nesting level; the next
multipart request's upload-progress treats it as a nested decoder. Negative
`used_slots` in a reclaimed destructor block selects slots *before* the
array (`slot = block + 16 + 16 × used_slots`) → controlled zval copy → RCE
under mod_php **and** PHP-FPM (application-dependent).

## Reaching OOM within `post_max_size`

- Chunked HTTP/1.1 or lengthless HTTP/2 multipart: `post_max_size` is
  checked against the **declared** `Content-Length` only — decoded body
  bytes are not re-counted (input-decompression filters create the same
  mismatch).
- Empty uploads `filename=""` don't count toward `max_file_uploads` but
  still create all six `$_FILES` entries; nested names
  (`files[a][b][c]...`) multiply `HashTable`/bucket/string-key allocations —
  hundreds of records exceed the 128 MiB default heap with a body under the
  8 MiB default `post_max_size`.
- Unrestricted multipart **part headers**; nested field names in
  urlencoded bodies (`root[x]=v` reaches
  `zend_symtable_str_update_ind()` → the vulnerable hash insertion).

## Affected / Fixed

| Branch | Affected | First fixed |
|---|---|---|
| 8.2 | < 8.2.35 | **8.2.35** |
| 8.3 | < 8.3.36 | **8.3.36** |
| 8.4 | < 8.4.27 | **8.4.27** |
| 8.5 | < 8.5.12 | **8.5.12** |
| 5.4–8.1 (EOL) | all | source backports published (7.4/8.0/8.1); check vendor |

Earliest affected path: **PHP 5.4.0** (upload-progress callback, 2012).
Confirmed-exploitable SAPIs: **Apache mod_php** (unconditional request
shutdown after startup failure — application-independent RCE), **PHP-FPM**
(109619 session/unserializer arms; FPM exits the child on *startup* failure,
so the producer must run post-startup — application-dependent),
FrankenPHP likely (analogous to mod_php), LSAPI conditional. PHP's release
announcement puts **every web-serving SAPI in scope** (mod_php, FPM,
php-cgi, FrankenPHP, LiteSpeed).

## Partial mitigations (patching is the only complete fix)

| Measure | Blocks | Notes |
|---|---|---|
| `memory_limit=-1` (admin-enforced) | 109618 predictable-OOM arm | `mmap()` failure still longjmps on vulnerable builds; **never** `RLIMIT_AS`/`RLIMIT_DATA` (they trigger the same path) |
| `session.upload_progress.enabled=0` + restart workers | 109619 session arms | does not touch OPcache/backtrace arms; feature hardly used — **also covers CVE-2026-115560** (unpatched as of 2026-10-27): keep it off after patching until the routine release ships a fix |
| `fatal_error_backtraces=0` (8.5) | backtrace arm | producer removal only |
| `pm.max_requests=1` | same-worker requirement | breaks producer→consumer pairing |
| Frontend: bound decoded body size, multipart parts/headers/uploads, `max_input_nesting_level` | OOM strategies | keeps working post-patch as DoS hygiene |

> **CVE-2026-115560 (disclosed 2026-10-23) — related, out of scope.** Separate
> unpatched session-upload-progress RCE affecting apps that set
> `session.serialize_handler` to `php_binary`/`php_serialize` in config and then
> `ini_set()` it to `php` before `session_start()`. **Not covered by the 21 Oct
> emergency releases** — `8.2.35/8.3.36/8.4.27/8.5.12` all remain affected under
> that configuration; the fix ships with the next regular bugfix release — [Snyk](https://snyk.io/blog/php-patches-critical-unauthenticated-rces/) frames it as a *partial bypass vector for CVE-2026-109619* (patched releases stay affected under this configuration). Still
> no fix commit or PHP-published CVSS/GHSA (a circulating "9.2" belongs to
> 109619; Amazon ALAS rates this one CVSS v3 8.1 *Important* with packages
> *pending fix*, and Red Hat bundles it in
> [RHSB-2026-013](https://access.redhat.com/security/vulnerabilities/RHSB-2026-013)),
> and no observed exploitation of this CVE specifically. The mechanism is now public
> via a third-party PoC
> ([basesixtythree/B63-POC-CVE-2026-115560](https://github.com/basesixtythree/B63-POC-CVE-2026-115560),
> lab-verified against *patched* 8.5.12, mod_php prefork): **serializer
> confusion, not a UAF** — the rfc1867 upload hook writes the upload-progress
> record under the *configured* serializer before the session module
> initializes for the request; the runtime switch to `php` makes the decoder
> split records on the first `|`, and an attacker-supplied `|` (uploaded
> filename / progress key) hands `php_var_unserialize()` attacker bytes with
> autoloading and destructors enabled → arbitrary object injection → a
> file-writing `__destruct()` gadget drops a webshell. Reported reliability:
> 5/5 direct (`session.upload_progress.cleanup=0`) and 10/10 racing the
> streaming window on the default `cleanup=1`, both arms also verified with
> `php_serialize`; configuration negatives break the chain 4/4. Shares the
> upload-progress surface with the session arm above but is a different bug
> class (insecure deserialization via handler confusion, not CWE-416), so the
> `session.upload_progress.enabled=0` row still covers it and vendors are
> flipping that default already (Kusanagi 8.3.36-2 and 8.4.27-2, 2026-10-25). Revisit when
> the routine release + full advisory land (fix commit → differential pair →
> detector is runnable then).

> **CVE-2026-111497 (disclosed 2026-10-21) — adjacent ecosystem, out of scope.**
> Out-of-bounds write in Google's Brotli **decoder** C library (affects 1.0.3–1.0.9,
> 1.1.0, 1.2.0; fixed in 1.0.10 / 1.1.1 / 1.2.1), found by OpenAI Codex Security
> and disclosed by Node.js the same day as the PHP2Shell releases; variously
> named Node2Shell / Brotli2Shell / HTTP2Shell / Broccoli2Shell. Not a PHP bug,
> but PHP-adjacent: the PHP Foundation shipped Windows rebuilds
> **8.5.12-1 / 8.4.27-1 / 8.3.36-1 / 8.2.35-1** on 2026-10-26 for it — Windows
> PHP bundles its own Brotli, while Linux builds link the system `libbrotli`
> (patch the distro package there). Also embedded in Node.js, Bun, Envoy, Istio,
> .NET (Microsoft out-of-band 2026-10-25), Python (`Brotli`/`brotlicffi`) and
> Java (`Brotli4j` ≤ 1.23.0; fixed 1.24.0). State as of 2026-10-27: RCE
> demonstrated on the official Node.js 24.22.0 image (Imperva), first ITW
> attempt recorded 2026-10-26 (ELLIO), not in KEV. Coverage:
> [THN](https://thehackernews.com/2026/10/cisa-confirms-active-exploitation-of.html) ·
> [Tenable FAQ](https://www.tenable.com/blog/brotli2shell-frequently-asked-questions-for-google-brotli-decoder-cve-2026-111497) ·
> [BleepingComputer](https://www.bleepingcomputer.com/news/security/critical-http2shell-brotli-vulnerability-triggers-emergency-patches/).

## Detection signatures (defenders)

- **PHP error log**: `PHP Fatal error: Allowed memory size of N bytes exhausted (tried to allocate M bytes) in Unknown on line 0` — `Unknown on line 0` = failed during request **initialization**, before any script. Datadog's observed size pair: 16777216 / 3500032.
- **Apache error log**: `AH00052: child pid ... exit signal Segmentation fault (11)` — failed ASLR guesses during exploitation.
- **Responses**: unexpectedly large or malformed `Set-Cookie: PHPSESSID=...` values (the leak arm URL-encodes reclaimed heap into the cookie).
- **Requests**: multipart bodies with many `filename=""` parts and deeply nested names; ~MiB-scale form **field names**; binary/NUL bytes in an empty-name field's value (`=[binary]&a=1&<long name>[x]=1`); chunked/lengthless multipart.
- **Host**: any shell spawned by a web worker (`www-data`); HTTP 200 does **not** mean harmless — Datadog's refined exploit returns 200 with the OOM error in the body and the worker keeps running.

## Lineage (why "decades-old")

2004 — Stefan Esser's [first PHP memory-limit remote vulnerability](https://marc.info/?l=bugtraq&m=108981780109154&w=2) · 2020 — [bug #78876](https://bugs.php.net/bug.php?id=78876) (`jr@coredu.mp`, patch [`3c8582ca`](https://github.com/php/php-src/commit/3c8582ca4b8e84e5647220b647914876d2c3b124), later imported into HHVM) · 2024 — OSTIF/Quarkslab audit finds a related issue, exploitation unproven (`security-audit-2024` tag) · 2026-08 — Calif (Aug 1) and Wiz (Aug 19, AI-assisted) independently reach RCE · 2026-10-17 — earliest known exploitation attempt, pre-disclosure (see below) · 2026-10-21 — coordinated disclosure + fixed releases · 2026-10-23 — third related CVE (2026-115560) disclosed · 2026-10-24 — first confirmed ITW shells (researcher honeypots) · 2026-10-26 — CISA KEV listing.

## Post-disclosure exploitation (observed through 2026-10-27)

- **2026-10-17 — pre-disclosure attempt.** Amazon [MadPot](https://aws.amazon.com/blogs/security/amazon-threat-intelligence-identifies-php2shell-exploitation-prior-to-public-disclosure-in-madpot/) telemetry recorded a CVE-2026-109618 exploit probe **four days before public disclosure**, from an IP on a commercial anonymization network — someone held working knowledge during embargo; acquisition path unknown. Cloudflare, Hadrian, watchTowr, Previdian and Patchstack also logged pre-release attempts, all unsuccessful.
- **PoCs public within hours** of the 21 Oct release; technical discussion in the open. Weaponization is non-trivial (per-build adaptation; [CrowdStrike](https://www.crowdstrike.com/en-us/blog/obstacles-to-weaponizing-php2shell-likely-constrain-exploitation/) and [NCSC-NL](https://www.ncsc.nl/en/alerts/update-php-vulnerabilities-remain-a-reason-for-immediate-patching/) both note complexity) — the [Sophos](https://www.sophos.com/en-us/blog/proof-of-concept-exploit-released-for-php-vulnerabilities-109618-109619) Adversary Group could not produce a working exploit even with AI support.
- **Scale:** [Delft Threat Intelligence Lab](https://php2shell.delftintellab.com/) live feed as of 2026-10-27 11:46 UTC — **66,448 exploitation requests** from **644 source IPs** (300 ASNs, 72 countries) since 2026-10-21; busiest hour 2026-10-26 14:00 UTC (**8,179 requests**). By furthest observed step: probe-only 47,854 requests (533 IPs), **code-execution stage 10,509 (147 IPs)**, dropper delivery 4,649 (49 IPs), memory overload only 3,436 (127 IPs). [CrowdSec](https://tracker.crowdsec.net/cves/CVE-2026-109618) — 508 IPs over 30d, first seen 2026-10-21. Exposure: [Unit 42](https://unit42.paloaltonetworks.com/cve-2026-109618-cve-2026-109619/) counts **22.6M exposed potentially vulnerable instances** (Cortex Xpanse); [Censys](https://thehackernews.com/2026/10/cisa-confirms-active-exploitation-of.html) counts **>32.51M PHP services still on an affected version**.
- **2026-10-24 — first confirmed successful exploitation (honeypots).** Adel Karimi (Perplexity) recorded **35 working shells across 3 honeypots from 2 IPs** (one IP: 32 shells across all three) — PHP 8.4.26, Apache mod_php, single worker: the same favorable profile this lab pins. After a first 26 h window with only 30 OOM errors, 11 crashes and no code execution, the sensors captured a four-stage HTTP chain (OOM groom → memory leak → execution) closely matching a public PoC, consistent with **CVE-2026-109618**: an 800 KiB decoded cookie dump, a function address derived from it via the public exploit's offsets appearing in the execution payload, and the shell landing ~1.6 ms after the request's final captured byte; no second-stage payload observed. Packet-to-process evidence: Tetragon recorded each `/bin/sh` as a **direct child of the Apache worker running as `uid 33`** — the same user this lab's RCE lands as — and every hit followed the same four-multipart-request chain defenders can hunt. Validated by Marcus Hutchins (Expel) as the highest-quality ITW confirmation to date. Caveat (Karimi): an intentionally favorable single-worker profile — not a reliability measurement for other worker counts, builds or applications. Coverage: [BleepingComputer](https://www.bleepingcomputer.com/news/security/php2shell-security-flaws-now-sucessfully-exploited-in-the-wild/) · [SecurityWeek](https://www.securityweek.com/php2shell-exploitation-moves-from-probes-to-working-shells/) · [SOCtember](https://www.soctember.com/detection/php2shell-honeypot-confirmed-rce-35-shells-apache-mod-php-multipart-chain).
- **2026-10-25/26 — suspected Lazarus-linked targeting (Cyfirma).** A closed I2P channel (monitored since 2026-10-22; two handles active since March) coordinated checks of **216 unpatched or partially mitigated hosts** from **21 compromised scan nodes** — the same addresses seen running web-shell tooling and upload-progress session-poisoning attempts; about a third of the list was verified when captured. Priority targets: government agencies and banks, then logistics, ports, airports, manufacturing and online transaction platforms, across the US, Japan, South Korea, Thailand, Indonesia, Australia, Taiwan, India, Singapore, the UAE, Saudi Arabia and the EU. The crew ranks public exploit repos with a local AI model and lab-tests manually; no compromise confirmed, imminence scored 78/100, attribution to Lazarus at moderate confidence (a Korean-speaking criminal crew would fit the same facts). Coverage: [Security Affairs](https://securityaffairs.com/201748/hacking/php2shell-suspected-north-korean-campaign-targets-216-vulnerable-php-hosts.html) · [THN](https://thehackernews.com/2026/10/php2shell-exploitation-hits-government.html).
- **Still no confirmed real-world victim compromise.** [Unit 42 **retracted** its 2026-10-23 claim](https://unit42.paloaltonetworks.com/cve-2026-109618-cve-2026-109619/) of post-compromise activity at a European government agency (initial access not attributable to php2shell). [Sophos](https://www.sophos.com/en-us/blog/proof-of-concept-exploit-released-for-php-vulnerabilities-109618-109619) initially reported successful customer exploitation, then **corrected itself on 2026-10-22**: scanning and a small number of *failed* attempts carrying **"Potassium"**, an expanded Mirai-variant (encrypted C2 at 134[.]199[.]154[.]64, ELF-magic payload check, DDoS capability). NCSC-NL (2026-10-23) knows one unconfirmed foreign report. CISA had observed none as of its 2026-10-23 alert revision (Sigma rule added) — reversed the next business day by the KEV listing below.
- **2026-10-26 — CISA adds both CVEs to the KEV catalog** ([notice](https://www.cisa.gov/news-events/alerts/2026/10/26/cisa-adds-two-known-exploited-vulnerabilities-catalog); [PHP alert](https://www.cisa.gov/news-events/alerts/2026/10/21/critical-vulnerabilities-php-require-immediate-patching) updated again) — active exploitation now officially confirmed on the heels of the honeypot shells; FCEB agencies must patch by **2026-10-29** (BOD 26-04). Coverage: [THN](https://thehackernews.com/2026/10/cisa-confirms-active-exploitation-of.html) · [BleepingComputer](https://www.bleepingcomputer.com/news/security/cisa-confirms-php2shell-vulnerabilities-now-exploited-in-attacks/).

## Lab verification status

| Claim | Status |
|---|---|
| Differential pair boots: `php:8.5.11-apache` (vuln) vs `php:8.5.12-apache` (fixed), mod_php, single prefork worker | **verified** — `X-Worker-PID` stable across requests, `apache2handler`, both 200 (lab/README.md) |
| Safe differential oracle, zero crashes on both | **verified** — `poc/diagnose.py`: VULNERABLE 3/3 (exit 0, pid stable) vs NOT-DETECTED 3/3 (exit 1, pid stable); groom marker `0x4848484848484840` echoed in-band; no-producer control 3/3 both |
| Deterministic worker kill on vuln; fixed survives identical attack | **verified** — `poc/crash.py --check-fixed`: bucket arm 3/3 (SIGSEGV, `AH00052`), session arm 3/3 (SIGABRT); fixed 0/6 kills, OOM error served |
| In-lab credited RCE port | **verified** — `exploit/rce.py`: 3/3 `RCE-RESULT: EXECUTED` as `uid=33(www-data)`, HTTP 200 with OOM error served, worker pid stable (fix `31c0ea7d7ff1` build 8.5.12 unaffected) |
| Accounting fingerprint: immediate vs deferred OOM report | **verified** — vuln `tried to allocate 6296371` 3/3 vs fixed `6299648` 3/3, identical request, zero crashes |
