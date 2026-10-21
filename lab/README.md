# php2shell lab — differential pair

Two Apache `mod_php` containers built from the official images, one vulnerable,
one fixed. Everything PHP-related runs inside Docker; the host only needs
Python 3 (stdlib) and Docker.

| Service | Image | Port | Role |
|---|---|---|---|
| `php2shell-vuln` | `php2shell-lab:8.5.11` (from `php:8.5.11-apache`) | **29555** | vulnerable — pre-fix `31c0ea7d7ff1` |
| `php2shell-fixed` | `php2shell-lab:8.5.12` (from `php:8.5.12-apache`) | **29556** | fixed — PHP 8.5.12 |

## Why mod_php and one worker

* **mod_php (`apache2handler`)** is the SAPI where both CVEs are
  application-independently exploitable: Apache runs `php_request_shutdown()`
  even after request startup fails, so shutdown consumes the half-initialized
  state (CVE-2026-109618) and the worker survives to serve the next request
  that consumes stale session globals (CVE-2026-109619). PHP-FPM exits the
  child on startup failure instead.
* **Single prefork child** (`ServerLimit 1 / MaxRequestWorkers 1`): the
  producer and consumer requests of the CVE-2026-109619 chain must land on
  the *same worker*. `X-Worker-PID` (from `html/index.php`) proves it.

## Configuration (relative to stock image)

`php-override.ini`: `memory_limit=16M` (small for a fast OOM), `post_max_size=64M`
(room for the trigger bodies), `display_errors=On` + `error_reporting=E_ALL`
(fatal-error fingerprints are served in-band), `session.save_path=/tmp`.
Everything the vulnerable paths depend on stays at factory defaults:
`session.upload_progress.enabled=On`, `session.upload_progress.cleanup=On`.

`AllowOverride All` enables the per-directory INI-diagnostic consumer path
documented in GHSA-6wmf-4rv5-p3rp (`.htaccess` `php_value` deprecations).

## Usage

```bash
docker compose up -d --build     # ~1-2 min (image pulls on first run)

curl -sD - http://127.0.0.1:29555/ | grep -E 'X-(Worker|PHP|SAPI)'   # vuln probe
curl -sD - http://127.0.0.1:29556/ | grep -E 'X-(Worker|PHP|SAPI)'   # fixed probe
```

## Empirical findings this lab was built on

All numbers below are from this exact pair (clean containers, fresh session
id per cycle; see `docs/research-writeup.md` for why a reused session id
poisons the chain: accumulated upload-progress data trips
`php_check_cancel_upload` and aborts multipart parsing before the OOM).

| Probe | vuln 8.5.11 | fixed 8.5.12 |
|---|---|---|
| P1 `POST` multipart, plain 17 MiB field value (no session fields) | 200 + `Fatal error: Allowed memory size of 16777216 bytes exhausted (tried to allocate 6296371 bytes) in Unknown on line 0`, worker stable — **3/3** | same shape, `tried to allocate 6299648 bytes` — **3/3** (immediate vs deferred OOM accounting; the only safe byte-level divergence found) |
| P2 producer (`PHP_SESSION_UPLOAD_PROGRESS` + file part → session state published; 17 MiB value OOMs the parse) | 200 + OOM error, worker stable — 6/6 | identical visible behavior, worker stable — 6/6+ |
| P3 consumer right after producer (multipart, no file part → `MULTIPART_EVENT_END` → `php_session_rfc1867_cleanup()` consumes stale `PS(*)`) | **ungroomed: worker dies (no response, PID change) — 6/6**; 16 KiB-groom first field: worker survives, no `Set-Cookie`, body = `Fatal error … tried to allocate 5208492444341522432 bytes` (≈ `0x4848484848484840` — the `H`-groom marker consumed as a live allocation size) — **3/3** | `Set-Cookie: PHPSESSID=<fresh 32-hex>` + normal script output, worker stable — **12/12** |
| P4 control: same consumer **without** a preceding producer | `Set-Cookie` emitted — 3/3 (previous request's normal RSHUTDOWN reset the globals; no stale state) | `Set-Cookie` emitted — 3/3 |
| P5 urlencoded bucket trigger (CVE-2026-109618): `=[276 B]&a=1&<3.5 MiB name>[x]=1` | **worker dies every time, empty reply, PID change — 5/5**; Apache respawns instantly | 200 + served OOM error, worker stable — 5/5 |

P3/P4 together are the safe oracle (`poc/diagnose.py`): cookie suppression +
groom marker echoed in the error *only* when the producer's fatal left stale
state behind. P5 is the deterministic DoS (`poc/crash.py`, vector 1); P3
ungroomed is vector 2.

## Teardown

```bash
docker compose down            # add -v if you changed named volumes (none by default)
```
