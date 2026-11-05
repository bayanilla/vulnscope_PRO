#!/usr/bin/env python3
"""Drive the local web page the way a user would and time it.

    python3 scripts/bench/bench_web.py upload INPUT_DIR [--port 8765]
    python3 scripts/bench/bench_web.py folder INPUT_DIR [--port 8765]

Starts `python -m vulnflow serve` in a child process, then either
  upload: streams every file in INPUT_DIR as one multipart POST to /analyze, or
  folder: POSTs INPUT_DIR to /analyze-folder (files are read in place),
and records request time, HTTP status and the server process's peak RSS (sampled every 100 ms
from /proc, children included). The request stays open for the whole analysis, so request time is
also how long the browser tab waits.
"""
from __future__ import annotations

import argparse
import http.client
import json
import os
import re
import secrets
import subprocess
import sys
import tempfile
import threading
import time

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
PAGE = os.sysconf("SC_PAGE_SIZE")


def tree_rss(pid: int) -> int:
    total = 0
    for p in [pid] + _children(pid):
        try:
            with open(f"/proc/{p}/statm") as fh:
                total += int(fh.read().split()[1]) * PAGE
        except OSError:
            pass
    return total


def _children(pid):
    try:
        with open(f"/proc/{pid}/task/{pid}/children") as fh:
            kids = [int(x) for x in fh.read().split()]
    except OSError:
        return []
    return kids + [g for k in kids for g in _children(k)]


def files_of(folder):
    out = []
    for r, ds, fs in os.walk(folder):
        ds[:] = sorted(d for d in ds if not d.startswith("."))
        out += [os.path.join(r, f) for f in sorted(fs) if not f.startswith(".")]
    return out


def multipart_stream(paths, boundary):
    """Yield (total_length, generator) for a multipart body without loading files in memory."""
    parts = []
    for p in paths:
        name = os.path.relpath(p).replace('"', "_")
        head = (f"--{boundary}\r\nContent-Disposition: form-data; name=\"files\"; "
                f"filename=\"{os.path.basename(p)}\"\r\nContent-Type: application/octet-stream\r\n\r\n").encode()
        parts.append((head, p))
    tail = f"--{boundary}--\r\n".encode()
    length = sum(len(h) + os.path.getsize(p) + 2 for h, p in parts) + len(tail)

    def gen():
        for h, p in parts:
            yield h
            with open(p, "rb") as fh:
                while chunk := fh.read(1 << 20):
                    yield chunk
            yield b"\r\n"
        yield tail
    return length, gen()


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("mode", choices=["upload", "folder"])
    ap.add_argument("input")
    ap.add_argument("--port", type=int, default=8765)
    ap.add_argument("--data-dir", default=None)
    ap.add_argument("--json", default=None)
    a = ap.parse_args()
    data_dir = a.data_dir or tempfile.mkdtemp(prefix="vs_web_")
    srv = subprocess.Popen([sys.executable, "-m", "vulnflow", "serve", "--port", str(a.port),
                            "--data-dir", data_dir], cwd=ROOT, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    peak = [0]
    stop = threading.Event()

    def sample():
        while not stop.is_set():
            peak[0] = max(peak[0], tree_rss(srv.pid))
            time.sleep(0.1)
    threading.Thread(target=sample, daemon=True).start()
    try:
        for _ in range(100):
            try:
                c = http.client.HTTPConnection("127.0.0.1", a.port, timeout=5)
                c.request("GET", "/")
                page = c.getresponse().read().decode()
                break
            except OSError:
                time.sleep(0.2)
        csrf = re.search(r'name="csrf" value="([^"]+)"', page)[1]
        hdr = {"Origin": f"http://127.0.0.1:{a.port}", "Host": f"127.0.0.1:{a.port}"}
        c = http.client.HTTPConnection("127.0.0.1", a.port, timeout=24 * 3600)
        t0 = time.time()
        if a.mode == "upload":
            paths = files_of(a.input)
            boundary = "----vsbench" + secrets.token_hex(8)
            length, body = multipart_stream(paths, boundary)
            c.putrequest("POST", "/analyze")
            for k, v in {**hdr, "Content-Type": f"multipart/form-data; boundary={boundary}",
                         "Content-Length": str(length)}.items():
                c.putheader(k, v)
            c.endheaders()
            sent = 0
            try:
                for chunk in body:
                    c.send(chunk)
                    sent += len(chunk)
            except (BrokenPipeError, ConnectionResetError) as exc:
                result_note = f"server closed the connection after {sent} bytes: {exc}"
            else:
                result_note = ""
            upload_s = time.time() - t0
        else:
            from urllib.parse import urlencode
            body = urlencode({"csrf": csrf, "path": a.input}).encode()
            length, upload_s, result_note = len(body), 0.0, ""
            c.request("POST", "/analyze-folder", body=body,
                      headers={**hdr, "Content-Type": "application/x-www-form-urlencoded"})
        try:
            resp = c.getresponse()
            status, loc = resp.status, resp.getheader("Location")
            text = resp.read().decode(errors="replace")
            err = re.search(r'<strong>([^<]+)</strong>', text)
        except Exception as exc:                     # noqa: BLE001
            status, loc, err = None, None, None
            result_note += f" no response: {exc}"
        total = time.time() - t0
        out = {"mode": a.mode, "input": a.input, "request_bytes": length, "status": status,
               "location": loc, "error": err[1] if err else None, "note": result_note.strip(),
               "upload_seconds": round(upload_s, 2), "total_seconds": round(total, 2),
               "server_peak_rss": peak[0], "server_alive": srv.poll() is None, "data_dir": data_dir}
        if loc and loc.startswith("/runs/"):
            run_dir = os.path.join(data_dir, loc.split("/")[2])
            out["run_dir_bytes"] = sum(os.path.getsize(os.path.join(r, f))
                                       for r, _, fs in os.walk(run_dir) for f in fs)
        print(json.dumps(out, indent=2))
        if a.json:
            with open(a.json, "w") as fh:
                json.dump(out, fh, indent=2)
    finally:
        stop.set()
        srv.terminate()
        try:
            srv.wait(10)
        except subprocess.TimeoutExpired:
            srv.kill()


if __name__ == "__main__":
    main()
