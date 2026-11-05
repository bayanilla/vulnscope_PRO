#!/usr/bin/env python3
"""Run the unchanged VulnScope pipeline on a folder and record time and peak memory per stage.

    python3 scripts/bench/bench_pipeline.py INPUT_DIR -o OUT_DIR --json result.json [--rss-limit 12G]

Stages (same calls as vulnflow.pipeline.run, timed separately):
  discover   walk the folder (vulnflow.cli._input_files)
  parse      the format parsers, file by file (inside normalize.load)
  normalize  the rest of normalize.load: concatenation, exact-duplicate removal, sort
  correlate  vulnflow.correlate.correlate
  report     vulnflow.report.write_all (reports, explorer.html, results.json, normalized/*)

A background thread samples RSS every 50 ms and, once a second, which vulnflow function the
main thread is in (recorded per stage as "hot", in seconds). If RSS passes --rss-limit the run is stopped
on purpose (so the box doesn't OOM; --time-limit does the same for run time) and the JSON records the stage it was in, how far parsing
got, and the RSS at that point. Nothing in vulnflow/ is modified; parsers are only wrapped.
"""
from __future__ import annotations

import argparse
import json
import os
import sys
import threading
import time

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
sys.path.insert(0, ROOT)

from vulnflow import normalize                       # noqa: E402
from vulnflow.cli import _input_files                # noqa: E402
from vulnflow.correlate import Config, correlate     # noqa: E402
from vulnflow.report import write_all                # noqa: E402

PAGE = os.sysconf("SC_PAGE_SIZE")


def rss() -> int:
    with open("/proc/self/statm") as fh:
        return int(fh.read().split()[1]) * PAGE


def size(s: str) -> int:
    units = {"K": 1 << 10, "M": 1 << 20, "G": 1 << 30}
    return int(float(s[:-1]) * units[s[-1].upper()]) if s[-1].upper() in units else int(s)


class Recorder:
    def __init__(self, path: str, limit: int):
        self.path, self.limit = path, limit
        self.result = {"stages": {}, "files": [], "status": "running", "rss_limit": limit}
        self.stage, self.stage_t0, self.stage_peak = None, 0.0, 0
        self.t0 = time.time()
        self.deadline = None
        self.lock = threading.Lock()
        threading.Thread(target=self._sample, daemon=True).start()

    def _sample(self):
        main_id, tick = threading.main_thread().ident, 0
        while True:
            r = rss()
            tick += 1
            with self.lock:
                self.stage_peak = max(self.stage_peak, r)
                if tick % 20 == 0 and self.stage:          # once a second: where is the main thread?
                    frame = sys._current_frames().get(main_id)
                    where = None
                    while frame is not None:
                        if "vulnflow" + os.sep in frame.f_code.co_filename and where is None:
                            where = (f"{os.path.basename(frame.f_code.co_filename)}:"
                                     f"{frame.f_code.co_name}:{frame.f_lineno}")
                        frame = frame.f_back
                    if where:
                        hot = self.result["stages"][self.stage].setdefault("hot", {})
                        hot[where] = hot.get(where, 0) + 1
                if self.deadline and time.time() > self.deadline:
                    self.end_stage(aborted=True)
                    self.result["status"] = f"stopped: time limit reached in stage '{self.stage}'"
                    self.dump()
                    os._exit(4)
                if r > self.limit:
                    self.end_stage(aborted=True)
                    self.result["status"] = f"stopped: RSS {r / 2**30:.2f} GiB passed the limit in stage '{self.stage}'"
                    self.dump()
                    os._exit(3)
            time.sleep(0.05)

    def start_stage(self, name: str):
        with self.lock:
            self.stage, self.stage_t0, self.stage_peak = name, time.time(), rss()
            self.result["stages"][name] = {"rss_start": self.stage_peak}

    def end_stage(self, aborted=False):
        st = self.result["stages"][self.stage]
        st.update(seconds=round(time.time() - self.stage_t0, 2), rss_peak=self.stage_peak,
                  rss_end=rss(), aborted=aborted)

    def finish_stage(self, **extra):
        with self.lock:
            self.end_stage()
            self.result["stages"][self.stage].update(extra)

    def dump(self):
        self.result["total_seconds"] = round(time.time() - self.t0, 2)
        try:
            import resource
            self.result["ru_maxrss"] = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss * 1024
        except Exception:
            pass
        with open(self.path + ".tmp", "w") as fh:       # atomic, so a kill never leaves it empty
            json.dump(self.result, fh, indent=2, default=str)
        os.replace(self.path + ".tmp", self.path)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("input")
    ap.add_argument("-o", "--out", required=True)
    ap.add_argument("--json", required=True)
    ap.add_argument("--rss-limit", default="12G")
    ap.add_argument("--time-limit", type=float, default=0, help="stop after this many seconds (0 = none)")
    a = ap.parse_args()
    rec = Recorder(a.json, size(a.rss_limit))
    rec.deadline = rec.t0 + a.time_limit if a.time_limit else None

    rec.start_stage("discover")
    files = _input_files([a.input], a.out)
    in_bytes = sum(os.path.getsize(f) for f in files)
    rec.result.update(input=a.input, input_files=len(files), input_bytes_on_disk=in_bytes)
    rec.finish_stage()

    # Wrap every parser so parse time and per-file record counts are visible.
    parse_seconds = [0.0]
    for fmt, (kind, fn) in list(normalize.FORMATS.items()):
        def timed(path, stats, fn=fn, fmt=fmt):
            t = time.time()
            out = fn(path, stats)
            dt = time.time() - t
            parse_seconds[0] += dt
            with rec.lock:
                rec.result["files"].append({"file": os.path.relpath(path, a.input), "fmt": fmt,
                                            "bytes": os.path.getsize(path), "seconds": round(dt, 3),
                                            "read": stats.read, "records": len(out),
                                            "dropped": dict(stats.dropped), "rss_after": rss()})
            return out
        normalize.FORMATS[fmt] = (kind, timed)

    rec.start_stage("parse+normalize")
    ds = normalize.load(files)
    rec.finish_stage(parse_seconds=round(parse_seconds[0], 2),
                     flows=len(ds.flows), threats=len(ds.threats), zeek_events=len(ds.zeek_events),
                     ot_events=len(ds.ot_events), findings=len(ds.findings),
                     duplicate_flows_removed=ds.duplicate_flows)
    st = rec.result["stages"]["parse+normalize"]
    st["normalize_seconds"] = round(st["seconds"] - st["parse_seconds"], 2)
    by_fmt: dict = {}
    for s in ds.stats:
        b = by_fmt.setdefault(s.fmt, {"files": 0, "read": 0, "kept": 0, "dropped": 0})
        b["files"] += 1
        b["read"] += s.read
        b["kept"] += s.kept
        b["dropped"] += sum(s.dropped.values())
    rec.result["by_format"] = by_fmt
    rec.dump()

    rec.start_stage("correlate")
    res = correlate(ds, Config())
    rec.finish_stage(hosts=len(res["hosts"]), findings_scored=len(res["findings"]),
                     network_leads=len(res["network_leads"]))
    rec.dump()

    rec.start_stage("report")
    paths = write_all(res, ds, a.out)
    rec.finish_stage(outputs={k: os.path.getsize(v) for k, v in paths.items()})
    rec.result["status"] = "ok"
    rec.dump()
    print(json.dumps({k: v for k, v in rec.result.items() if k != "files"}, indent=2, default=str))


if __name__ == "__main__":
    main()
