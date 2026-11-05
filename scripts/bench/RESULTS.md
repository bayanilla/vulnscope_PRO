# Baseline scale results (2026-11-05)

Current `main` (945d374), unchanged. Synthetic telemetry only (Zeek `conn` + `dns`, Palo Alto
TRAFFIC/THREAT) from `gen_logs.py` with default settings. Machine: 4 vCPU, 15 GiB RAM cloud sandbox,
Python 3.13. Raw numbers are in [`results/`](results/).

## Summary

- **A folder run completes up to about 500 MB of logs** on a 16 GB machine, and takes 10 minutes.
  At 1 GB the process was OOM-killed after 28 minutes, while writing `explorer.html`.
- **The Explorer page breaks well before that.** Above about 250 MB of logs the page is larger
  than the browser's maximum string length (about 512 MB). It loads blank with
  `SyntaxError: Unexpected end of JSON input`. 100 MB opens fine (257 MB page); 250 MB (564 MB page)
  and 500 MB (1.04 GB page) do not.
- **Memory grows linearly at about 6.4 GiB per GB of logs once loaded** (about 1 KB per session).
  The report stage then roughly triples that, so the overall peak is about 20 GiB per GB of logs.
- **Telemetry-only correlation is close to quadratic** (time grows with flows^1.86). One loop does
  almost all the work: `network_leads` in `Correlator.run`
  (`correlate.py:444`, `min(f.ts for f in inbound if f.src_ip == peer)` for every peer of every host).
  At 1 GB it takes 26 minutes. With a scan file the stage is cheap: 15 s instead of 127 s at 250 MB.
- **Parsing is linear and slow, at about 110 s per GB** (around 9 MB/s, one core). A local disk or a
  network share delivers data much faster than that, so share speed will not be the limit.
  (This is inferred; a real share was not tested.)
- **Palo Alto `.gz` files are silently lost.** `detect()` opens them with gzip, but
  `paloalto.parse()` opens them as text. Every line becomes "unrecognized line" and no rows are
  kept. At 1 GB this drops 371,171 firewall rows (12% of them). The drop count shown is the number of
  compressed binary "lines" (83,635), not the number of rows, so the input table understates the
  loss.
- **A session seen by both Zeek and the firewall is counted twice.** At 1 GB there were 4.21 M real
  sessions, and the tool reported 6.37 M flows (+51% with 60% sensor overlap). Exact duplicate rows
  are removed correctly: 127 k removed, and the remaining 7 k generated duplicates sat in the lost
  `.gz` firewall files.
- **The web page is the same pipeline, run inside the HTTP request.** Uploading 250 MB kept the
  request open for 206 s, the server peaked at 5.8 GiB, and the run folder took 1.07 GiB on disk
  (6× the upload). Analyzing the same folder through the page took the same time and memory. The
  multipart upload itself streams to disk with flat memory and is not a bottleneck.
- **The 1 GB upload cap is above what the analysis can handle.** A 1 GB set (853 MB on disk) passes
  the cap, but the analysis needs about 20 GiB. An over-cap request (1.37 GB) is refused after the
  server has read about 2 MB, and the connection is closed. The client saw a connection reset with a
  truncated reply, so a browser probably shows a network error rather than the size message. This
  was not checked in a real browser.

## Folder runs (`bench_pipeline.py`)

| Logs (uncompressed / on disk) | Sessions in tool | Parse + normalize | Correlate | Report | Total | Peak RSS | Outcome |
| --- | --- | --- | --- | --- | --- | --- | --- |
| 100 MB / 76 MB | 0.66 M | 13 s | 23 s | 21 s | 57 s | 2.6 GiB | OK; Explorer opens |
| 250 MB / 183 MB | 1.52 M | 29 s | 127 s | 48 s | 3.4 min | 5.8 GiB | OK; Explorer blank (591 MB page) |
| 500 MB / 393 MB | 3.03 M | 59 s | 444 s | 94 s | 10 min | 10.7 GiB | OK; Explorer blank (1.09 GB page) |
| 1 GB / 853 MB | 6.37 M | 125 s | 1,580 s | killed | >28 min | >13.3 GiB | OOM-killed in report (explorer.html) |
| 5 GB (extrapolated) | ~32 M | ~10 min | ~9 h | — | — | ~32 GiB after load, ~100 GiB in report | Needs a machine with more than 100 GB of RAM |
| 10 GB (extrapolated) | ~64 M | ~20 min | ~32 h | — | — | ~64 GiB after load, ~200 GiB in report | Not practical |

The 100 MB and 250 MB runs ran at the same time as one other run, on separate cores. The 500 MB and
1 GB runs ran alone. Five and 10 GB were not generated: the sandbox cannot hold their memory, so the
rows are extrapolated from the measured trend (linear parse and memory, flows^1.86 correlate,
report peak about 3× the load peak).

Output size per run at 500 MB: `explorer.html` 1.04 GB, `normalized/flows.csv` 368 MB,
`normalized/zeek_events.jsonl` 272 MB, and 1.7 GB in total, which is about 4× the input on disk.

### Where the time goes (sampled once a second)

| Stage | Hottest lines |
| --- | --- |
| parse | `zeek.py:parse` (dict per row + typed values), `paloalto.py:parse` |
| normalize | `normalize.py:load` dedup set and sort (about 10% of load time) |
| correlate, telemetry only | `correlate.py:444` (279 of 305 samples at 500 MB, 1,046 of 1,098 at 1 GB) |
| correlate, with scan | `correlate.py:indicators`, `_Net.internal` |
| report | `explore.build` (`_Pair` per host pair with example dicts), `write_all` CSV/JSONL writers, final `json.dumps` of the Explorer blob |

## Web runs (`bench_web.py`, 250 MB set)

| Mode | Request size | Request open for | Server peak RSS | Run folder on disk |
| --- | --- | --- | --- | --- |
| Upload (`/analyze`) | 191 MB | 206 s | 5.8 GiB | 1.07 GiB |
| Folder (`/analyze-folder`) | 154 B | 204 s | 5.8 GiB | 0.88 GiB |
| Upload over the cap (1.37 GB) | 1.37 GB | refused after 2 MB | 25 MB | — |

Both endpoints do the work inside the request thread. A second user who starts a run at the same time
doubles the server's memory, and the browser tab waits with no progress for the whole run.

## What this means for the plan

This supports the agreed order. The first three items are the walls hit above:

1. Fix Palo Alto `.gz` reading, and merge Zeek and firewall sessions into one session (correctness).
2. Replace the `network_leads` loop. Grouping by peer once makes it linear; this alone takes 1 GB
   from 26 minutes to about the cost of parsing.
3. Stop embedding all data in `explorer.html`. Have the page read results from the server or from
   per-host files, so it never needs one string larger than 512 MB.
4. Stream parsers to Parquet and use DuckDB for dedup and correlation, so memory stays flat as the
   input grows.
5. Run web analyses as background jobs with progress, and lower the upload cap to what the machine
   can actually analyze, or remove the cap once memory no longer depends on input size.
