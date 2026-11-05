# Scale benchmark

Tools to measure how the current pipeline copes with large Zeek + Palo Alto log sets read from a
folder (local or network share) or uploaded through the web page. They do not change `vulnflow/`.

| Script | What it does |
| --- | --- |
| `gen_logs.py` | Writes a synthetic log set of a target size: hourly Zeek `conn`/`dns` logs and Palo Alto TRAFFIC/THREAT CSVs, with sessions seen by both sensors, exact duplicate rows and a share of `.gz` files. A hidden `.manifest.json` holds the true counts. |
| `bench_pipeline.py` | Runs discover, parse, normalize/dedup, correlate and report on a folder, and records time, peak RSS and the hottest `vulnflow` lines per stage. Stops itself at `--rss-limit` or `--time-limit` and still writes the JSON. |
| `bench_web.py` | Starts `vulnflow serve` and times either a multipart upload to `/analyze` or a folder run through `/analyze-folder`, with the server's peak RSS. |

```bash
python3 scripts/bench/gen_logs.py /data/bench/1g --size 1G            # add --scan for a Nessus CSV
python3 scripts/bench/bench_pipeline.py /data/bench/1g -o /tmp/out1g --json 1g.json --rss-limit 12G
python3 scripts/bench/bench_web.py upload /data/bench/250m
python3 scripts/bench/bench_web.py folder /data/bench/250m
```

Run one benchmark at a time: they are memory-bound, and two at once can push the machine into the
kernel's OOM killer, which leaves no result.

Generator defaults: 2,000 internal hosts in `10.10.0.0/16` (5% servers), 50,000 internet addresses,
60% of sessions seen by both Zeek and the firewall, 2% of rows duplicated, 30% of files gzipped, and
15% of the Zeek volume in `dns.log`. `--size` is uncompressed volume; on disk it is about 85% of that.

Results from the first run are in [`RESULTS.md`](RESULTS.md).
