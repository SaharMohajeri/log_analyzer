# Access Log Analyzer (CLI Tool)

A command-line tool that reads an access log file (Combined Log Format) line by line, skips malformed lines without crashing, and produces useful statistical reports from it.

## How to run

```bash
python Project.py <path_to_log_file>
```

Example:
```bash
python Project.py access.log
```

### Command-line options

| Option | Description |
|---|---|
| `filepath` | Path to the log file (required). Can be a plain `.log` file or a compressed `.gz` file. |
| `--top N` | Number of top-traffic endpoints to show (default: 10) |
| `--json` | Output the base report as JSON instead of human-readable text |
| `--output FILE` | Write the JSON output to the specified file (only meaningful together with `--json`) |

More examples:
```bash
python Project.py access.log --top 5
python Project.py access.log.gz
python Project.py access.log --json --output report.json
```

Running this tool on the sample file (500,000 lines) takes about 3 seconds.

## Side outputs

When run, the tool also produces two extra files:
- `good_lines.log` — every line that was parsed successfully
- `bad_lines.log` — every line that failed to parse (malformed/truncated) or had an invalid timestamp

## What reports does it generate?

- **Base statistics**: total lines, bad lines, valid requests, unique IP count, 4xx/5xx error rate
- **Top N endpoints** by traffic
- **Time distribution**: request counts broken down by date and hour, with a text histogram
- **Suspicious activity detection**: IPs with abnormally high traffic, total 401/403 access attempts, heavy access to sensitive paths (`/admin`, `/login`, etc.)
- **Error spike detection**: finds the time bucket where the 5xx error rate spiked abnormally compared to the file's average

## Key design decisions

### Manual regex parsing instead of a ready-made library
Per the task's rules, only Python's standard library is used. Each line is parsed with a single regular expression that extracts the IP, timestamp, method, path, status, size, referrer, and user-agent fields using named groups.

### Manual timestamp parsing instead of `datetime.strptime`
Initially, `datetime.strptime` was used to parse the timestamp column. After running the tool on the 500,000-line file, I benchmarked `strptime` against manually slicing the timestamp string, and found manual slicing to be roughly **30x faster**, since `strptime` re-parses the format string on every call. The `parse_timestamp` function does this manually — extracting day/month/year/hour/minute/second via string slicing, mapping month abbreviations through a lookup dictionary, and validating each value's range — so it works correctly for any date/month (not just a single fixed day) while staying close to the speed of raw slicing.

### The `size` field is matched as `\S+`, not `\d+`
Real-world logs sometimes record `-` instead of a number for response size (when the size is unknown), so this field is allowed to be non-numeric.

### A line with an invalid timestamp is counted as "bad"
If the regex successfully parses a line but its timestamp turns out to be invalid (e.g. an unrecognized month name or an hour outside 0–23), that line is counted as malformed and written to `bad_lines.log` — rather than being silently ignored.

### Line-by-line processing without loading the whole file into memory
The file is read with `for line in f:`, which Python reads lazily, line by line, instead of loading it all at once with `readlines()`. This keeps memory usage low even for large files.

### Thresholds for suspicious activity detection
- A "high-traffic" IP: more than 1000 requests
- A "notable" total of 401/403 responses: more than 100
- A "heavily accessed" sensitive path: more than 100 hits
- A 5xx error rate "spike": when the worst time bucket's error rate is at least 2x the file's overall average (and at least 1%, to avoid false positives on very small sample sizes)

These thresholds are arbitrary and adjustable; for this sample file (500,000 lines) they seemed like reasonable defaults.

## Problems I ran into and how I solved them

Initially, `datetime.strptime` was used to parse the timestamp column. While running the tool on the 500,000-line file, I wondered whether this function could be a performance bottleneck, since the task explicitly emphasized processing speed. I wrote a small benchmark comparing `strptime` against directly slicing the timestamp string, and the result showed slicing was about 30x faster. However, naive slicing (just grabbing the two characters for the hour) assumed every log line was from the same single day and a fixed format — an unsafe assumption for a general-purpose tool. To fix this, instead of raw slicing, I wrote a manual parsing function (`parse_timestamp`) that extracts and validates the full day/month/year (not just the hour) — so it's both correct (works for any date/month) and fast (close to raw-slicing speed).

A second problem came up while building the suspicious-activity report. At first I was only counting how many 401/403 responses occurred in total, but that gave no way to tell which specific IP addresses were responsible for them — the total count alone doesn't say who's actually attempting unauthorized access. To fix this, I introduced `unauthorized_counter`, a `Counter` keyed by the `(ip, path)` pair instead of a plain total. This lets the report break the count down per IP (and per path), so it's possible to identify, for example, which single IP was responsible for the bulk of the 401 attempts on `/login`.

## Tests

`test_parser.py` contains a handful of simple tests (using plain `assert`, no test framework) covering:
- Parsing a well-formed line and extracting the correct fields
- Rejecting a completely invalid line
- Rejecting a line with a broken timestamp, an invalid month name, or an out-of-range hour
- A `size` field equal to `-`
- Referrer and user-agent values containing spaces
- A truncated/incomplete line and an empty line
- Timestamps from different months (not just a single fixed month)

Run with:
```bash
python test_parser.py
```

## Known limitations

- The "time distribution" report buckets requests by hour; if the log spans multiple days, each day/hour combination is shown separately.
- The suspicious-activity thresholds are hardcoded and may need tuning for logs with different volume or traffic patterns.
- JSON output only includes the base report; the "suspicious activity" and "error spike" sections are not currently included in the JSON output.
