import re
from collections import Counter
from datetime import datetime
import argparse

LOG_PATTERN = re.compile(
    r'(?P<ip>\S+) \S+ \S+ '
    r'\[(?P<time>[^\]]+)\] '
    r'"(?P<method>\S+) (?P<path>\S+) \S+" '
    r'(?P<status>\d+) (?P<size>\S+) '
    r'"(?P<referrer>[^"]*)" '
    r'"(?P<user_agent>[^"]*)"'
)

TIME_FORMAT = "%d/%b/%Y:%H:%M:%S %z"

def print_report(total, bad, ip_counter, path_counter, status_counter, hour_counter):
    valid_total = total - bad

    error_count = sum(
        count for status, count in status_counter.items()
        if status.startswith("4") or status.startswith("5")
    )
    error_rate = (error_count / valid_total * 100) if valid_total else 0

    print(f"Total lines processed: {total}")
    print(f"Bad/malformed lines skipped: {bad}")
    print(f"Valid requests: {valid_total}")
    print(f"Unique IPs: {len(ip_counter)}")
    print(f"Error rate (4xx/5xx): {error_rate:.3f}% ({error_count} requests)")

    print("\nTop 10 endpoints:")
    for path, count in path_counter.most_common(10):
        print(f"  {path:<25} {count}")

    print("\nHourly distribution:")
    max_count = max(hour_counter.values()) if hour_counter else 1
    for hour in sorted(hour_counter):
        count = hour_counter[hour]
        bar_length = int((count / max_count) * 40)
        bar = "#" * bar_length
        print(f"  {hour:02d}:00 | {bar} {count}")

def main():
    parser = argparse.ArgumentParser(description="Analyze access log files")
    parser.add_argument("filepath", help="Path to the access log file")
    args = parser.parse_args()
    total = 0
    bad = 0
    ip_counter = Counter()
    path_counter = Counter()
    status_counter = Counter()
    hour_counter = Counter() 

    try:
        input_file = open(args.filepath, "r", encoding="utf-8")
    except FileNotFoundError:
        print(f"Error: file not found: {args.filepath}")
        return
    except PermissionError:
        print(f"Error: no permission to read file: {args.filepath}")
        return

    with input_file, \
         open("good_lines.log", "w", encoding="utf-8") as good_file, \
         open("bad_lines.log", "w", encoding="utf-8") as bad_file:

        for line in input_file:
            total += 1
            match = LOG_PATTERN.match(line)
            if match is None:
                bad += 1
                bad_file.write(line)
                continue
            data = match.groupdict()
            try:
                dt = datetime.strptime(data["time"], TIME_FORMAT)
            except ValueError:
                bad += 1
                bad_file.write(line)
                continue
            good_file.write(line)
            ip_counter[data["ip"]] += 1
            path_counter[data["path"]] += 1
            status_counter[data["status"]] += 1
            hour_counter[dt.hour] += 1

    print_report(total, bad, ip_counter, path_counter, status_counter, hour_counter)

if __name__ == "__main__":
    main()