import re
from collections import Counter
from datetime import datetime

LOG_PATTERN = re.compile(
    r'(?P<ip>\S+) \S+ \S+ '
    r'\[(?P<time>[^\]]+)\] '
    r'"(?P<method>\S+) (?P<path>\S+) \S+" '
    r'(?P<status>\d+) (?P<size>\S+) '
    r'"(?P<referrer>[^"]*)" '
    r'"(?P<user_agent>[^"]*)"'
)

TIME_FORMAT = "%d/%b/%Y:%H:%M:%S %z"


total = 0
bad = 0
ip_counter = Counter()
path_counter = Counter()
status_counter = Counter()
hour_counter = Counter() 

with open("access.log", "r", encoding="utf-8") as f:
    for line in f:
        total += 1
        match = LOG_PATTERN.match(line)
        if match is None:
            bad += 1
            continue
        data = match.groupdict()
        try:
            dt = datetime.strptime(data["time"], TIME_FORMAT)
        except ValueError:
            bad += 1
            continue

        data = match.groupdict()
        ip_counter[data["ip"]] += 1
        path_counter[data["path"]] += 1
        status_counter[data["status"]] += 1
        hour_counter[dt.hour] += 1

print(f"total lines: {total}")
print(f"bad lines: {bad}")
print(f"Unique IPs: {len(ip_counter)}")
print("Top 10 endpoints:")
for path, count in path_counter.most_common(10):
    print(f"  {path}: {count}")

print("\nHourly distribution:")
for hour in sorted(hour_counter):
    print(f"  {hour:02d}:00 -> {hour_counter[hour]}")

error_count = 0
for status, count in status_counter.items():
    if status.startswith("4") or status.startswith("5"):
        error_count += count

valid_total = total - bad
error_rate = (error_count / valid_total) * 100

print(f"\nError rate: {error_rate:.3f}%")
print(f"Error count: {error_count}")