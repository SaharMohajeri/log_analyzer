import re
from collections import Counter

LOG_PATTERN = re.compile(
    r'(?P<ip>\S+) \S+ \S+ '
    r'\[(?P<time>[^\]]+)\] '
    r'"(?P<method>\S+) (?P<path>\S+) \S+" '
    r'(?P<status>\d+) (?P<size>\S+) '
    r'"(?P<referrer>[^"]*)" '
    r'"(?P<user_agent>[^"]*)"'
)

total = 0
bad = 0
ip_counter = Counter()
path_counter = Counter()
status_counter = Counter()

with open("access.log", "r", encoding="utf-8") as f:
    for line in f:
        total += 1
        match = LOG_PATTERN.match(line)
        if match is None:
            bad += 1
            continue

        data = match.groupdict()
        ip_counter[data["ip"]] += 1
        path_counter[data["path"]] += 1
        status_counter[data["status"]] += 1

print(f"total lines: {total}")
print(f"bad lines: {bad}")
print(f"Unique IPs: {len(ip_counter)}")
print("Top 10 endpoints:")
for path, count in path_counter.most_common(10):
    print(f"  {path}: {count}")

error_count = 0
for status, count in status_counter.items():
    if status.startswith("4") or status.startswith("5"):
        error_count += count

valid_total = total - bad
error_rate = (error_count / valid_total) * 100

print(f"\nError rate: {error_rate:.2f}%")
print(f"Error count: {error_count}")