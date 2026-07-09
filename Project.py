import re

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

with open("access.log", "r", encoding="utf-8") as f:
    for line in f:
        total += 1
        match = LOG_PATTERN.match(line)
        if match is None:
            bad += 1
            continue

print(f"total lines: {total}")
print(f"bad lines: {bad}")