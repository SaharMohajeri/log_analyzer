import re
from collections import Counter, defaultdict
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

def detect_suspicious_activity(ip_counter, path_counter, status_counter, hour_counter, unauthorized_counter):
    print("\n" + "═" * 60)
    print("⚠️  SUSPICIOUS ACTIVITY DETECTION REPORT")
    print("═" * 60)
    
    suspicious_found = False
    
    print("\n▸ High Traffic IPs (Top 5):")
    print("  ─" * 20)
    high_traffic_ips = [(ip, count) for ip, count in ip_counter.most_common(10) if count > 1000]
    if high_traffic_ips:
        for ip, count in high_traffic_ips[:5]:
            print(f"    🔴 {ip:<20} → {count} requests")
        suspicious_found = True
    else:
        print("    ✅ No high-traffic IPs detected")
    
    print("\n▸ Unauthorized Access (401/403):")
    print("  ─" * 20)
    unauthorized_count = sum(
        count for status, count in status_counter.items() 
        if status in ['401', '403']
    )
    if unauthorized_count > 100:
        print(f"    🔴 Total unauthorized attempts: {unauthorized_count}")
        suspicious_found = True
    else:
        print(f"    ✅ Total unauthorized attempts: {unauthorized_count} (within normal range)")
    
    print("\n▸ Sensitive Paths Access (Top 5):")
    print("  ─" * 20)
    sensitive_paths = ['/admin', '/wp-admin', '/login', '/api/v1/auth', '/.env', '/config']
    sensitive_hits = []
    for path, count in path_counter.items():
        for sensitive in sensitive_paths:
            if sensitive in path and count > 100:
                sensitive_hits.append((path, count))
                break
    
    if sensitive_hits:
        for path, count in sorted(sensitive_hits, key=lambda x: x[1], reverse=True)[:5]:
            print(f"    🔴 {path:<30} → {count} accesses")
        suspicious_found = True
    else:
        print("    ✅ No excessive sensitive path access detected")
    
    print_unauthorized_details(unauthorized_counter)
    
    print("\n" + "─" * 60)
    if suspicious_found:
        print("⚠️  SUMMARY: Suspicious activity detected! Review the details above.")
    else:
        print("✅ SUMMARY: No suspicious activity detected. System appears healthy.")
    print("═" * 60)

def print_unauthorized_details(unauthorized_counter):
    print("\n▸ Detailed Unauthorized Access Log (401/403):")
    print("  ─" * 20)
    
    if not unauthorized_counter:
        print("    ✅ No 401/403 errors found in the log")
        return
    
    print(f"    {'IP Address':<20} {'Target Path':<40} {'Attempts':>8}")
    print("    " + "─" * 70)
    
    for (ip, path), count in unauthorized_counter.most_common(10):
        display_path = path if len(path) <= 38 else path[:35] + "..."
        print(f"    {ip:<20} {display_path:<40} {count:>8}")
    
    print("    " + "─" * 70)
    
    total_unauthorized = sum(unauthorized_counter.values())
    unique_ips = len(set(ip for ip, _ in unauthorized_counter.keys()))
    
    print(f"    📊 Total 401/403 attempts: {total_unauthorized}")
    print(f"    📊 Unique attacking IPs: {unique_ips}")
    
    if unauthorized_counter:
        ip_attack_count = defaultdict(int)
        for (ip, _), count in unauthorized_counter.items():
            ip_attack_count[ip] += count
        
        top_ip = max(ip_attack_count, key=ip_attack_count.get)
        top_ip_count = ip_attack_count[top_ip]
        print(f"    🎯 Most active attacker: {top_ip} ({top_ip_count} attempts)")

def print_report(total, bad, ip_counter, path_counter, status_counter, hour_counter):
    print("\n" + "═" * 60)
    print("📊 ACCESS LOG ANALYSIS REPORT")
    print("═" * 60)
    
    valid_total = total - bad
    error_count = sum(
        count for status, count in status_counter.items()
        if status.startswith("4") or status.startswith("5")
    )
    error_rate = (error_count / valid_total * 100) if valid_total > 0 else 0
    
    print("\n▸ General Statistics:")
    print("  ─" * 20)
    print(f"    📄 Total lines processed: {total}")
    print(f"    ❌ Bad/malformed lines: {bad}")
    print(f"    ✅ Valid requests: {valid_total}")
    print(f"    🌐 Unique IPs: {len(ip_counter)}")
    print(f"    ⚠️  Error rate (4xx/5xx): {error_rate:.3f}% ({error_count} requests)")
    
    print("\n▸ Top 10 Most Requested Endpoints:")
    print("  ─" * 20)
    for idx, (path, count) in enumerate(path_counter.most_common(10), 1):
        display_path = path if len(path) <= 50 else path[:47] + "..."
        bar = "█" * min(int(count / max(path_counter.values()) * 30), 30)
        print(f"    {idx:2}. {display_path:<50} {count:>6}  {bar}")
    
    print("\n▸ Hourly Request Distribution:")
    print("  ─" * 20)
    if hour_counter:
        max_count = max(hour_counter.values())
        for hour in sorted(hour_counter):
            count = hour_counter[hour]
            bar_length = int((count / max_count) * 40)
            bar = "█" * bar_length
            print(f"    {hour:02d}:00  │ {bar:<40} {count:>6}")
    else:
        print("    No hourly data available")
    
    print("\n" + "═" * 60)

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
    unauthorized_counter = Counter()
    
    try:
        input_file = open(args.filepath, "r", encoding="utf-8")
    except FileNotFoundError:
        print(f"❌ Error: File not found: {args.filepath}")
        return
    except PermissionError:
        print(f"❌ Error: No permission to read file: {args.filepath}")
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
            
            ip = data["ip"]
            path = data["path"]
            status = data["status"]
            ip_counter[ip] += 1
            path_counter[path] += 1
            status_counter[status] += 1
            hour_counter[dt.hour] += 1
            if status in ['401', '403']:
                unauthorized_counter[(ip, path)] += 1

    print_report(total, bad, ip_counter, path_counter, status_counter, hour_counter)
    detect_suspicious_activity(ip_counter, path_counter, status_counter, hour_counter, unauthorized_counter)

if __name__ == "__main__":
    main()