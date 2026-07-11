from Project import parse_line

# Test 1: a valid, well-formed line should parse correctly
line = '203.0.113.42 - - [01/Jun/2026:09:14:22 +0000] "GET /products/1877 HTTP/1.1" 200 5324 "-" "Mozilla/5.0"'
result = parse_line(line)
assert result is not None
assert result["ip"] == "203.0.113.42"
assert result["status"] == "200"
assert result["path"] == "/products/1877"
print("Test 1 passed: valid line parsed correctly")

# Test 2: a garbage line should return None, not crash
bad_line = "this is not a valid log line"
result = parse_line(bad_line)
assert result is None
print("Test 2 passed: invalid line correctly rejected")

# Test 3: a line with a broken date should return None
line_bad_date = '203.0.113.42 - - [not-a-date] "GET / HTTP/1.1" 200 100 "-" "Mozilla/5.0"'
result = parse_line(line_bad_date)
assert result is None
print("Test 3 passed: bad date correctly rejected")

# Test 4: size field can be "-" instead of a number (some real servers do this)
line_dash_size = '198.51.100.7 - - [01/Jun/2026:10:00:00 +0000] "GET /health HTTP/1.1" 200 - "-" "curl/8.4.0"'
result = parse_line(line_dash_size)
assert result is not None
assert result["size"] == "-"
print("Test 4 passed: dash-size line parsed correctly")

# Test 5: referrer and user_agent should be extracted correctly, including ones with spaces
line_full_ua = '10.0.0.5 - - [01/Jun/2026:11:00:00 +0000] "POST /login HTTP/1.1" 401 159 "https://example.com/page" "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"'
result = parse_line(line_full_ua)
assert result is not None
assert result["referrer"] == "https://example.com/page"
assert result["user_agent"] == "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"
print("Test 5 passed: referrer and user-agent with spaces parsed correctly")

# Test 6: a truncated/incomplete line should not crash and should return None
truncated_line = '203.0.113.42 - - [01/Jun/2026:09:14:22 +0000] "GET /products'
result = parse_line(truncated_line)
assert result is None
print("Test 6 passed: truncated line correctly rejected")

# Test 7: an empty line should not crash
empty_line = ""
result = parse_line(empty_line)
assert result is None
print("Test 7 passed: empty line correctly rejected")

print("\nAll tests passed!")