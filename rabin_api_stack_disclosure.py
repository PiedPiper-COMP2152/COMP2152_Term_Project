# author: Rabin Kunnananickal Binu
# vulnerability: Technology Stack Disclosure via HTTP Headers
# target: api.0x10.cloud

import urllib.request
import urllib.error
import time

TARGET = "http://api.0x10.cloud"

# headers that should not be exposed
SENSITIVE_HEADERS = [
    "x-powered-by",
    "x-api-version",
    "server",
    "x-aspnet-version",
    "x-aspnetmvc-version"
]

# security headers that should be present but are missing
REQUIRED_SECURITY_HEADERS = [
    "Strict-Transport-Security",
    "X-Content-Type-Options",
    "X-Frame-Options",
    "Content-Security-Policy",
    "X-XSS-Protection",
    "Referrer-Policy",
    "Permissions-Policy"
]

print("=" * 60)
print("  Technology Stack Disclosure — api.0x10.cloud")
print("=" * 60)

# helper to fetch url and return status, headers, body
def fetch_headers(path="/"):
    url = TARGET + path
    req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0"})
    try:
        response = urllib.request.urlopen(req, timeout=5)
        return response.status, dict(response.headers), response.read().decode("utf-8", errors="ignore")
    except urllib.error.HTTPError as e:
        return e.code, dict(e.headers), e.read().decode("utf-8", errors="ignore")
    except Exception as e:
        return None, {}, str(e)

# step 1 - collect headers from multiple endpoints
endpoints = ["/", "/login", "/api", "/health", "/status", "/v1", "/v2"]
all_headers = {}

print("\n[STEP 1] scanning endpoints for header info...")
for ep in endpoints:
    status, headers, body = fetch_headers(ep)
    if status:
        print(f"  [{status}] {TARGET}{ep}")
        # store all headers for later analysis
        for key, val in headers.items():
            all_headers[key.lower()] = val
    time.sleep(0.15)

# step 2 - check for sensitive headers that expose tech stack
print("\n[STEP 2] checking for sensitive header disclosure...")
found_sensitive = []
for header in SENSITIVE_HEADERS:
    if header.lower() in all_headers:
        value = all_headers[header.lower()]
        found_sensitive.append((header, value))
        print(f"  [EXPOSED] {header}: {value}")

# step 3 - check for missing security headers
print("\n[STEP 3] checking for missing security headers...")
missing_headers = []
for header in REQUIRED_SECURITY_HEADERS:
    if header.lower() not in all_headers:
        missing_headers.append(header)
        print(f"  [MISSING] {header}")
    else:
        print(f"  [PRESENT] {header}: {all_headers[header.lower()]}")

# step 4 - check versions against known vulnerabilities
print("\n[STEP 4] analyzing disclosed versions...")
if "x-powered-by" in all_headers:
    powered_by = all_headers["x-powered-by"]
    print(f"  detected: {powered_by}")
    # express 4.16.3 is outdated and has known issues
    if "Express/4.16" in powered_by:
        print(f"  [VULNERABILITY] Express.js 4.16.3 is outdated")
        print(f"  known issues: prototype pollution, path traversal in older middleware")
        print(f"  current stable version is 4.18+")

if "x-api-version" in all_headers:
    api_version = all_headers["x-api-version"]
    print(f"  detected api version: {api_version}")
    # beta version should not be running in production
    if "beta" in api_version.lower():
        print(f"  [VULNERABILITY] beta api version exposed in production")
        print(f"  beta endpoints often lack proper security controls")

# summary of what was found
print("\n" + "=" * 60)
print("  SUMMARY")
print("=" * 60)
print(f"  target: {TARGET}")
print(f"\n  sensitive headers exposed ({len(found_sensitive)}):")
for h, v in found_sensitive:
    print(f"    {h}: {v}")
print(f"\n  missing security headers ({len(missing_headers)}):")
for h in missing_headers:
    print(f"    {h}")
print(f"\n  impact: exposing tech stack versions lets attackers find")
print(f"          exact CVEs for the running software and craft")
print(f"          targeted exploits without any guesswork")
print(f"  modules used: urllib.request, urllib.error, time")
print("=" * 60)
