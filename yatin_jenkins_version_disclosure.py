# author: Yatin Korat
# vulnerability: Jenkins Version Disclosure + Unauthenticated Access
# target: jenkins.0x10.cloud

import urllib.request
import urllib.error
import time

TARGET = "http://jenkins.0x10.cloud"

# endpoints to check for unauthenticated access
ENDPOINTS = [
    "/",
    "/api/json",
    "/api/json?pretty=true",
    "/asynchPeople/api/json",
    "/view/all/builds",
    "/systemInfo",
    "/script",
    "/credentials/",
    "/manage",
    "/computer/api/json",
    "/queue/api/json",
    "/jobs",
]

print("=" * 60)
print("  Jenkins Scanner — jenkins.0x10.cloud")
print("=" * 60)

# helper to fetch a url and return status, headers, body
def fetch(endpoint):
    url = TARGET + endpoint
    req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0"})
    try:
        response = urllib.request.urlopen(req, timeout=5)
        body = response.read().decode("utf-8", errors="ignore")
        headers = dict(response.headers)
        return response.status, headers, body
    except urllib.error.HTTPError as e:
        body = e.read().decode("utf-8", errors="ignore")
        return e.code, dict(e.headers), body
    except Exception as e:
        return None, {}, str(e)

# step 1 - check headers for version disclosure
print("\n[STEP 1] checking headers for version info...")
status, headers, body = fetch("/")

jenkins_version = headers.get("x-jenkins", "not found")
server = headers.get("Server", "not found")

print(f"  server header:    {server}")
print(f"  x-jenkins header: {jenkins_version}")

# check if version is exposed
if jenkins_version != "not found":
    print(f"\n  [VULNERABILITY] Jenkins version {jenkins_version} exposed in headers")
    print(f"  attackers can look up CVEs for version {jenkins_version}")
    print(f"  CVE-2022-36882 and CVE-2022-36881 affect Jenkins 2.346.x")

time.sleep(0.15)

# step 2 - check if sensitive endpoints are open without auth
print("\n[STEP 2] checking for unauthenticated access to sensitive endpoints...")
for endpoint in ENDPOINTS:
    status, headers, body = fetch(endpoint)
    if status == 200:
        print(f"  [OPEN] {TARGET}{endpoint} — status {status}")
        # flag if sensitive data is in the response
        if any(kw in body.lower() for kw in ["jobs", "builds", "_class", "credential", "script"]):
            print(f"    -> sensitive data accessible without authentication")
        if len(body) > 100:
            print(f"    -> preview: {body[:200]}")
    elif status == 403:
        print(f"  [BLOCKED] {TARGET}{endpoint} — access denied")
    else:
        print(f"  [OTHER] {TARGET}{endpoint} — status {status}")
    time.sleep(0.15)

# summary of findings
print("\n" + "=" * 60)
print("  SUMMARY")
print("=" * 60)
print(f"  target:        {TARGET}")
print(f"  jenkins version exposed: {jenkins_version}")
print(f"  impact:        attackers can find known CVEs for this version")
print(f"                 and access credentials, scripts, and system info")
print(f"                 without any authentication")
print(f"  modules used:  urllib.request, urllib.error, time")
print("=" * 60)