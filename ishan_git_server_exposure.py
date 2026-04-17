# author: Ishan Sood
# vulnerability: Exposed Git Server - Public Repository Access
# target: git.0x10.cloud

import urllib.request
import urllib.error
import time

TARGET = "http://git.0x10.cloud"

# common gitea/gogs endpoints to probe
ENDPOINTS = [
    "/",
    "/explore/repos",
    "/explore/users",
    "/explore/organizations",
    "/api/v1/repos/search",
    "/api/v1/repos/search?limit=50",
    "/api/swagger",
    "/.git/config",
    "/admin",
    "/user/login",
    "/api/v1/settings/api",
    "/api/v1/version",
]

print("=" * 60)
print("  Exposed Git Server Scanner — git.0x10.cloud")
print("=" * 60)

# helper to fetch url and return status, headers, body
def fetch(path):
    url = TARGET + path
    req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0"})
    try:
        response = urllib.request.urlopen(req, timeout=5)
        body = response.read().decode("utf-8", errors="ignore")
        return response.status, dict(response.headers), body
    except urllib.error.HTTPError as e:
        body = e.read().decode("utf-8", errors="ignore")
        return e.code, dict(e.headers), body
    except Exception as e:
        return None, {}, str(e)

# step 1 - identify what kind of git server it is
print("\n[STEP 1] identifying git server type...")
status, headers, body = fetch("/")
server = headers.get("Server", "unknown")
print(f"  status: {status}")
print(f"  server: {server}")

# check for common git server signatures in response
if "gitea" in body.lower():
    print(f"  [DETECTED] Gitea git server")
elif "gogs" in body.lower():
    print(f"  [DETECTED] Gogs git server")
elif "gitlab" in body.lower():
    print(f"  [DETECTED] GitLab server")
else:
    print(f"  [DETECTED] unknown git server")
    print(f"  preview: {body[:200]}")

time.sleep(0.15)

# step 2 - check each endpoint for unauthenticated access
print("\n[STEP 2] checking for unauthenticated access...")
for endpoint in ENDPOINTS:
    status, headers, body = fetch(endpoint)
    if status == 200:
        print(f"  [OPEN] {TARGET}{endpoint} — status {status}")
        # flag if repo or credential data is accessible
        if any(kw in body.lower() for kw in ["repository", "repo", "clone", "commit", "branch"]):
            print(f"    -> repository data accessible without authentication")
        if any(kw in body.lower() for kw in ["password", "secret", "token", "api_key", "private"]):
            print(f"    -> [HIGH RISK] sensitive data found in response")
        if len(body) > 50:
            print(f"    -> preview: {body[:150]}")
    elif status == 302:
        print(f"  [REDIRECT] {TARGET}{endpoint} — may require auth")
    elif status == 403:
        print(f"  [BLOCKED] {TARGET}{endpoint} — access denied")
    time.sleep(0.15)

# step 3 - check api version endpoint (gitea exposes this without auth)
print("\n[STEP 3] checking api version without auth...")
status, headers, body = fetch("/api/v1/version")
if status == 200:
    print(f"  [VULNERABILITY] git server api accessible without authentication")
    print(f"  response: {body[:300]}")

time.sleep(0.15)

# step 4 - check if repos are publicly listed
print("\n[STEP 4] checking for public repo listing...")
status, headers, body = fetch("/explore/repos")
if status == 200:
    print(f"  [VULNERABILITY] repository listing accessible without login")
    repo_count = body.lower().count("repository") + body.lower().count("/src/")
    print(f"  approximate repositories found: {repo_count}")
    print(f"  preview: {body[:300]}")

# summary of findings
print("\n" + "=" * 60)
print("  SUMMARY")
print("=" * 60)
print(f"  target: {TARGET}")
print(f"  impact: a publicly accessible git server can expose source code,")
print(f"          hardcoded credentials, api keys, database passwords,")
print(f"          and internal infrastructure details to anyone online")
print(f"  modules used: urllib.request, urllib.error, time")
print("=" * 60)