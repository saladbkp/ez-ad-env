#!/usr/bin/env python3
"""
Checker for CalcPwn service (Hackerdom/ForcAD compatible).

CHECK: health + list endpoint
PUT:   store flag as secret, return token as public flag_id
GET:   retrieve flag by token, verify content
"""
import sys
import os
import random
import string
import requests

OK, CORRUPT, MUMBLE, DOWN, CHECKER_ERROR = 101, 102, 103, 104, 110

def rand_str(n=10):
    return "".join(random.choices(string.ascii_lowercase + string.digits, k=n))

def verdict(code, public="", private=""):
    if public:
        print(public, file=sys.stdout)
    if private:
        print(private, file=sys.stderr)
    sys.exit(code)

def check(host):
    try:
        r = requests.get(f"http://{host}:8081/health", timeout=5)
        if r.status_code != 200 or r.json().get("status") != "ok":
            verdict(MUMBLE, "Health check failed")
        r = requests.get(f"http://{host}:8081/api/list", timeout=5)
        if r.status_code != 200:
            verdict(MUMBLE, "List endpoint failed")
        # Test calc with safe expression
        r = requests.post(f"http://{host}:8081/api/calc",
                         json={"expr": "2+2"}, timeout=5)
        if r.status_code != 200 or r.json().get("result") != "4":
            verdict(MUMBLE, "Calc endpoint broken")
    except requests.ConnectionError:
        verdict(DOWN, "Connection refused")
    except Exception as e:
        verdict(MUMBLE, f"Check failed: {e}")
    verdict(OK)

def put(host, flag_id, flag, vuln=1):
    owner = rand_str()
    try:
        r = requests.post(f"http://{host}:8081/api/store",
                         json={"secret": flag, "owner": owner}, timeout=5)
        if r.status_code != 201:
            verdict(MUMBLE, "Store failed", f"HTTP {r.status_code}: {r.text}")
        token = r.json().get("token", "")
        if not token:
            verdict(MUMBLE, "No token returned")
    except requests.ConnectionError:
        verdict(DOWN, "Connection refused")
    except Exception as e:
        verdict(MUMBLE, f"Put failed: {e}")
    # Print token as public flag_id (attack data)
    verdict(OK, token)

def get(host, flag_id, flag, vuln=1):
    token = flag_id
    try:
        r = requests.get(f"http://{host}:8081/api/get",
                        params={"token": token}, timeout=5)
        if r.status_code == 404:
            verdict(CORRUPT, "Secret not found")
        if r.status_code != 200:
            verdict(MUMBLE, "Get failed", f"HTTP {r.status_code}: {r.text}")
        secret = r.json().get("secret", "")
        if secret != flag:
            verdict(CORRUPT, "Secret mismatch",
                    f"Expected {flag}, got {secret}")
    except requests.ConnectionError:
        verdict(DOWN, "Connection refused")
    except Exception as e:
        verdict(MUMBLE, f"Get failed: {e}")
    verdict(OK)

if __name__ == "__main__":
    action = sys.argv[1]
    host = sys.argv[2]
    if action == "check":
        check(host)
    elif action == "put":
        flag_id, flag, vuln = sys.argv[3], sys.argv[4], sys.argv[5]
        put(host, flag_id, flag, vuln)
    elif action == "get":
        flag_id, flag, vuln = sys.argv[3], sys.argv[4], sys.argv[5]
        get(host, flag_id, flag, vuln)
    else:
        verdict(CHECKER_ERROR, "Unknown action")
